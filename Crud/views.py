from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import login
from django.http import JsonResponse
from django.utils import timezone
from django.conf import settings
from .models import Empresas, Amenaza, RegistroActividad, ConfiguracionMonitoreo
from .forms import UserRegisterForm, EmpresasForm
from .services import ServicioMonitoreo
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.views.decorators.http import require_http_methods
import logging
import time

logger = logging.getLogger(__name__)

servicio = ServicioMonitoreo()

def landing(request):
    """Vista para la landing page."""
    if request.user.is_authenticated:
        return redirect('home')
    return render(request, 'landing.html')

# Actualizar la configuración de login
settings.LOGIN_REDIRECT_URL = 'home'
settings.LOGIN_URL = 'login'

def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, '¡Cuenta creada exitosamente!')
            return redirect('home')
    else:
        form = UserRegisterForm()
    return render(request, 'registration/register.html', {'form': form})

@login_required
def home(request):
    # Obtener las empresas del usuario
    empresas = Empresas.objects.filter(usuario=request.user)
    
    # Obtener amenazas recientes (últimas 24 horas) con paginación
    amenazas_list = Amenaza.objects.filter(
        empresa__in=empresas,
        fecha_deteccion__gte=timezone.now() - timezone.timedelta(days=1)
    ).order_by('-fecha_deteccion')
    
    paginator_amenazas = Paginator(amenazas_list, 50)  # 50 amenazas por página
    page_amenazas = request.GET.get('page_amenazas', 1)
    
    try:
        amenazas_recientes = paginator_amenazas.page(page_amenazas)
    except PageNotAnInteger:
        amenazas_recientes = paginator_amenazas.page(1)
    except EmptyPage:
        amenazas_recientes = paginator_amenazas.page(paginator_amenazas.num_pages)
    
    # Obtener actividades recientes con paginación
    actividades_list = RegistroActividad.objects.filter(
        empresa__in=empresas
    ).order_by('-fecha')
    
    paginator_actividades = Paginator(actividades_list, 50)  # 50 actividades por página
    page_actividades = request.GET.get('page_actividades', 1)
    
    try:
        actividades_recientes = paginator_actividades.page(page_actividades)
    except PageNotAnInteger:
        actividades_recientes = paginator_actividades.page(1)
    except EmptyPage:
        actividades_recientes = paginator_actividades.page(paginator_actividades.num_pages)
    
    # Calcular total de escaneos
    total_escaneos = RegistroActividad.objects.filter(
        empresa__in=empresas,
        tipo='ESCANEO'
    ).count()
    
    context = {
        'empresas': empresas,
        'amenazas_recientes': amenazas_recientes,
        'actividades_recientes': actividades_recientes,
        'total_escaneos': total_escaneos,
    }
    
    return render(request, 'home.html', context)

@login_required
def crear_empresa(request):
    if request.method == 'POST':
        form = EmpresasForm(request.POST, request.FILES)
        if form.is_valid():
            empresa = form.save(commit=False)
            empresa.usuario = request.user
            empresa.save()
            
            # Crear configuración de monitoreo por defecto
            ConfiguracionMonitoreo.objects.create(empresa=empresa)
            
            messages.success(request, '¡Empresa creada exitosamente!')
            return redirect('home')
    else:
        form = EmpresasForm()
    return render(request, 'empresas/crear_empresa.html', {'form': form})

@login_required
def editar_empresa(request, empresa_id):
    try:
        empresa = Empresas.objects.get(pk=empresa_id, usuario=request.user)
    except Empresas.DoesNotExist:
        messages.error(request, 'La empresa no existe o no tienes permisos para acceder a ella.')
        return redirect('lista_empresas')

    if request.method == 'POST':
        form = EmpresasForm(request.POST, request.FILES, instance=empresa)
        if form.is_valid():
            form.save()
            messages.success(request, '¡Empresa actualizada exitosamente!')
            return redirect('detalle_empresa', empresa_id=empresa_id)
    else:
        form = EmpresasForm(instance=empresa)
    return render(request, 'empresas/editar_empresa.html', {'form': form})

@login_required
def eliminar_empresa(request, empresa_id):
    try:
        empresa = Empresas.objects.get(pk=empresa_id, usuario=request.user)
    except Empresas.DoesNotExist:
        messages.error(request, 'La empresa no existe o no tienes permisos para acceder a ella.')
        return redirect('lista_empresas')

    if request.method == 'POST':
        empresa.delete()
        messages.success(request, '¡Empresa eliminada exitosamente!')
        return redirect('home')
    return render(request, 'empresas/eliminar_empresa.html', {'empresa': empresa})

@login_required
def detalle_empresa(request, empresa_id):
    """Muestra los detalles de una empresa y el estado del monitoreo de descargas."""
    empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
    
    # Obtener estado del monitoreo
    estado_monitoreo = servicio.obtener_estado_monitoreo(empresa.id)
    
    # Obtener amenazas y actividades paginadas
    amenazas = Amenaza.objects.filter(empresa=empresa).order_by('-fecha_deteccion')
    actividades = RegistroActividad.objects.filter(empresa=empresa).order_by('-fecha')
    
    # Paginar amenazas y actividades (10 por página)
    paginator_amenazas = Paginator(amenazas, 10)
    paginator_actividades = Paginator(actividades, 10)
    
    page_amenazas = request.GET.get('page_amenazas', 1)
    page_actividades = request.GET.get('page_actividades', 1)
    
    amenazas_paginadas = paginator_amenazas.get_page(page_amenazas)
    actividades_paginadas = paginator_actividades.get_page(page_actividades)
    
    context = {
        'empresa': empresa,
        'estado_monitoreo': estado_monitoreo,
        'amenazas': amenazas_paginadas,
        'actividades': actividades_paginadas,
    }
    return render(request, 'empresas/detalle_empresa.html', context)

@login_required
@require_http_methods(["POST"])
def iniciar_monitoreo(request, empresa_id):
    """Inicia el monitoreo de descargas para una empresa."""
    try:
        empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
        
        # Verificar si el monitoreo ya está activo
        if servicio.monitoreo_activo:
            return JsonResponse({
                'success': True,
                'message': 'El monitoreo ya está activo'
            })
        
        # Intentar iniciar el monitoreo
        if servicio.iniciar_monitoreo():
            logger.info(f"Monitoreo iniciado para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': True,
                'message': 'Monitoreo iniciado correctamente'
            })
        else:
            logger.error(f"No se pudo iniciar el monitoreo para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': False,
                'message': 'No se pudo iniciar el monitoreo'
            })
    except Exception as e:
        logger.error(f"Error al iniciar monitoreo para empresa {empresa_id}: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error al iniciar monitoreo: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def detener_monitoreo(request, empresa_id):
    """Detiene el monitoreo de descargas para una empresa."""
    try:
        empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
        
        # Verificar si el monitoreo está activo
        if not servicio.monitoreo_activo:
            return JsonResponse({
                'success': True,
                'message': 'El monitoreo ya está detenido'
            })
        
        if servicio.detener_monitoreo():
            logger.info(f"Monitoreo detenido para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': True,
                'message': 'Monitoreo detenido correctamente'
            })
        else:
            logger.error(f"No se pudo detener el monitoreo para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': False,
                'message': 'No se pudo detener el monitoreo'
            })
    except Exception as e:
        logger.error(f"Error al detener monitoreo para empresa {empresa_id}: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error al detener monitoreo: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def reiniciar_monitoreo(request, empresa_id):
    """Reinicia el monitoreo de descargas para una empresa."""
    try:
        empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
        
        # Detener el monitoreo actual si está activo
        if servicio.monitoreo_activo:
            servicio.detener_monitoreo()
            time.sleep(1)  # Esperar a que se detenga completamente
        
        # Iniciar el monitoreo nuevamente
        if servicio.iniciar_monitoreo():
            logger.info(f"Monitoreo reiniciado para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': True,
                'message': 'Monitoreo reiniciado correctamente'
            })
        else:
            logger.error(f"No se pudo reiniciar el monitoreo para empresa {empresa.Nombre_Empresa}")
            return JsonResponse({
                'success': False,
                'message': 'No se pudo reiniciar el monitoreo'
            })
    except Exception as e:
        logger.error(f"Error al reiniciar monitoreo para empresa {empresa_id}: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error al reiniciar monitoreo: {str(e)}'
        }, status=500)

@login_required
@require_http_methods(["GET"])
def estado_monitoreo(request, empresa_id):
    """Obtiene el estado actual del monitoreo de descargas."""
    try:
        # Verificar que la empresa existe y pertenece al usuario
        empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
        
        # Obtener estado del monitoreo
        estado = servicio.obtener_estado_monitoreo(empresa_id)
        
        # Asegurarse de que el estado tenga todos los campos necesarios
        if not isinstance(estado, dict):
            logger.warning(f"Estado inválido recibido: {estado}")
            estado = {
                'estado': 'INACTIVO',
                'descargas_activas': 0,
                'descargas_info': [],
                'ultima_actualizacion': timezone.now().isoformat()
            }
        
        # Asegurarse de que los campos requeridos existan con valores por defecto
        estado.setdefault('estado', 'INACTIVO')
        estado.setdefault('descargas_activas', 0)
        estado.setdefault('descargas_info', [])
        estado.setdefault('ultima_actualizacion', timezone.now().isoformat())
        
        # Si hay un error en el estado, registrarlo pero no fallar
        if 'error' in estado:
            logger.warning(f"Error en estado de monitoreo para empresa {empresa.Nombre_Empresa}: {estado['error']}")
            # Mantener el estado pero marcar como inactivo
            estado['estado'] = 'INACTIVO'
            estado['descargas_activas'] = 0
            estado['descargas_info'] = []
        
        logger.debug(f"Estado de monitoreo para empresa {empresa.Nombre_Empresa}: {estado}")
        return JsonResponse(estado)
        
    except Empresas.DoesNotExist:
        logger.error(f"Empresa no encontrada: {empresa_id}")
        return JsonResponse({
            'estado': 'INACTIVO',
            'descargas_activas': 0,
            'descargas_info': [],
            'ultima_actualizacion': timezone.now().isoformat(),
            'error': 'Empresa no encontrada'
        }, status=404)
        
    except Exception as e:
        logger.error(f"Error al obtener estado de monitoreo para empresa {empresa_id}: {str(e)}")
        # Retornar un estado válido incluso en caso de error
        return JsonResponse({
            'estado': 'INACTIVO',
            'descargas_activas': 0,
            'descargas_info': [],
            'ultima_actualizacion': timezone.now().isoformat(),
            'error': 'Error al obtener el estado del monitoreo'
        })

@login_required
def escanear_empresa(request, empresa_id):
    """Inicia un escaneo de la empresa en segundo plano."""
    empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
    
    try:
        # Obtener el límite de archivos del request
        limite_archivos = int(request.POST.get('limite_archivos', 1000))
        logger.info(f"Límite de archivos recibido: {limite_archivos}")
        
        # Validar el límite
        limites_validos = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 2000, 5000, 10000]
        if limite_archivos not in limites_validos:
            logger.error(f"Límite de archivos no válido: {limite_archivos}")
            raise ValueError(f"Límite de archivos no válido. Debe ser uno de: {', '.join(map(str, limites_validos))}")
        
        # Eliminar amenazas no resueltas antes de iniciar nuevo escaneo
        Amenaza.objects.filter(empresa=empresa, resuelta=False).delete()
        
        # Registrar limpieza de amenazas anteriores
        RegistroActividad.objects.create(
            empresa=empresa,
            tipo='LIMPIEZA',
            descripcion='Limpieza de amenazas no resueltas antes de nuevo escaneo',
            usuario=request.user
        )
        
        # Iniciar escaneo en segundo plano
        servicio = ServicioMonitoreo()
        servicio.escanear_sistema(empresa, limite_archivos=limite_archivos)
        
        logger.info(f"Escaneo iniciado con límite de {limite_archivos} archivos")
        return JsonResponse({'status': 'success', 'message': 'Escaneo iniciado correctamente'})
    except ValueError as e:
        logger.error(f"Error de validación: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error al iniciar escaneo: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Error al iniciar el escaneo'}, status=500)

@login_required
def obtener_progreso_escaneo(request, empresa_id):
    """Obtiene el progreso actual del escaneo."""
    empresa = get_object_or_404(Empresas, id=empresa_id, usuario=request.user)
    servicio = ServicioMonitoreo()
    progreso = servicio.obtener_progreso_escaneo(empresa.id)
    return JsonResponse(progreso)

@login_required
def actualizar_config_monitoreo(request, empresa_id):
    try:
        empresa = Empresas.objects.get(pk=empresa_id, usuario=request.user)
        config = ConfiguracionMonitoreo.objects.get(empresa=empresa)
    except Empresas.DoesNotExist:
        messages.error(request, 'La empresa no existe o no tienes permisos para acceder a ella.')
        return redirect('lista_empresas')
    except ConfiguracionMonitoreo.DoesNotExist:
        config = ConfiguracionMonitoreo.objects.create(empresa=empresa)
    
    if request.method == 'POST':
        config.escaneo_automatico = request.POST.get('escaneo_automatico') == 'on'
        config.frecuencia_escaneo = int(request.POST.get('frecuencia_escaneo', 24))
        config.notificar_amenazas = request.POST.get('notificar_amenazas') == 'on'
        config.nivel_alertas = request.POST.get('nivel_alertas', 'MEDIA_ALTA')
        config.save()
        
        messages.success(request, '¡Configuración de monitoreo actualizada exitosamente!')
        return redirect('detalle_empresa', empresa_id=empresa_id)
    
    return render(request, 'empresas/config_monitoreo.html', {
        'empresa': empresa,
        'config': config
    })

@login_required
def marcar_amenaza_resuelta(request, amenaza_id):
    try:
        amenaza = Amenaza.objects.get(pk=amenaza_id, empresa__usuario=request.user)
        amenaza.resuelta = True
        amenaza.fecha_resolucion = timezone.now()
        amenaza.save()

        # Registrar la actividad
        RegistroActividad.objects.create(
            empresa=amenaza.empresa,
            tipo='ACTUALIZACION',
            descripcion=f'Amenaza resuelta: {amenaza.get_tipo_display()}',
            detalles={
                'amenaza_id': amenaza.id,
                'tipo': amenaza.tipo,
                'severidad': amenaza.severidad,
                'fecha_resolucion': amenaza.fecha_resolucion.isoformat()
            }
        )

        messages.success(request, 'La amenaza ha sido marcada como resuelta.')
    except Amenaza.DoesNotExist:
        messages.error(request, 'La amenaza no existe o no tienes permisos para acceder a ella.')
    except Exception as e:
        messages.error(request, f'Error al marcar la amenaza como resuelta: {str(e)}')

    return redirect('detalle_empresa', empresa_id=amenaza.empresa.id)

@login_required
def dashboard_seguridad(request):
    empresas = Empresas.objects.filter(usuario=request.user)
    
    # Obtener amenazas activas con filtros
    amenazas_activas = Amenaza.objects.filter(
        empresa__in=empresas,
        resuelta=False
    )
    
    # Aplicar filtros adicionales si existen
    tipo = request.GET.get('tipo')
    empresa_id = request.GET.get('empresa')
    fecha_desde = request.GET.get('fecha_desde')
    fecha_hasta = request.GET.get('fecha_hasta')
    
    if tipo:
        amenazas_activas = amenazas_activas.filter(tipo=tipo)
    if empresa_id:
        amenazas_activas = amenazas_activas.filter(empresa_id=empresa_id)
    if fecha_desde:
        amenazas_activas = amenazas_activas.filter(fecha_deteccion__gte=fecha_desde)
    if fecha_hasta:
        amenazas_activas = amenazas_activas.filter(fecha_deteccion__lte=fecha_hasta)
    
    # Ordenar por fecha de detección y severidad
    amenazas_activas = amenazas_activas.order_by('-fecha_deteccion', '-severidad')
    
    # Estadísticas generales
    total_amenazas = Amenaza.objects.filter(empresa__in=empresas).count()
    total_escaneos = RegistroActividad.objects.filter(
        empresa__in=empresas,
        tipo='ESCANEO'
    ).count()
    
    # Amenazas por tipo
    amenazas_por_tipo = {}
    for tipo, _ in Amenaza.TIPOS_AMENAZA:
        count = Amenaza.objects.filter(
            empresa__in=empresas,
            tipo=tipo,
            resuelta=False
        ).count()
        amenazas_por_tipo[tipo] = count
    
    # Actividad reciente
    actividad_reciente = RegistroActividad.objects.filter(
        empresa__in=empresas
    ).order_by('-fecha')[:10]
    
    # Paginar amenazas activas
    paginator = Paginator(amenazas_activas, 50)  # 50 amenazas por página
    page = request.GET.get('page', 1)
    try:
        amenazas_paginadas = paginator.page(page)
    except (PageNotAnInteger, EmptyPage):
        amenazas_paginadas = paginator.page(1)
    
    context = {
        'total_amenazas': total_amenazas,
        'amenazas_activas': amenazas_paginadas,
        'total_escaneos': total_escaneos,
        'amenazas_por_tipo': amenazas_por_tipo,
        'actividad_reciente': actividad_reciente,
        'empresas': empresas,
        'filtros_activos': {
            'tipo': tipo,
            'empresa': empresa_id,
            'fecha_desde': fecha_desde,
            'fecha_hasta': fecha_hasta
        }
    }
    
    return render(request, 'dashboard_seguridad.html', context)

@login_required
def manual_usuario(request):
    """Vista para el manual de usuario."""
    return render(request, 'manual_usuario.html')

@login_required
def registro_actividad(request):
    """Vista para el registro de actividad del sistema."""
    # Obtener todas las empresas del usuario
    empresas = Empresas.objects.filter(usuario=request.user)
    
    # Filtrar actividades según los parámetros
    actividades = RegistroActividad.objects.filter(empresa__in=empresas)
    
    # Aplicar filtros
    tipo = request.GET.get('tipo')
    empresa_id = request.GET.get('empresa')
    fecha_desde = request.GET.get('fecha_desde')
    fecha_hasta = request.GET.get('fecha_hasta')
    
    if tipo:
        actividades = actividades.filter(tipo=tipo)
    if empresa_id:
        actividades = actividades.filter(empresa_id=empresa_id)
    if fecha_desde:
        actividades = actividades.filter(fecha__gte=fecha_desde)
    if fecha_hasta:
        actividades = actividades.filter(fecha__lte=fecha_hasta)
    
    # Ordenar por fecha descendente y paginar
    actividades = actividades.order_by('-fecha')
    paginator = Paginator(actividades, 20)  # 20 registros por página
    page = request.GET.get('page')
    actividades = paginator.get_page(page)
    
    return render(request, 'registro_actividad.html', {
        'actividades': actividades,
        'empresas': empresas
    })
