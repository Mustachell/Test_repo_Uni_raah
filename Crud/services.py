import os
import json
import logging
import requests
import hashlib
import threading
import time
import yara
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from .models import Empresas, Amenaza, RegistroActividad

logger = logging.getLogger(__name__)

# Configuración de YARA
YARA_RULES_DIR = os.path.join(settings.BASE_DIR, 'yara_rules')
YARA_RULES = {}

def _cargar_reglas_yara():
    """Carga las reglas YARA desde el directorio de reglas."""
    global YARA_RULES
    try:
        if not os.path.exists(YARA_RULES_DIR):
            os.makedirs(YARA_RULES_DIR)
            logger.warning(f"Directorio de reglas YARA creado en: {YARA_RULES_DIR}")
            return

        for archivo in os.listdir(YARA_RULES_DIR):
            if archivo.endswith('.yar') or archivo.endswith('.yara'):
                ruta_regla = os.path.join(YARA_RULES_DIR, archivo)
                try:
                    YARA_RULES[archivo] = yara.compile(ruta_regla)
                    logger.info(f"Regla YARA cargada: {archivo}")
                except Exception as e:
                    logger.error(f"Error al cargar regla YARA {archivo}: {str(e)}")
    except Exception as e:
        logger.error(f"Error al cargar reglas YARA: {str(e)}")

# Cargar reglas YARA al iniciar
_cargar_reglas_yara()

class ServicioMonitoreo:
    _instancia = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instancia is None:
            with cls._lock:
                if cls._instancia is None:
                    cls._instancia = super(ServicioMonitoreo, cls).__new__(cls)
                    cls._instancia._inicializado = False
        return cls._instancia
    
    def __init__(self):
        if self._inicializado:
            return
            
        # Configuración de VirusTotal (mantenemos la estructura pero no la usamos)
        self.virustotal_api_key = "50090cdca66602e767ea1d42a05135b418779e8a6f84e347bbfb39e894d5431b"
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.virustotal_headers = {
            "x-apikey": self.virustotal_api_key,
            "Accept": "application/json"
        }
        
        # Estado del monitoreo
        self.monitoreo_activo = False
        self._hilo_monitoreo = None
        self._evento_detener = threading.Event()
        self.descargas_activas = {}
        self.escaneo_inicial_completado = False
        
        # Directorio de descargas
        self.directorio_descargas = os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        
        self._inicializado = True
        logger.info("ServicioMonitoreo inicializado")

    def _registrar_actividad_monitoreo(self, tipo, descripcion):
        """Registra una actividad relacionada con el monitoreo."""
        try:
            empresas = Empresas.objects.all()
            for empresa in empresas:
                RegistroActividad.objects.create(
                    empresa=empresa,
                    tipo=tipo,
                    descripcion=descripcion,
                    detalles={
                        'timestamp': timezone.now().isoformat(),
                        'estado': 'MONITOREANDO' if self.monitoreo_activo else 'INACTIVO'
                    },
                    usuario=empresa.usuario
                )
        except Exception as e:
            logger.error(f"Error al registrar actividad de monitoreo: {str(e)}")

    def iniciar_monitoreo(self):
        """Inicia el monitoreo de descargas."""
        try:
            with self._lock:
                if self.monitoreo_activo:
                    logger.warning("El monitoreo ya está activo")
                    return True  # Cambiado a True para indicar que ya está activo
                
                # Limpiar estado anterior
                self.descargas_activas.clear()
                self._evento_detener.clear()
                self.monitoreo_activo = True
                self.escaneo_inicial_completado = False
                
                # Registrar inicio del monitoreo
                self._registrar_actividad_monitoreo(
                    'INICIO_MONITOREO',
                    'Iniciando monitoreo de descargas'
                )
                
                # Iniciar hilo de monitoreo
                self._hilo_monitoreo = threading.Thread(
                    target=self._monitorear_descargas,
                    daemon=True
                )
                self._hilo_monitoreo.start()
                
                logger.info("Monitoreo iniciado correctamente")
                return True
                
        except Exception as e:
            logger.error(f"Error al iniciar monitoreo: {str(e)}")
            self.monitoreo_activo = False
            return False

    def detener_monitoreo(self):
        """Detiene el monitoreo de descargas."""
        try:
            with self._lock:
                if not self.monitoreo_activo:
                    logger.warning("El monitoreo ya está detenido")
                    return True  # Cambiado a True para indicar que ya está detenido
                
                self._evento_detener.set()
                self.monitoreo_activo = False
                
                # Registrar detención del monitoreo
                self._registrar_actividad_monitoreo(
                    'DETENCION_MONITOREO',
                    'Deteniendo monitoreo de descargas'
                )
                
                if self._hilo_monitoreo and self._hilo_monitoreo.is_alive():
                    self._hilo_monitoreo.join(timeout=5)
                
                # Limpiar estado
                self.descargas_activas.clear()
                
                logger.info("Monitoreo detenido correctamente")
                return True
                
        except Exception as e:
            logger.error(f"Error al detener monitoreo: {str(e)}")
            return False

    def reiniciar_monitoreo(self):
        """Reinicia el monitoreo de descargas."""
        try:
            # Registrar reinicio del monitoreo
            self._registrar_actividad_monitoreo(
                'REINICIO_MONITOREO',
                'Reiniciando monitoreo de descargas'
            )
            
            # Detener el monitoreo actual
            self.detener_monitoreo()
            time.sleep(1)  # Esperar a que se detenga completamente
            
            # Iniciar el monitoreo nuevamente
            return self.iniciar_monitoreo()
            
        except Exception as e:
            logger.error(f"Error al reiniciar monitoreo: {str(e)}")
            return False

    def _escanear_archivos_existentes(self):
        """Escanea los archivos existentes en el directorio de descargas."""
        try:
            logger.info("Iniciando escaneo de archivos existentes...")
            
            # Obtener la fecha de hoy
            hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Listar archivos en el directorio
            archivos = os.listdir(self.directorio_descargas)
            
            for nombre_archivo in archivos:
                if self._evento_detener.is_set():
                    break
                    
                ruta_archivo = os.path.join(self.directorio_descargas, nombre_archivo)
                
                # Solo procesar archivos (no directorios)
                if not os.path.isfile(ruta_archivo):
                    continue
                
                # Verificar si el archivo fue modificado hoy
                tiempo_modificacion = datetime.fromtimestamp(os.path.getmtime(ruta_archivo))
                if tiempo_modificacion < hoy:
                    continue
                
                # Procesar el archivo
                self._procesar_archivo(nombre_archivo, ruta_archivo)
            
            logger.info("Escaneo de archivos existentes completado")
            self.escaneo_inicial_completado = True
            
        except Exception as e:
            logger.error(f"Error al escanear archivos existentes: {str(e)}")
            self.escaneo_inicial_completado = True  # Marcar como completado para no bloquear el monitoreo

    def _monitorear_descargas(self):
        """Monitorea el directorio de descargas en busca de nuevos archivos."""
        logger.info(f"Iniciando monitoreo de directorio: {self.directorio_descargas}")
        
        # Obtener la fecha de hoy para el monitoreo
        hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Archivos ya procesados en esta sesión
        archivos_procesados = set()
        
        while not self._evento_detener.is_set():
            try:
                # Verificar archivos en el directorio
                archivos = os.listdir(self.directorio_descargas)
                
                # Procesar cada archivo
                for nombre_archivo in archivos:
                    if self._evento_detener.is_set():
                        break
                    
                    # Ignorar archivos temporales de descarga
                    if nombre_archivo.endswith(('.crdownload', '.part', '.tmp')):
                        continue
                        
                    ruta_archivo = os.path.join(self.directorio_descargas, nombre_archivo)
                    
                    # Solo procesar archivos (no directorios)
                    if not os.path.isfile(ruta_archivo):
                        continue
                    
                    # Verificar si el archivo fue modificado hoy
                    tiempo_modificacion = datetime.fromtimestamp(os.path.getmtime(ruta_archivo))
                    if tiempo_modificacion < hoy:
                        continue
                    
                    # Verificar si el archivo es nuevo y no ha sido procesado
                    with self._lock:
                        if nombre_archivo not in self.descargas_activas and nombre_archivo not in archivos_procesados:
                            logger.info(f"Nueva descarga detectada: {nombre_archivo}")
                            
                            # Agregar a la lista de procesados
                            archivos_procesados.add(nombre_archivo)
                            
                            # Iniciar procesamiento del archivo
                            self.descargas_activas[nombre_archivo] = {
                                'ruta': ruta_archivo,
                                'tamaño': os.path.getsize(ruta_archivo),
                                'estado': 'Procesando',
                                'estado_color': 'primary',
                                'fecha_deteccion': tiempo_modificacion.isoformat(),
                                'ultima_actualizacion': time.time()
                            }
                            
                            # Procesar el archivo en un hilo separado
                            threading.Thread(
                                target=self._procesar_archivo,
                                args=(nombre_archivo, ruta_archivo),
                                daemon=True
                            ).start()
                
                # Limpiar archivos que ya no existen
                with self._lock:
                    for nombre_archivo in list(self.descargas_activas.keys()):
                        if nombre_archivo not in archivos:
                            del self.descargas_activas[nombre_archivo]
                
                # Esperar antes de la siguiente verificación
                time.sleep(1)  # Importante: evitar uso excesivo de CPU
                
            except Exception as e:
                logger.error(f"Error en ciclo de monitoreo: {str(e)}")
                if not self._evento_detener.is_set():
                    time.sleep(1)
        
        logger.info("Monitoreo detenido")

    def _simular_descarga(self, nombre_archivo):
        """Simula el progreso de una descarga."""
        try:
            tiempo_inicio = time.time()
            tiempo_total = 5  # Reducido a 5 segundos para que sea más rápido
            ultima_actualizacion_estado = tiempo_inicio
            
            while not self._evento_detener.is_set():
                tiempo_actual = time.time()
                tiempo_transcurrido = tiempo_actual - tiempo_inicio
                
                with self._lock:
                    if nombre_archivo not in self.descargas_activas:
                        return
                    
                    info = self.descargas_activas[nombre_archivo]
                    
                    # Calcular progreso asegurando que llegue al 100%
                    if tiempo_transcurrido >= tiempo_total:
                        info['progreso'] = 100
                        info['ultima_actualizacion'] = tiempo_actual
                        info['estado'] = 'Escaneando'
                        info['estado_color'] = 'warning'
                        # Procesar el archivo inmediatamente
                        self._procesar_archivo(nombre_archivo, info['ruta'])
                        return
                    else:
                        # Calcular progreso lineal
                        progreso = min(100, int((tiempo_transcurrido / tiempo_total) * 100))
                        info['progreso'] = progreso
                        info['ultima_actualizacion'] = tiempo_actual
                        info['estado'] = 'Descargando'
                        info['estado_color'] = 'primary'
                        
                        # Actualizar estado cada 2 segundos
                        if tiempo_actual - ultima_actualizacion_estado >= 2:
                            ultima_actualizacion_estado = tiempo_actual
                            info['ultima_actualizacion_estado'] = tiempo_actual
                
                # Actualizar más frecuentemente para una animación más suave
                time.sleep(0.1)  # Actualizar cada 100ms
                
        except Exception as e:
            logger.error(f"Error al simular descarga de {nombre_archivo}: {str(e)}")
            with self._lock:
                if nombre_archivo in self.descargas_activas:
                    self.descargas_activas[nombre_archivo]['estado'] = 'Error'
                    self.descargas_activas[nombre_archivo]['estado_color'] = 'danger'
                    self.descargas_activas[nombre_archivo]['error'] = str(e)
                    self.descargas_activas[nombre_archivo]['progreso'] = 100
                    self.descargas_activas[nombre_archivo]['ultima_actualizacion'] = time.time()

    def _procesar_archivo(self, nombre_archivo, ruta_archivo):
        """Procesa un archivo descargado usando YARA y VirusTotal."""
        try:
            logger.info(f"Iniciando procesamiento de archivo: {nombre_archivo}")
            
            with self._lock:
                if nombre_archivo not in self.descargas_activas:
                    return
                
                info = self.descargas_activas[nombre_archivo]
                info['estado'] = 'Escaneando'
                info['estado_color'] = 'warning'
                info['ultima_actualizacion'] = time.time()
            
            # Calcular hash del archivo
            hash_sha256 = self._calcular_hash(ruta_archivo)
            
            # Primero escanear con YARA
            resultado_yara = self._escanear_yara(ruta_archivo)
            es_malware = resultado_yara['detectado']
            
            # Si YARA no detecta nada, consultar VirusTotal
            if not es_malware:
                resultado_vt = self._consultar_virustotal(hash_sha256)
                if resultado_vt:
                    stats = resultado_vt.get('data', {}).get('attributes', {}).get('stats', {})
                    es_malware = stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 5
                else:
                    # Si no hay resultado de VT, usar solo YARA
                    resultado_vt = None
            
            # Preparar detalles del escaneo
            detalles = {
                'yara': resultado_yara,
                'virustotal': resultado_vt,
                'hash_sha256': hash_sha256,
                'timestamp': timezone.now().isoformat()
            }
            
            # Actualizar estado según el resultado
            with self._lock:
                if nombre_archivo in self.descargas_activas:
                    info = self.descargas_activas[nombre_archivo]
                    info['ultima_actualizacion'] = time.time()
                    info['detalles'] = detalles
                    
                    if es_malware:
                        info['estado'] = 'Malware Detectado'
                        info['estado_color'] = 'danger'
                        logger.warning(f"¡ALERTA! Archivo malicioso detectado: {nombre_archivo}")
                        self._registrar_amenaza(nombre_archivo, ruta_archivo, detalles)
                    else:
                        info['estado'] = 'Archivo Seguro'
                        info['estado_color'] = 'success'
                        logger.info(f"Archivo seguro: {nombre_archivo}")
                        self._registrar_actividad(nombre_archivo, ruta_archivo, detalles)
            
            # Notificar al usuario
            try:
                from plyer import notification
                notification.notify(
                    title="Escaneo Completado",
                    message=f"'{nombre_archivo}' ha sido escaneado y está {'seguro' if not es_malware else 'infectado'}.",
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Error al mostrar notificación: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error al procesar archivo {nombre_archivo}: {str(e)}")
            with self._lock:
                if nombre_archivo in self.descargas_activas:
                    self.descargas_activas[nombre_archivo]['estado'] = 'Error en Escaneo'
                    self.descargas_activas[nombre_archivo]['estado_color'] = 'danger'
                    self.descargas_activas[nombre_archivo]['error'] = str(e)
                    self.descargas_activas[nombre_archivo]['ultima_actualizacion'] = time.time()

    def _calcular_hash(self, ruta_archivo):
        """Calcula el hash SHA-256 de un archivo."""
        try:
            sha256_hash = hashlib.sha256()
            with open(ruta_archivo, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error al calcular hash: {str(e)}")
            raise

    def _escanear_yara(self, ruta_archivo):
        """Escanea un archivo usando reglas YARA locales."""
        try:
            resultados = []
            matches = []
            
            # Asegurarse de que las reglas estén cargadas
            if not YARA_RULES:
                _cargar_reglas_yara()
            
            # Escanear el archivo con cada regla
            for nombre_regla, regla in YARA_RULES.items():
                try:
                    matches = regla.match(ruta_archivo)
                    if matches:
                        for match in matches:
                            resultados.append({
                                'regla': nombre_regla,
                                'strings': match.strings,
                                'metadatos': match.meta,
                                'namespace': match.namespace
                            })
                except Exception as e:
                    logger.error(f"Error al escanear con regla {nombre_regla}: {str(e)}")
                    continue
            
            return {
                'detectado': len(resultados) > 0,
                'resultados': resultados,
                'total_reglas': len(YARA_RULES),
                'reglas_aplicadas': list(YARA_RULES.keys())
            }
            
        except Exception as e:
            logger.error(f"Error en escaneo YARA: {str(e)}")
            raise

    def _consultar_virustotal(self, hash_sha256):
        """Consulta el hash en VirusTotal."""
        try:
            # Verificar rate limit (4 requests por minuto para API pública)
            tiempo_actual = time.time()
            if hasattr(self, '_ultima_consulta_vt'):
                tiempo_desde_ultima = tiempo_actual - self._ultima_consulta_vt
                if tiempo_desde_ultima < 15:  # Esperar 15 segundos entre consultas
                    time.sleep(15 - tiempo_desde_ultima)
            
            # Realizar la consulta
            url = f"{self.virustotal_base_url}/files/{hash_sha256}"
            response = requests.get(url, headers=self.virustotal_headers)
            
            # Actualizar timestamp de última consulta
            self._ultima_consulta_vt = time.time()
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"Hash no encontrado en VirusTotal: {hash_sha256}")
                return None
            elif response.status_code == 429:
                logger.warning("Rate limit de VirusTotal alcanzado")
                time.sleep(60)  # Esperar 1 minuto antes de reintentar
                return self._consultar_virustotal(hash_sha256)
            else:
                logger.error(f"Error en consulta VirusTotal: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error al consultar VirusTotal: {str(e)}")
            return None

    def _registrar_amenaza(self, nombre_archivo, ruta_archivo, resultado):
        """Registra una amenaza detectada."""
        try:
            # Obtener todas las empresas
            empresas = Empresas.objects.all()
            
            # Detalles del escaneo
            stats = resultado.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            # Determinar severidad
            if malicious > 5 or suspicious > 10:
                severidad = 'ALTA'
            elif malicious > 2 or suspicious > 5:
                severidad = 'MEDIA'
            else:
                severidad = 'BAJA'
            
            # Crear amenaza para cada empresa
            for empresa in empresas:
                Amenaza.objects.create(
                    empresa=empresa,
                    tipo='MALWARE',
                    severidad=severidad,
                    descripcion=f"Archivo malicioso detectado: {nombre_archivo}",
                    detalles_tecnicos={
                        'ruta': ruta_archivo,
                        'hash_sha256': resultado.get("data", {}).get("id"),
                        'detectores': stats,
                        'reporte_completo': resultado
                    }
                )
                
                # Registrar actividad
                RegistroActividad.objects.create(
                    empresa=empresa,
                    tipo='ALERTA',
                    descripcion=f"Archivo malicioso detectado: {nombre_archivo}",
                    detalles={
                        'archivo': nombre_archivo,
                        'severidad': severidad,
                        'detectores': stats
                    },
                    usuario=empresa.usuario
                )
                
        except Exception as e:
            logger.error(f"Error al registrar amenaza: {str(e)}")

    def _registrar_actividad(self, nombre_archivo, ruta_archivo, resultado):
        """Registra una actividad de escaneo."""
        try:
            # Obtener todas las empresas
            empresas = Empresas.objects.all()
            
            for empresa in empresas:
                RegistroActividad.objects.create(
                    empresa=empresa,
                    tipo='ESCANEO',
                    descripcion=f"Archivo escaneado: {nombre_archivo}",
                    detalles={
                        'archivo': nombre_archivo,
                        'ruta': ruta_archivo,
                        'hash_sha256': resultado.get("data", {}).get("id"),
                        'resultado': resultado
                    },
                    usuario=empresa.usuario
                )
                
        except Exception as e:
            logger.error(f"Error al registrar actividad: {str(e)}")

    def obtener_estado_monitoreo(self, empresa_id):
        """Obtiene el estado actual del monitoreo."""
        try:
            # Verificar que la empresa existe
            empresa = Empresas.objects.get(id=empresa_id)
            
            with self._lock:
                descargas_info = []
                try:
                    for nombre_archivo, info in self.descargas_activas.items():
                        try:
                            # Convertir tamaño a formato legible
                            tamaño = info.get('tamaño', 0)
                            if tamaño > 1024 * 1024:
                                tamaño_str = f"{tamaño/1024/1024:.1f} MB"
                            elif tamaño > 1024:
                                tamaño_str = f"{tamaño/1024:.1f} KB"
                            else:
                                tamaño_str = f"{tamaño} B"
                            
                            # Asegurar que el progreso nunca sea mayor a 100
                            progreso = min(info.get('progreso', 0), 100)
                            
                            # Determinar color del estado
                            estado = info.get('estado', 'Desconocido')
                            if estado == 'Malware':
                                estado_color = 'danger'
                            elif estado == 'Seguro':
                                estado_color = 'success'
                            elif estado in ['Descargando', 'Escaneando']:
                                estado_color = 'warning'
                            else:
                                estado_color = 'secondary'
                            
                            # Incluir detalles del escaneo si existen
                            detalles = None
                            if estado in ['Malware', 'Seguro'] and 'detalles' in info:
                                detalles = info['detalles']
                            
                            descargas_info.append({
                                'nombre': nombre_archivo,
                                'tamaño': tamaño_str,
                                'estado': estado,
                                'estado_color': estado_color,
                                'progreso': progreso,
                                'ultima_actualizacion': info.get('ultima_actualizacion', time.time()),
                                'detalles': detalles,
                                'error': info.get('error')
                            })
                        except Exception as e:
                            logger.error(f"Error al procesar información de descarga {nombre_archivo}: {str(e)}")
                            continue
                
                except Exception as e:
                    logger.error(f"Error al procesar descargas activas: {str(e)}")
                    descargas_info = []
            
            return {
                'estado': 'MONITOREANDO' if self.monitoreo_activo else 'INACTIVO',
                'descargas_activas': len(descargas_info),
                'descargas_info': descargas_info,
                'ultima_actualizacion': timezone.now().isoformat()
            }
                
        except Empresas.DoesNotExist:
            logger.error(f"Empresa no encontrada: {empresa_id}")
            return {
                'estado': 'INACTIVO',
                'descargas_activas': 0,
                'descargas_info': [],
                'ultima_actualizacion': timezone.now().isoformat(),
                'error': 'Empresa no encontrada'
            }
            
        except Exception as e:
            logger.error(f"Error al obtener estado de monitoreo: {str(e)}")
            return {
                'estado': 'INACTIVO',
                'descargas_activas': 0,
                'descargas_info': [],
                'ultima_actualizacion': timezone.now().isoformat(),
                'error': str(e)
            } 