from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('', views.landing, name='landing'),  # Nueva landing page
    path('home/', views.home, name='home'),  # Dashboard principal (requiere login)
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', LogoutView.as_view(next_page='landing', http_method_names=['get', 'post']), name='logout'),
    
    # Manual de Usuario
    path('manual/', views.manual_usuario, name='manual_usuario'),
    
    # Registro de Actividad
    path('registro/', views.registro_actividad, name='registro_actividad'),
    
    # URLs para Empresas
    path('empresa/nueva/', views.crear_empresa, name='crear_empresa'),
    path('empresa/<int:empresa_id>/', views.detalle_empresa, name='detalle_empresa'),
    path('empresa/<int:empresa_id>/editar/', views.editar_empresa, name='editar_empresa'),
    path('empresa/<int:empresa_id>/eliminar/', views.eliminar_empresa, name='eliminar_empresa'),
    
    # URLs para Seguridad
    path('empresa/<int:empresa_id>/escanear/', views.escanear_empresa, name='escanear_empresa'),
    path('empresa/<int:empresa_id>/progreso/', views.obtener_progreso_escaneo, name='progreso_escaneo'),
    path('empresa/<int:empresa_id>/config/', views.actualizar_config_monitoreo, name='actualizar_config_monitoreo'),
    path('amenaza/<int:amenaza_id>/resolver/', views.marcar_amenaza_resuelta, name='marcar_amenaza_resuelta'),
    path('dashboard/seguridad/', views.dashboard_seguridad, name='dashboard_seguridad'),
    path('empresa/<int:empresa_id>/iniciar-monitoreo/', views.iniciar_monitoreo, name='iniciar_monitoreo'),
    path('empresa/<int:empresa_id>/detener-monitoreo/', views.detener_monitoreo, name='detener_monitoreo'),
    path('empresa/<int:empresa_id>/reiniciar-monitoreo/', views.reiniciar_monitoreo, name='reiniciar_monitoreo'),
    path('empresa/<int:empresa_id>/estado-monitoreo/', views.estado_monitoreo, name='estado_monitoreo'),
] 