from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.

class Empresas(models.Model):
    Nombre_Empresa = models.CharField(max_length=100)
    Cant_Empleados = models.IntegerField()
    representante = models.CharField(max_length=100, verbose_name='Representante Legal')
    imagen = models.ImageField(upload_to='empresas/', null=True, blank=True)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    # Nuevos campos para ciberseguridad
    nivel_seguridad = models.CharField(
        max_length=20,
        choices=[
            ('BAJO', 'Bajo'),
            ('MEDIO', 'Medio'),
            ('ALTO', 'Alto'),
        ],
        default='MEDIO'
    )
    ultimo_escaneo = models.DateTimeField(null=True, blank=True)
    estado_monitoreo = models.BooleanField(default=True)

    def __str__(self):
        return self.Nombre_Empresa

    class Meta:
        verbose_name = 'Empresa'
        verbose_name_plural = 'Empresas'

class Amenaza(models.Model):
    TIPOS_AMENAZA = [
        ('MALWARE', 'Malware'),
        ('PHISHING', 'Phishing'),
        ('RANSOMWARE', 'Ransomware'),
        ('DOS', 'Denegación de Servicio'),
        ('OTRO', 'Otro'),
    ]

    NIVEL_SEVERIDAD = [
        ('BAJA', 'Baja'),
        ('MEDIA', 'Media'),
        ('ALTA', 'Alta'),
        ('CRITICA', 'Crítica'),
    ]

    empresa = models.ForeignKey(Empresas, on_delete=models.CASCADE, related_name='amenazas')
    tipo = models.CharField(max_length=20, choices=TIPOS_AMENAZA)
    severidad = models.CharField(max_length=20, choices=NIVEL_SEVERIDAD)
    descripcion = models.TextField()
    fecha_deteccion = models.DateTimeField(auto_now_add=True)
    fecha_resolucion = models.DateTimeField(null=True, blank=True)
    resuelta = models.BooleanField(default=False)
    detalles_tecnicos = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.get_tipo_display()} - {self.empresa.Nombre_Empresa}"

    class Meta:
        verbose_name = 'Amenaza'
        verbose_name_plural = 'Amenazas'
        ordering = ['-fecha_deteccion']

class RegistroActividad(models.Model):
    TIPOS_ACTIVIDAD = [
        ('ESCANEO', 'Escaneo de Sistema'),
        ('ACTUALIZACION', 'Actualización de Seguridad'),
        ('ALERTA', 'Alerta de Seguridad'),
        ('CONFIGURACION', 'Cambio de Configuración'),
    ]

    empresa = models.ForeignKey(Empresas, on_delete=models.CASCADE, related_name='actividades')
    tipo = models.CharField(max_length=20, choices=TIPOS_ACTIVIDAD)
    descripcion = models.TextField()
    fecha = models.DateTimeField(auto_now_add=True)
    detalles = models.JSONField(null=True, blank=True)
    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"{self.get_tipo_display()} - {self.empresa.Nombre_Empresa}"

    class Meta:
        verbose_name = 'Registro de Actividad'
        verbose_name_plural = 'Registros de Actividad'
        ordering = ['-fecha']

class ConfiguracionMonitoreo(models.Model):
    empresa = models.OneToOneField(Empresas, on_delete=models.CASCADE, related_name='configuracion')
    escaneo_automatico = models.BooleanField(default=True)
    frecuencia_escaneo = models.IntegerField(default=24, help_text='Frecuencia en horas')
    notificar_amenazas = models.BooleanField(default=True)
    nivel_alertas = models.CharField(
        max_length=20,
        choices=[
            ('TODAS', 'Todas las alertas'),
            ('MEDIA_ALTA', 'Media y Alta'),
            ('ALTA', 'Solo Alta'),
        ],
        default='MEDIA_ALTA'
    )
    ultima_actualizacion = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Configuración de {self.empresa.Nombre_Empresa}"

    class Meta:
        verbose_name = 'Configuración de Monitoreo'
        verbose_name_plural = 'Configuraciones de Monitoreo'
