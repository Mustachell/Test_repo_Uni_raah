import time
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from Crud.models import Empresas
from Crud.services import ServicioMonitoreo

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Ejecuta el servicio de monitoreo de seguridad en segundo plano'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Iniciando servicio de monitoreo de seguridad...'))
        
        while True:
            try:
                # Obtener todas las empresas con monitoreo activo
                empresas = Empresas.objects.filter(estado_monitoreo=True)
                
                for empresa in empresas:
                    try:
                        servicio = ServicioMonitoreo(empresa)
                        
                        # Verificar si es necesario realizar un escaneo
                        if servicio.monitorear_continuamente():
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f'Escaneo completado para {empresa.Nombre_Empresa}'
                                )
                            )
                            
                        # Verificar actualizaciones
                        if servicio.verificar_actualizaciones():
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f'Actualizaciones verificadas para {empresa.Nombre_Empresa}'
                                )
                            )
                            
                    except Exception as e:
                        logger.error(f"Error al monitorear empresa {empresa.Nombre_Empresa}: {str(e)}")
                        self.stdout.write(
                            self.style.ERROR(
                                f'Error al monitorear {empresa.Nombre_Empresa}: {str(e)}'
                            )
                        )
                
                # Esperar 5 minutos antes de la siguiente verificación
                time.sleep(300)
                
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('Servicio de monitoreo detenido por el usuario'))
                break
            except Exception as e:
                logger.error(f"Error en el servicio de monitoreo: {str(e)}")
                self.stdout.write(
                    self.style.ERROR(f'Error en el servicio de monitoreo: {str(e)}')
                )
                time.sleep(60)  # Esperar 1 minuto antes de reintentar 