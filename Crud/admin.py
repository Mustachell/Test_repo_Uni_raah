from django.contrib import admin
from .models import Empresas

@admin.register(Empresas)
class EmpresasAdmin(admin.ModelAdmin):
    list_display = ('Nombre_Empresa', 'Cant_Empleados', 'fecha_creacion', 'usuario')
    list_filter = ('fecha_creacion', 'usuario')
    search_fields = ('Nombre_Empresa',)
    date_hierarchy = 'fecha_creacion'
