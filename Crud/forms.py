from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Empresas

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password1', 'password2']

class EmpresasForm(forms.ModelForm):
    class Meta:
        model = Empresas
        fields = ['Nombre_Empresa', 'Cant_Empleados', 'representante', 'imagen']
        widgets = {
            'Nombre_Empresa': forms.TextInput(attrs={'class': 'form-control'}),
            'Cant_Empleados': forms.NumberInput(attrs={'class': 'form-control'}),
            'representante': forms.TextInput(attrs={'class': 'form-control'}),
            'imagen': forms.FileInput(attrs={'class': 'form-control'}),
        } 