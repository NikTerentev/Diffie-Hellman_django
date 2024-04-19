from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm

from .models import Photo


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'validate', }))
    password = forms.CharField(label='Password', widget=forms.PasswordInput(),
                               min_length=12, max_length=100)


class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(label='Password',
                               widget=forms.PasswordInput, min_length=12,
                               max_length=100)
    password2 = forms.CharField(label='Repeat password',
                                widget=forms.PasswordInput, min_length=12,
                                max_length=100)
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'first_name', 'email']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already in use.')
        return email


class PhotoForm(forms.ModelForm):
    class Meta:
        model = Photo
        fields = ['image']
