from django import forms
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class AddPasswordForm(forms.Form):
    note = forms.CharField(
        label=_("Примета"),
        max_length=256
    )
    password1 = forms.CharField(
        label=_("Пароль"),
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False
    )
    password2 = forms.CharField(
        label=_("Подтверждение пароля"),
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                "Пароли не совпадают",
                code="password_mismatch",
            )
        password_validation.validate_password(password2)
        return password2