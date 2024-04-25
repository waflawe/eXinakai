from django import forms
from django.contrib.auth import get_user_model
from django.core.validators import ValidationError
from django.utils.translation import gettext_lazy as _

User = get_user_model()


class UserCreationForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput,
        help_text=_("Пароль для входа в аккаунт.")
    )
    password2 = forms.CharField(
        label="Подтверждение пароля",
        widget=forms.PasswordInput,
        help_text=_("Повторите выбранный пароль.")
    )

    class Meta:
        model = User
        fields = "username", "email"

    def clean_username(self):
        username = self.cleaned_data.get("username")
        username_len = len(username)
        if username_len < 5 or username_len > 64:
            raise ValidationError("Неверная длина имени пользователя.", code="invalid")

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Пароли не совпадают.", code="invalid")
        pass_length = len(password2)
        if pass_length > 64 or pass_length < 8:
            raise ValidationError("Недопустимая длина пароля.", code="invalid")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserAuthenticationForm(forms.Form):
    username = forms.CharField(max_length=64, widget=forms.TextInput(attrs={
        "class": "form-input"
    }), label="Имя пользователя")
    password = forms.CharField(max_length=64, min_length=8, widget=forms.PasswordInput(attrs={
        "class": "form-input",
    }), label="Пароль")
