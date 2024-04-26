from typing import Any, Dict, NoReturn, Optional, Union

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm as PasswordResetFormCore
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from users.tasks import send_reset_password_mail

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

    def clean_username(self) -> Union[str, NoReturn]:
        username: str = self.cleaned_data.get("username", "")
        username_len = len(username)
        if username_len < 5 or username_len > 64:
            raise ValidationError("Неверная длина имени пользователя.", code="invalid")
        return username

    def clean_password2(self) -> Union[str, NoReturn]:
        password1: str = self.cleaned_data.get("password1", "")
        password2: str = self.cleaned_data.get("password2", "")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Пароли не совпадают.", code="invalid")
        pass_length = len(password2)
        if pass_length > 64 or pass_length < 8:
            raise ValidationError("Недопустимая длина пароля.", code="invalid")
        return password2

    def save(self, commit: Optional[bool] = True) -> User:
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


class PasswordResetForm(PasswordResetFormCore):
    email = forms.EmailField(
        label=_("Почта"),
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )

    def send_mail(
        self,
        subject_template_name: str,
        email_template_name: str,
        context: Dict[str, Any],
        from_email: Union[str, None],
        to_email: str,
        html_email_template_name: Optional[str] = None,
    ) -> None:
        context['user'] = context['user'].id

        send_reset_password_mail.delay(
            subject_template_name,
            email_template_name,
            context,
            from_email,
            to_email,
            html_email_template_name
        )
