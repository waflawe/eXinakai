from typing import Any, Dict, NoReturn, Optional, Union

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm as PasswordChangeFormCore
from django.contrib.auth.forms import PasswordResetForm as PasswordResetFormCore
from django.core.exceptions import ValidationError
from django.forms.widgets import CheckboxInput, Select, TextInput
from django.utils.translation import gettext_lazy as _
from pytz import common_timezones

from users.tasks import send_reset_password_mail

User = get_user_model()


class UserCreationForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput(attrs={"placeholder": "Пароль будущего пользователя"})
    )
    password2 = forms.CharField(
        label="Подтверждение пароля",
        widget=forms.PasswordInput(attrs={"placeholder": "Повтор пороля"})
    )

    class Meta:
        model = User
        fields = "username", "email"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget = forms.TextInput(attrs={"placeholder": "Имя будущего пользователя"})
        self.fields["email"].widget = forms.EmailInput(attrs={"placeholder": "Почта будущего пользователя"})

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
        "class": "form-input", "placeholder": "Имя пользователя"
    }), label="Имя пользователя")
    password = forms.CharField(max_length=64, min_length=8, widget=forms.PasswordInput(attrs={
        "class": "form-input", "placeholder": "Пароль пользователя"
    }), label="Пароль")


class PasswordResetForm(PasswordResetFormCore):
    email = forms.EmailField(
        label=_("Почта"),
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email", "placeholder": "Пароль для сброса"}),
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


class PasswordChangeForm(PasswordChangeFormCore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field, (label, placeholder) in {
            "old_password": ("Старый пароль", "Ваш старый пароль"),
            "new_password1": ("Новый пароль", "Ваш новый пароль"),
            "new_password2": ("Подтверждение нового пароля", "Повтор нового пароля"),
        }.items():
            self.fields[field].label = label
            self.fields[field].widget = forms.PasswordInput(attrs={"placeholder": placeholder})


class DataListInput(Select):
    template_name = "users/widgets/datalist.html"


class UpdateSettingsForm(forms.ModelForm):
    timezones = (
        (tzname, tzname) for tzname in common_timezones
    )

    timezone = forms.ChoiceField(
        choices=timezones,
        widget=DataListInput(),
        label="Временная зона"
    )

    class Meta:
        model = User
        fields = "email", "avatar", "timezone", "is_2fa_enabled"

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", kwargs.get("instance"))

        super().__init__(*args, **kwargs)
        self.fields["email"].widget = TextInput(attrs={"placeholder": user.email})
        is_2fa_enabled_attrs = {"checked": ""} if user.is_2fa_enabled else {}
        self.fields["timezone"].widget.attrs = {"placeholder": user.timezone}
        self.fields["is_2fa_enabled"].widget = CheckboxInput(attrs=is_2fa_enabled_attrs)

        for fname, fvalue in self.fields.items():
            fvalue.required = False


class ActivateCryptographicKeyForm(forms.Form):
    cryptographic_key = forms.CharField(
        label="Ключ шифрования",
        max_length=512,
        widget=forms.PasswordInput(attrs={"placeholder": "Ключ"})
    )


class TwoFactorAuthenticationForm(forms.Form):
    code = forms.CharField(
        label="Код аутентификации",
        help_text="Код аутентификации, который был выслан Вам на почту.",
        max_length=6,
        widget=forms.TextInput(attrs={"placeholder": "Код"})
    )
