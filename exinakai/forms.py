from django import forms
from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.forms.widgets import Input
from django.utils.translation import gettext_lazy as _

from exinakai.models import Password, PasswordsCollection

User = get_user_model()


class CustomPasswordInput(forms.PasswordInput):
    def get_context(self, name, value, attrs):
        return Input().get_context(name, value, attrs)


class ChangePasswordCollectionForm(forms.Form):
    collection = forms.ChoiceField(required=False)

    def __init__(self, collections: QuerySet, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["collection"].choices = (
            (collection.id, str(collection)) for collection in collections
        )
        self.fields["collection"].label = _("Коллекция")


class UpdatePasswordForm(forms.ModelForm):
    class Meta:
        model = Password
        fields = "note",


class AddPasswordForm(ChangePasswordCollectionForm):
    note = forms.CharField(
        label=_("Примета"),
        max_length=256
    )
    password1 = forms.CharField(
        label=_("Пароль"),
        widget=CustomPasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False
    )
    password2 = forms.CharField(
        label=_("Подтверждение пароля"),
        widget=CustomPasswordInput(attrs={"autocomplete": "new-password"}),
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


class AddPasswordsCollectionForm(forms.ModelForm):
    class Meta:
        model = PasswordsCollection
        fields = "name",
