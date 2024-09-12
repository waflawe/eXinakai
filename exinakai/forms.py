from django import forms
from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.utils.translation import gettext_lazy as _

from exinakai.models import Password, PasswordsCollection

User = get_user_model()


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
        max_length=256,
        widget=forms.TextInput(attrs={"placeholder": "Примета пароля"})
    )
    password1 = forms.CharField(
        label=_("Пароль"),
        widget=forms.TextInput(attrs={"autocomplete": "new-password", "placeholder": "Пароль"}),
        strip=False
    )
    password2 = forms.CharField(
        label=_("Подтверждение пароля"),
        widget=forms.TextInput(attrs={"autocomplete": "new-password", "placeholder": "Повтор пороля"}),
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["name"].widget = forms.TextInput(attrs={"placeholder": "Название коллекции"})
