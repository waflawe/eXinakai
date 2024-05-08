from typing import NamedTuple, Tuple

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls.base import reverse

from exinakai.models import Password

User = get_user_model()


class CryptographicKeyRequiredMixin(AccessMixin):
    def handle_no_permission(self) -> HttpResponseRedirect:
        return redirect(reverse("accounts:activate-cryptographic-key"))

    def dispatch(self, request: HttpRequest, *args, **kwargs):
        if not request.session.get("cryptographic_key", False):
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class PasswordRender(NamedTuple):
    password: Password
    decrypted_password: str


def encrypt_and_save_password(user: User, cryptographic_key: str, password: str, note: str) -> None:
    fernet = Fernet(bytes(cryptographic_key, "utf-8"))
    encrypted_password = fernet.encrypt(bytes(password, "utf-8")).decode("utf-8")
    Password.storable.create(owner=user, note=note, password=encrypted_password)
    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    cache.delete(key=key)
    return


def get_decrypted_password(cryptographic_key: str, password: str) -> str:
    try:
        fernet = Fernet(bytes(cryptographic_key, "utf-8"))
    except ValueError:
        return settings.INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE
    return fernet.decrypt(bytes(password, "utf-8")).decode("utf-8")


def get_all_passwords(cryptographic_key: str, user: User, search: str | None) -> Tuple[PasswordRender, ...]:
    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    queryset = cache.get(key=key)

    if not queryset:
        queryset = Password.storable.filter(owner=user)
        cache.set(key, queryset)
    if search:
        queryset = queryset.filter(note__icontains=search)

    return tuple(
        PasswordRender(password, get_decrypted_password(cryptographic_key, password.password))
        for password in queryset
    )


def get_password(**kwargs) -> Password:
    return Password.storable.get(**kwargs)


def check_user_perms_to_edit_password(user: User, **kwargs) -> Password:
    password = get_password(**kwargs)
    if not password.owner == user:
        raise PermissionDenied("Вы не можете редактировать этот пароль.")
    return password


def delete_password(user: User, **kwargs) -> None:
    password = check_user_perms_to_edit_password(user, **kwargs)
    password.delete()
    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    cache.delete(key=key)
    return
