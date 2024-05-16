from typing import NamedTuple, Optional, Tuple, Mapping, KeysView

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db.models.query import QuerySet
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls.base import reverse

from exinakai.models import Password
from exinakai.passgen import Options, generate_random_password

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


def get_all_passwords(
        user: User,
        search: Optional[bool] = None,
        *,
        to_tuple: Optional[bool] = True,
        cryptographic_key: Optional[str] = None
) -> Tuple[PasswordRender, ...] | QuerySet:
    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    queryset = cache.get(key=key)

    if not queryset:
        queryset = Password.storable.filter(owner=user)
        cache.set(key, queryset)
    if search:
        queryset = queryset.filter(note__icontains=search)

    if to_tuple:
        return tuple(
            PasswordRender(password, get_decrypted_password(cryptographic_key, password.password))
            for password in queryset
        )
    return queryset


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


def generate_random_password_from_request(request_data: Mapping) -> tuple[str, KeysView, int]:
    default_characters = {"l": "lowercase", "u": "uppercase", "d": "digits", "p": "punctuation"}
    submited_sumbols = request_data.keys()
    characters = "".join(alias for alias, sumbols in default_characters.items() if sumbols in submited_sumbols)

    length: str = request_data.get("length", "0")
    clean_length: int = length if length.isnumeric() and 8 <= int(length) <= 32 else 16

    return (
        generate_random_password(Options(clean_length, characters or "ludp")),
        submited_sumbols,
        clean_length
    )
