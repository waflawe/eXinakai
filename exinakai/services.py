from typing import NamedTuple, Tuple

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
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


class EncryptPasswordService(object):
    @staticmethod
    def encrypt_and_insert(user: User, cryptographic_key: str, password: str, note: str) -> None:
        encrypted_password = EncryptPasswordService.encrypt(cryptographic_key, password)
        return EncryptPasswordService.insert(user, encrypted_password, note)

    @staticmethod
    def encrypt(cryptographic_key: str, password: str) -> str:
        fernet = Fernet(bytes(cryptographic_key, "utf-8"))
        return fernet.encrypt(bytes(password, "utf-8")).decode("utf-8")

    @staticmethod
    def insert(user: User, password: str, note: str) -> None:
        Password.storable.create(owner=user, note=note, password=password)
        return


class PasswordRender(NamedTuple):
    password: Password
    decrypted_password: str


class AllPasswordsService(object):
    @staticmethod
    def get_all_passwords(cryptographic_key: str, user: User) -> Tuple[PasswordRender, ...]:
        return tuple(
            PasswordRender(password, AllPasswordsService.get_decrypted_password(cryptographic_key, password.password))
            for password in Password.storable.filter(owner=user)
        )

    @staticmethod
    def get_decrypted_password(cryptographic_key: str, password: str) -> str:
        try:
            fernet = Fernet(bytes(cryptographic_key, "utf-8"))
        except ValueError:
            return settings.INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE
        return fernet.decrypt(bytes(password, "utf-8")).decode("utf-8")
