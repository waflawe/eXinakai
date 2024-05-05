from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.contrib.sessions.backends.base import SessionBase
from django.http import HttpRequest

from exinakai.models import Password
from exinakai.services import AllPasswordsService

User = get_user_model()


def get_upload_crop_path(path: str) -> str:
    """ Функция для получения пути к центрированному изображению по пути исходного. """

    if path == settings.DEFAULT_USER_AVATAR_PATH:
        return path

    splitted_path = path.split("/")
    filename = splitted_path.pop()
    name, extension = filename.split(".")
    splitted_path.append(f"{name}_crop.{extension}")
    return "/".join(splitted_path)


class CryptographicKeyEmptyRequiredMixin(AccessMixin):
    def dispatch(self, request: HttpRequest, *args, **kwargs):
        if request.session.get("cryptographic_key", False):
            self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class GenerateCryptographicKeyService(object):
    @staticmethod
    def generate() -> str:
        return Fernet.generate_key().decode("utf-8")


class SetSessionCryptographicKeyService(object):
    @staticmethod
    def is_key_valid(user: User, cryptographic_key: str) -> bool:
        password = Password.storable.filter(owner=user).only("password").first()
        if password:
            decrypted_password = AllPasswordsService.get_decrypted_password(cryptographic_key, password.password)
            if decrypted_password == settings.INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE:
                return False
        return True

    @staticmethod
    def set_key(session: SessionBase, cryptographic_key: str) -> None:
        session["cryptographic_key"] = cryptographic_key
        return