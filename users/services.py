from cryptography.fernet import Fernet
from django.contrib.auth.mixins import AccessMixin
from django.contrib.sessions.backends.base import SessionBase
from django.http import HttpRequest
from django.conf import settings


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


class SetSessionCryptographicKey(object):
    @staticmethod
    def set_key(session: SessionBase, cryptographic_key: str) -> None:
        session["cryptographic_key"] = cryptographic_key
        return
