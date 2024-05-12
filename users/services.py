import secrets
import string
from typing import NoReturn

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.contrib.sessions.backends.base import SessionBase
from django.http import Http404, HttpRequest

from exinakai.models import Password
from exinakai.services import get_decrypted_password

User = get_user_model()


def check_is_redirect_url_valid(request: HttpRequest, *valid_urls: str) -> None | NoReturn:
    is_requests_hosts_equal = request.get_host() in request.META.get("HTTP_REFERER", "")
    referer = (request.META.get("HTTP_REFERER", "")
               .replace(request.get_host(), "")
               .replace("http://", "")
               .replace("https://", ""))
    if not (is_requests_hosts_equal and any(
        url in referer for url in valid_urls
    )):
        raise Http404
    return None


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


def generate_cryptographic_key() -> str:
    return Fernet.generate_key().decode("utf-8")


class SetSessionCryptographicKeyService(object):
    @staticmethod
    def is_key_valid(user: User, cryptographic_key: str) -> bool:
        password = Password.storable.filter(owner=user).only("password").first()
        if password:
            decrypted_password = get_decrypted_password(cryptographic_key, password.password)
            if decrypted_password == settings.INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE:
                return False
        return True

    @staticmethod
    def set_key(session: SessionBase, cryptographic_key: str) -> None:
        session["cryptographic_key"] = cryptographic_key
        return


def generate_2fa_code() -> str:
    return "".join(secrets.choice(string.digits) for i in range(6))
