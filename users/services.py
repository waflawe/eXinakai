import secrets
import string
from typing import Mapping, NoReturn

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.contrib.sessions.backends.base import SessionBase
from django.http import Http404, HttpRequest
from django.shortcuts import get_object_or_404

from exinakai.models import Password
from exinakai.services import get_decrypted_password
from users.tasks import make_center_crop, send_change_account_email_mail_message

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


def make_2fa_authentication(session: SessionBase, user: User) -> str:
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    session["2fa_code"] = code
    session["2fa_code_user_id"] = user.pk
    session.set_expiry(60*5)
    return code


def validate_2fa_code(session: SessionBase, data: Mapping) -> User | None:
    if session.get("2fa_code", 0) == data.get("code", 1):
        pk = session["2fa_code_user_id"]
        session.flush()
        session.set_expiry(0)
        return get_object_or_404(User, pk=pk)
    return None


def process_avatar_and_email_if_updated(user: User, old_avatar_path: str, old_email: str) -> None:
    if str(user.avatar) != old_avatar_path:
        make_center_crop.delay(str(user.avatar))
    if user.email != old_email:
        send_change_account_email_mail_message.delay(user.email)
