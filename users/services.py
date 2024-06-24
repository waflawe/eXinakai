import secrets
import string
from typing import Mapping, NoReturn, Optional

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


class CryptographicKeyEmptyRequiredMixin(AccessMixin):
    """Mixin to verify that the user has an encryption key attached."""

    def dispatch(self, request: HttpRequest, *args, **kwargs):
        if request.session.get("cryptographic_key", False):
            self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class SetSessionCryptographicKeyService(object):
    @staticmethod
    def is_key_valid(user: User, cryptographic_key: str) -> bool:
        """
        Checking the encryption key for validity.

        :param user: The user to whom the key is checked for validity.
        :param cryptographic_key: Key to check for validity.
        :return: Is the key valid.
        """

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


def check_is_redirect_url_valid(request: HttpRequest, *valid_urls: str, raise_exception: Optional[bool] = True) \
        -> None | NoReturn:
    """
    A service to check if a request redirect matches one of the collection.

    :param request: django.http.request.HttpRequest object.
    :param valid_urls: A set of valid referers.
    :param raise_exception: Flag to indicate whether an error should be raised if the redirected url is invalid.
    :return: None if redirect url valid else Http404 error.
    """

    is_requests_hosts_equal = request.get_host() in request.META.get("HTTP_REFERER", "")
    referer = (request.META.get("HTTP_REFERER", "")
               .replace(request.get_host(), "")
               .replace("http://", "")
               .replace("https://", ""))
    if not (is_requests_hosts_equal and any(
        url in referer for url in valid_urls
    )):
        if raise_exception:
            raise Http404
        return False
    return True


def generate_cryptographic_key() -> str:
    return Fernet.generate_key().decode("utf-8")


def make_2fa_authentication(session: SessionBase, user: User) -> str:
    """
    A service for creating and assigning a 2FA code to a user.

    :param session: Session undergoing verification.
    :param user: Target user to log in.
    :return: Generated code for 2FA.
    """

    code = "".join(secrets.choice(string.digits) for _ in range(6))
    session["2fa_code"] = code
    session["2fa_code_user_id"] = user.pk
    session.set_expiry(60*5)
    return code


def validate_2fa_code(session: SessionBase, data: Mapping) -> User | None:
    """
    Service to check 2FA code for validity.

    :param session: Session undergoing verification
    :param data: Received dataset from a user with the code 2FA.
    :return: User for login or None if the 2FA code is invalid.
    """

    if session.get("2fa_code", 0) == data.get("code", 1):
        pk = session["2fa_code_user_id"]
        session.flush()
        session.set_expiry(0)
        return get_object_or_404(User, pk=pk)
    return None


def process_avatar_and_email_if_updated(user: User, old_avatar_path: str, old_email: str) -> None:
    """
    Service to recall the corresponding tasks for avatar and mail if they have been changed.

    :param user: The user who changed the settings.
    :param old_avatar_path: Path to the user's old avatar.
    :param old_email: User's old email.
    :return: None.
    """

    if str(user.avatar) != old_avatar_path:
        make_center_crop.delay(str(user.avatar))
    if user.email != old_email:
        send_change_account_email_mail_message.delay(user.email)
    return
