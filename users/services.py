from cryptography.fernet import Fernet
from django.contrib.sessions.backends.base import SessionBase
from django.contrib.auth.mixins import AccessMixin


class CryptographicKeyEmptyRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if request.session.get("cryptographic_key", False):
            self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class GenerateCryptographicKeyService(object):
    @staticmethod
    def generate():
        return Fernet.generate_key().decode("utf-8")


class SetSessionCryptographicKey(object):
    @staticmethod
    def set_key(session: SessionBase, cryptographic_key: str) -> None:
        session["cryptographic_key"] = cryptographic_key
        return
