from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin

from exinakai.models import Password

User = get_user_model()


class CryptographicKeyRequiredMixin(AccessMixin):
    permission_denied_message = "Активация ключа шифрования необходима"

    def dispatch(self, request, *args, **kwargs):
        if not request.session.get("cryptographic_key", False):
            self.handle_no_permission()
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
