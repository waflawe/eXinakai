from rest_framework import permissions
from rest_framework.request import Request


class IsUserCryptographicKeyValid(permissions.BasePermission):
    def has_permission(self, request: Request, view) -> bool:
        if request.session.get("cryptographic_key", None):
            return True
        return False
