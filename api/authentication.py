import pytz
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from api.serializers import DetailedCodeSerializer


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key: str):
        user, token = super().authenticate_credentials(key)

        utc_now = timezone.now()
        utc_now = utc_now.replace(tzinfo=pytz.utc)

        if token.created < utc_now - settings.TOKEN_TTL:
            data = DetailedCodeSerializer({
                "detail": "Токен уже не действителен.",
                "code": "TOKEN_EXPIRED"
            }).data
            token.delete()
            raise AuthenticationFailed(data)
        return user, token
