from django.contrib.auth import get_user_model
from django.db.models.query import QuerySet
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers import (
    AuthTokenSerializer,
    CryptographicKeySerializer,
    DetailedCodeSerializer,
    DetailSerializer,
    PasswordsSerializer,
    TwoFactorAuthenticationCodeSerializer,
)
from exinakai.models import Password
from users.services import SetSessionCryptographicKeyService, make_2fa_authentication, validate_2fa_code
from users.tasks import send_2fa_code_mail_message

User = get_user_model()


class UserLoginAPIView(ObtainAuthToken):
    authentication_classes = ()

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if not user.is_2fa_enabled:
            token, created = Token.objects.get_or_create(user=user)
            data = AuthTokenSerializer(data={"token": token.key}).data
            return Response(data, status=status.HTTP_200_OK)
        code = make_2fa_authentication(request.session, user)
        send_2fa_code_mail_message.delay(user.email, code)
        data = DetailedCodeSerializer({
            "detail": "Код для прохождения 2FA отправлен вам на почту.",
            "code": "CODE_SENDED"
        }).data
        return Response(data, status=status.HTTP_202_ACCEPTED)


class UserTwoFactorAuthenticationAPIView(APIView):
    serializer_class = TwoFactorAuthenticationCodeSerializer
    authentication_classes = ()

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = validate_2fa_code(request.session, serializer.validated_data)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            data = AuthTokenSerializer({"token": token.key}).data
            return Response(data, status=status.HTTP_200_OK)
        data = DetailedCodeSerializer({
            "detail": "Код 2FA неверен.",
            "code": "INVALID_CODE"
        }).data
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


class ActivateCryptographicKeyAPIView(APIView):
    serializer_class = CryptographicKeySerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if SetSessionCryptographicKeyService.is_key_valid(request.user, serializer.validated_data["cryptographic_key"]):
            SetSessionCryptographicKeyService.set_key(request.session, serializer.validated_data["cryptographic_key"])
            data = DetailSerializer({"detail": "Ключ шифрования активирован."}).data
            return Response(data, status=status.HTTP_200_OK)
        data = DetailedCodeSerializer({
            "detail": "Неверный ключ шифрования.",
            "code": "INVALID_KEY"
        }).data
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request: Request, *args, **kwargs) -> Response:
        token = Token.objects.get(user=request.user)
        token.delete()
        data = DetailSerializer({"detail": "Выход из системы совершен."}).data
        return Response(data, status=status.HTTP_200_OK)


class PasswordViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet
):
    lookup_url_kwarg = "pk"
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = PasswordsSerializer

    def get_queryset(self) -> QuerySet:
        return Password.storable.filter(owner=self.request.user)
