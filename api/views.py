from dj_rest_auth.serializers import (
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
)
from dj_rest_auth.views import PasswordChangeView as PasswordChangeViewCore
from dj_rest_auth.views import PasswordResetConfirmView as PasswordResetConfirmViewCore
from dj_rest_auth.views import PasswordResetView as PasswordResetViewCore
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models.query import QuerySet
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer as AuthTokenSerializerCore
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsUserCanEditCollection, IsUserCryptographicKeyValid
from api.serializers import (
    AuthTokenSerializer,
    ChangePasswordCollectionSerializer,
    CryptographicKeySerializer,
    DetailedCodeSerializer,
    DetailSerializer,
    PasswordsCollectionSerializer,
    PasswordsSerializer,
    RandomPasswordSerializer,
    SettingsSerializer,
    TwoFactorAuthenticationCodeSerializer,
)
from exinakai.services import (
    change_password_collection,
    encrypt_and_save_password,
    generate_random_password_from_request_data,
    get_all_passwords,
    get_user_collections,
)
from users.services import (
    is_cryptographic_key_valid,
    make_2fa_authentication,
    process_avatar_and_email_if_updated,
    validate_2fa_code,
)
from users.tasks import send_2fa_code_mail_message, send_change_account_password_mail_message

User = get_user_model()


#########
# USERS #
#########


class TokenLoginAPIMixin(object):
    def get_response(self, token: Token) -> Response:
        data = AuthTokenSerializer({"token": token.key}).data
        return Response(data, status=status.HTTP_200_OK)

    def login(self, user: User) -> Response:
        token, created = Token.objects.get_or_create(user=user)
        return self.get_response(token)


class UserLoginAPIView(TokenLoginAPIMixin, ObtainAuthToken):
    """Account login by token."""

    authentication_classes = ()

    @extend_schema(request=AuthTokenSerializerCore, responses={
        status.HTTP_200_OK: AuthTokenSerializer,
        status.HTTP_202_ACCEPTED: DetailedCodeSerializer,
        status.HTTP_400_BAD_REQUEST: None
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if not user.is_2fa_enabled:
            return self.login(user)
        code = make_2fa_authentication(request.session, user)
        send_2fa_code_mail_message.delay(user.email, code)
        data = DetailedCodeSerializer({
            "detail": "Код для прохождения 2FA отправлен вам на почту.",
            "code": "CODE_SENDED"
        }).data
        return Response(data, status=status.HTTP_202_ACCEPTED)


class UserTwoFactorAuthenticationAPIView(TokenLoginAPIMixin, APIView):
    """Log in to your account with two-step authentication enabled."""

    serializer_class = TwoFactorAuthenticationCodeSerializer
    authentication_classes = ()

    @extend_schema(request=TwoFactorAuthenticationCodeSerializer, responses={
        status.HTTP_200_OK: AuthTokenSerializer,
        status.HTTP_400_BAD_REQUEST: DetailedCodeSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = validate_2fa_code(request.session, serializer.validated_data)
        if user:
            return self.login(user)
        data = DetailedCodeSerializer({
            "detail": "Код 2FA неверен.",
            "code": "INVALID_CODE"
        }).data
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


class ActivateCryptographicKeyAPIView(APIView):
    """Activation of the encryption key."""

    serializer_class = CryptographicKeySerializer
    permission_classes = (permissions.IsAuthenticated,)

    @extend_schema(request=CryptographicKeySerializer, responses={
        status.HTTP_200_OK: DetailSerializer,
        status.HTTP_400_BAD_REQUEST: DetailedCodeSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        key = serializer.validated_data["cryptographic_key"]
        if not is_cryptographic_key_valid(request.user, key):
            data = DetailedCodeSerializer({
                "detail": "Неверный ключ шифрования.",
                "code": "INVALID_KEY"
            }).data
            return Response(data, status=status.HTTP_400_BAD_REQUEST)
        request.session["cryptographic_key"] = key
        data = DetailSerializer({"detail": "Ключ шифрования активирован."}).data
        return Response(data, status=status.HTTP_200_OK)


class UserLogoutAPIView(APIView):
    """Logging out of the account."""

    permission_classes = (permissions.IsAuthenticated,)

    @extend_schema(request=None, responses={
        status.HTTP_200_OK: DetailSerializer,
        status.HTTP_401_UNAUTHORIZED: DetailSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        token = Token.objects.get(user=request.user)
        token.delete()
        request.session.flush()
        data = DetailSerializer({"detail": "Выход из системы совершен."}).data
        return Response(data, status=status.HTTP_200_OK)


class PasswordResetAPIView(PasswordResetViewCore):
    """Account password reset."""

    @extend_schema(request=PasswordResetSerializer, responses={
        status.HTTP_202_ACCEPTED: DetailedCodeSerializer,
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        super().post(request, *args, **kwargs)
        data = DetailedCodeSerializer({
            "detail": "Сообщение для сброса пароля отправлено на почту.",
            "code": "MAIL_SENDED"
        }).data
        return Response(data, status=status.HTTP_202_ACCEPTED)


class SuccessChangePasswordResponseAPIMixin(object):
    def get_response(self) -> Response:
        data = DetailSerializer({"detail": "Пароль аккаунта изменен успешно."}).data
        return Response(data, status=status.HTTP_200_OK)


class PasswordResetConfirmAPIView(SuccessChangePasswordResponseAPIMixin, PasswordResetConfirmViewCore):
    """Account password reset confirmation."""

    @extend_schema(request=PasswordResetConfirmSerializer, responses={
        status.HTTP_200_OK: DetailSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        super().post(request, *args, **kwargs)
        return self.get_response()


class PasswordChangeAPIView(SuccessChangePasswordResponseAPIMixin, PasswordChangeViewCore):
    """Changing the account password."""

    @extend_schema(request=PasswordChangeSerializer, responses={
        status.HTTP_200_OK: DetailSerializer,
        status.HTTP_400_BAD_REQUEST: DetailSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        super().post(request, *args, **kwargs)
        send_change_account_password_mail_message.delay(request.user.email, None)
        return self.get_response()


class UpdateSettingsAPIView(APIView):
    """View and change account settings."""

    serializer_class = SettingsSerializer
    permission_classes = (permissions.IsAuthenticated,)

    @extend_schema(responses={
        status.HTTP_200_OK: SettingsSerializer
    })
    def get(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(request=SettingsSerializer, responses={
        status.HTTP_200_OK: DetailSerializer,
        status.HTTP_400_BAD_REQUEST: DetailSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        old_avatar_path, old_email = str(request.user.avatar), request.user.email
        serializer = self.serializer_class(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.validated_data["is_2fa_enabled"] = request.data.get("is_2fa_enabled", request.user.is_2fa_enabled)
        serializer.save()
        process_avatar_and_email_if_updated(request.user, old_avatar_path, old_email)
        data = DetailSerializer({"detail": "Обновлено успешно."}).data
        return Response(data, status=status.HTTP_200_OK)


############
# EXINAKAI #
############


@extend_schema_view(
    get=extend_schema(responses={
        status.HTTP_200_OK: PasswordsSerializer
    })
)
class PasswordViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet
):
    """View all saved passwords."""

    lookup_url_kwarg = "pk"
    permission_classes = (permissions.IsAuthenticated, IsUserCryptographicKeyValid)
    serializer_class = PasswordsSerializer

    def get_queryset(self) -> QuerySet:
        return get_all_passwords(self.request.user, self.request.GET.get("search", None), decrypt=False)

    @extend_schema(request=PasswordsSerializer, responses={
        status.HTTP_201_CREATED: DetailSerializer,
        status.HTTP_400_BAD_REQUEST: DetailSerializer
    })
    def create(self, request: Request, *args, **kwargs) -> Response:
        """Saves the new password to the database."""

        super().create(request, *args, **kwargs)
        data = DetailSerializer({"detail": "Пароль добавлен успешно."}).data
        return Response(data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer: PasswordsSerializer) -> None:
        cryptographic_key = self.request.session["cryptographic_key"]
        password, note = serializer.initial_data["password"], serializer.initial_data["note"]
        encrypt_and_save_password(self.request.user, cryptographic_key, password, note)

    @extend_schema(responses={
        status.HTTP_204_NO_CONTENT: DetailSerializer,
        status.HTTP_404_NOT_FOUND: DetailSerializer
    })
    def destroy(self, request: Request, *args, **kwargs) -> Response:
        """Deleting a password from the database."""

        super().destroy(request, *args, **kwargs)
        data = DetailSerializer({"detail": "Пароль удален успешно."}).data
        return Response(data, status=status.HTTP_204_NO_CONTENT)


class GeneratePasswordAPIView(APIView):
    """Random password generation."""

    serializer_class = RandomPasswordSerializer
    permission_classes = (permissions.IsAuthenticated,)

    @extend_schema(responses={
        status.HTTP_200_OK: RandomPasswordSerializer
    })
    def get(self, request: Request) -> Response:
        password, *_ = generate_random_password_from_request_data(request.query_params)
        data = self.serializer_class({"password": password}).data
        return Response(data, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(responses={
        status.HTTP_200_OK: PasswordsCollectionSerializer
    })
)
class PasswordsCollectionViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet
):
    """View all passwords collections."""

    lookup_url_kwarg = "pk"
    permission_classes = (permissions.IsAuthenticated, IsUserCryptographicKeyValid, IsUserCanEditCollection)
    serializer_class = PasswordsCollectionSerializer

    def get_queryset(self) -> QuerySet:
        return get_user_collections(self.request.user)

    @extend_schema(request=PasswordsCollectionSerializer, responses={
        status.HTTP_201_CREATED: DetailSerializer,
        status.HTTP_400_BAD_REQUEST: DetailSerializer
    })
    def create(self, request: Request, *args, **kwargs) -> Response:
        """Saves the new passwords collection to the database."""

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(owner=request.user)
        data = DetailSerializer({"detail": "Коллекция добавлена успешно."}).data
        return Response(data, status=status.HTTP_201_CREATED)

    @extend_schema(responses={
        status.HTTP_204_NO_CONTENT: DetailSerializer,
        status.HTTP_404_NOT_FOUND: DetailSerializer
    })
    def destroy(self, request: Request, *args, **kwargs) -> Response:
        """Deleting a passwords collection from the database."""

        if (collection := self.get_object()).name == settings.DEFAULT_PASSWORDS_COLLECTION_NAME:
            data = DetailSerializer({"detail": "Эту коллекцию нельзя удалить."}).data
            return Response(data, status=status.HTTP_403_FORBIDDEN)
        default_collection = self.get_queryset().filter(name=settings.DEFAULT_PASSWORDS_COLLECTION_NAME).first()
        passwords = collection.passwords.all()
        passwords.update(collection=default_collection)
        for password in passwords:
            default_collection.passwords.add(password)
        collection.delete()
        key = (f"{self.request.user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
               f"{settings.ALL_USER_PASSWORDS_CACHE_NAME}")
        cache.delete(key=key)
        key = (f"{self.request.user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
               f"{settings.ALL_USER_PASSWORDS_COLLECTIONS_CACHE_NAME}")
        cache.delete(key=key)
        data = DetailSerializer({"detail": "Коллекция удалена успешно."}).data
        return Response(data, status=status.HTTP_204_NO_CONTENT)


class ChangePasswordCollectionAPIView(APIView):
    serializer_class = ChangePasswordCollectionSerializer
    permission_classes = (permissions.IsAuthenticated, IsUserCryptographicKeyValid)

    @extend_schema(responses={
        status.HTTP_200_OK: DetailSerializer,
        status.HTTP_403_FORBIDDEN: DetailSerializer,
        status.HTTP_404_NOT_FOUND: DetailSerializer
    })
    def post(self, request: Request, *args, **kwargs) -> Response:
        change_password_collection(
            request.user,
            request.data,
            request.data.get("collection", 0)
        )
        data = DetailSerializer({"detail": "Коллекция пароля изменена успешно."}).data
        return Response(data, status=status.HTTP_200_OK)
