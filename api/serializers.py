from datetime import datetime
from typing import Dict, NoReturn, Optional, Type

import pytz
from dj_rest_auth.serializers import PasswordResetSerializer as PasswordResetSerializerCore
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from exinakai.models import Password, PasswordsCollection
from exinakai.services import get_decrypted_password
from users.forms import PasswordResetForm

User = get_user_model()


def datetime_to_timezone(dt: datetime, timezone: str, attribute_name: Optional[str] = "time_added") -> Dict:
    """Приведение datetime объекта к временной зоне."""

    dt = pytz.timezone(timezone).localize(datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second))
    return {
        attribute_name: (dt + dt.utcoffset()).strftime("%H:%M %d/%m/%Y"),
        "timezone": timezone
    }


class DetailSerializer(serializers.Serializer):
    detail = serializers.CharField()


class DetailedCodeSerializer(DetailSerializer):
    code = serializers.CharField(max_length=32)


class AuthTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class TwoFactorAuthenticationCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)


class CryptographicKeySerializer(serializers.Serializer):
    cryptographic_key = serializers.CharField(max_length=512)


class PasswordResetSerializer(PasswordResetSerializerCore):
    def get_email_options(self) -> Dict:
        return {
            "subject_template_name": 'users/mails/password_reset_subject_message.html',
            "email_template_name": 'users/mails/password_reset_email_message.html'
        }

    @property
    def password_reset_form_class(self) -> Type[PasswordResetForm]:
        return PasswordResetForm


class SettingsSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    avatar = serializers.ImageField(required=False)
    is_2fa_enabled = serializers.BooleanField(required=False)

    class Meta:
        model = User
        fields = "username", "email", "avatar", "timezone", "is_2fa_enabled"
        read_only_fields = ("username",)

    def validate_timezone(self, timezone: str) -> str | NoReturn:
        if timezone not in pytz.common_timezones:
            raise ValidationError("Переданная временная зона не валидна.", code="INVALID_TIMEZONE")
        return timezone


class PasswordsSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    collection = serializers.SerializerMethodField()
    time_added = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Password
        fields = "id", "note", "password", "collection", "time_added"

    def get_password(self, password: Password) -> str:
        return get_decrypted_password(self.context["request"].session["cryptographic_key"], password.password)

    def get_collection(self, password: Password) -> str:
        return password.collection.name

    def get_time_added(self, password: Password) -> Dict:
        return datetime_to_timezone(password.time_added, self.context["request"].user.timezone)


class RandomPasswordSerializer(serializers.Serializer):
    password = serializers.CharField()


class PasswordsCollectionSerializer(serializers.ModelSerializer):
    time_created = serializers.SerializerMethodField()

    class Meta:
        model = PasswordsCollection
        fields = "id", "owner", "name", "time_created"
        read_only_fields = "id", "time_created"
        extra_kwargs = {'owner': {'required': False}}

    def get_time_created(self, collection: PasswordsCollection) -> Dict:
        return datetime_to_timezone(collection.time_created, self.context["request"].user.timezone)
