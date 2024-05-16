from rest_framework import serializers
from dj_rest_auth.serializers import PasswordResetSerializer as PasswordResetSerializerCore
from django.contrib.auth import get_user_model
from datetime import datetime
from typing import Dict, Optional
import pytz

from exinakai.models import Password
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
    def password_reset_form_class(self):
        return PasswordResetForm


class PasswordsSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    time_added = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Password
        fields = "id", "note", "password", "time_added"

    def get_password(self, password: Password) -> str:
        return get_decrypted_password(self.context["request"].session["cryptographic_key"], password.password)

    def get_time_added(self, password: Password) -> Dict:
        return datetime_to_timezone(password.time_added, self.context["request"].user.timezone)
