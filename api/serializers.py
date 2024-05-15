from rest_framework import serializers

from exinakai.models import Password
from exinakai.services import get_decrypted_password


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


class PasswordsSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    time_added = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Password
        fields = "id", "note", "password", "time_added"

    def get_password(self, password: Password) -> str:
        return get_decrypted_password(self.context["request"].session["cryptographic_key"], password.password)

    def get_time_added(self, password: Password) -> str:
        return str(password.time_added)
