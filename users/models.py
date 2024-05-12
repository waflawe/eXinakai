from typing import Optional

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.validators import MinLengthValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


def get_uploaded_avatar_path(instance: 'ExinakaiUser', filename: str) -> str:
    return f"{settings.CUSTOM_USER_AVATARS_DIR}/{filename}"


class ExinakaiUserManager(BaseUserManager):
    def create_user(self, username: str, email: str, avatar: str, timezone: str, password: Optional[str] = None) \
            -> 'ExinakaiUser':
        if not email:
            raise ValueError("Users must have an email address")

        user: 'ExinakaiUser' = self.model(
            username=username,
            email=self.normalize_email(email),
            avatar=avatar,
            timezone=timezone
        )

        user.set_password(password)
        user.save(using=self._db)
        return user


class ExinakaiUser(AbstractBaseUser):
    username = models.CharField(
        verbose_name=_("Имя пользователя"),
        max_length=16,
        unique=True,
        help_text=_("Не более 16 символов, не менее 5. Буквы, цифры, @/./+/-/_."),
        validators=[UnicodeUsernameValidator(), MinLengthValidator(5)],
        error_messages={
            "unique": _("Пользователь с таким именем уже существует."),
        }
    )
    email = models.EmailField(
        verbose_name=_('Почта'),
        unique=True,
        help_text=_("Электронная почта для сброса пароля.")
    )
    avatar = models.ImageField(
        verbose_name=_("Аватарка"),
        upload_to=get_uploaded_avatar_path,
        default=settings.DEFAULT_USER_AVATAR_PATH
    )
    timezone = models.CharField(
        verbose_name=_("Временная зона"),
        max_length=64,
        default=settings.DEFAULT_USER_TIMEZONE
    )
    date_joined = models.DateTimeField(verbose_name=_('Время регистрации'), auto_now_add=True)
    is_active = models.BooleanField(verbose_name=_('Активен ли'), default=True)
    is_2fa_enabled = models.BooleanField(verbose_name=_('Включена ли 2FA'), default=False)

    USERNAME_FIELD = "username"
    objects = ExinakaiUserManager()

    class Meta:
        verbose_name = _("Пользователь")
        verbose_name_plural = _("Пользователи")

        db_table = "exinakai_user"

    def __str__(self):
        return f"{self.username}"
