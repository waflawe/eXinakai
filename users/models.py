import pytz
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


def get_uploaded_avatar_path(instance: 'ExinakaiUser', filename: str) -> str:
    return f"{settings.CUSTOM_USER_AVATARS_DIR}/{instance.pk}.{filename.split('.')[-1]}"


class ExinakaiUser(AbstractBaseUser):
    username = models.CharField(
        verbose_name=_("Имя пользователя"),
        max_length=64,
        unique=True,
        help_text=_("Обязателен. Не более 64 символов. Буквы, цифры, @/./+/-/_."),
        validators=[UnicodeUsernameValidator()],
        error_messages={
            "unique": _("Пользователь с таким именем уже существует."),
        }
    )
    email = models.EmailField(verbose_name=_('Почта'), unique=True)
    date_joined = models.DateTimeField(verbose_name=_('Время регистрации'), auto_now_add=True)
    is_active = models.BooleanField(verbose_name=_('Активен ли'), default=True)
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

    class Meta:
        verbose_name = _("Пользователь")
        verbose_name_plural = _("Пользователи")

        db_table = "user"

    def __str__(self):
        return f"{self.username}"

    def clean(self):
        if self.timezone not in pytz.common_timezones:
            raise ValidationError({"timezone": _("Неверная временная зона.")})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)
