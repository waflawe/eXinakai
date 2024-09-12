from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _

User = get_user_model()


class PasswordsCollection(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name=_("Создатель"), related_name="Создатель")
    name = models.CharField(max_length=128, verbose_name=_("Название"))
    time_created = models.DateTimeField(auto_now_add=True, verbose_name=_("Время создания"))

    class Meta:
        verbose_name = _("Коллекция")
        verbose_name_plural = _("Коллекции")
        get_latest_by = ordering = "time_created",

        db_table = "passwords_collection"
        db_table_comment = "Созданные пользователями коллекции паролей."

    def __str__(self):
        return f"{self.name}"


class StorablePasswordsManager(models.Manager):
    pass


class Password(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name=_("Владелец"), related_name="Владелец")
    note = models.CharField(max_length=256, verbose_name=_("Примета"))
    collection = models.ForeignKey(
        PasswordsCollection,
        on_delete=models.CASCADE,
        verbose_name=_("Коллекция"),
        related_name="Коллекция",
        null=True
    )
    password = models.CharField(max_length=512, verbose_name=_("Пароль"))
    time_added = models.DateTimeField(auto_now_add=True, verbose_name=_("Время добавления"))

    storable = StorablePasswordsManager()

    class Meta:
        verbose_name = _("Пароль")
        verbose_name_plural = _("Пароли")

        base_manager_name = "storable"
        default_manager_name = "storable"
        get_latest_by = ordering = "-time_added",
        indexes = [
            models.Index(fields=["note"])
        ]

        db_table = "passwords"
        db_table_comment = "Сохраненные пользователем пароли."

    def __str__(self):
        return f"{self.note}"
