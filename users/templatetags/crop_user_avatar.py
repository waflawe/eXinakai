from django import template
from django.contrib.auth import get_user_model

from users.services import get_upload_crop_path

User = get_user_model()
register = template.Library()


def get_crop_user_avatar(user: User) -> str:
    return get_upload_crop_path(str(user.avatar))


register.filter("get_crop_user_avatar", get_crop_user_avatar)
