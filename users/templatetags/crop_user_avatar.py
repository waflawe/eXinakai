from django import template
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()
register = template.Library()


def get_upload_crop_path(path: str) -> str:
    """
    Function to get the path to a centered image from the path of the original image.

    :param path: The path to the original image.
    :return: Path to a centered image.
    """

    if path == settings.DEFAULT_USER_AVATAR_PATH:
        return path

    splitted_path = path.split("/")
    filename = splitted_path.pop()
    name, extension = filename.rsplit(".", 1)
    splitted_path.append(f"{name}_crop.{extension}")
    return "/".join(splitted_path)


def get_crop_user_avatar(user: User) -> str:
    return get_upload_crop_path(str(user.avatar))


register.filter("get_crop_user_avatar", get_crop_user_avatar)
