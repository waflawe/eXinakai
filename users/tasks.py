import os
from typing import Any, Dict, Optional, Union

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from PIL.Image import Image
from PIL.Image import open as open_image

from users.services import get_upload_crop_path

User = get_user_model()


@shared_task
def send_reset_password_mail(
        subject_template_name: str,
        email_template_name: str,
        context: Dict[str, Any],
        from_email: Union[str, None],
        to_email: str,
        html_email_template_name: Optional[str] = None
) -> None:
    context['user'] = User.objects.get(pk=context['user'])

    PasswordResetForm().send_mail(
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name
    )


@shared_task
def make_center_crop(avatar_path: str) -> None:
    """ Таска для центрирования аватарки/вложения. """

    image_full_path = str(settings.BASE_DIR / settings.MEDIA_ROOT / avatar_path)
    image = open_image(os.path.join(image_full_path))
    new_crop_image_path = str(settings.BASE_DIR / settings.MEDIA_ROOT / get_upload_crop_path(avatar_path))
    _center_crop(image).save(new_crop_image_path)


def _center_crop(img: Image) -> Image:
    width, height = img.size
    if width / height == 1:
        return img

    left = (width - min(width, height)) / 2
    top = (height - min(width, height)) / 2
    right = (width + min(width, height)) / 2
    bottom = (height + min(width, height)) / 2

    return img.crop((int(left), int(top), int(right), int(bottom)))


def send_mail_with_subject_and_body_html(
        subject_template: str,
        body_template: str,
        recipient_mail: str,
        context: Optional[Dict] = None
) -> None:
    subject = render_to_string(subject_template)
    html_message = render_to_string(body_template, context)
    plain_message = strip_tags(html_message)

    send_mail(
        subject,
        plain_message,
        None,
        [recipient_mail],
        fail_silently=True,
        html_message=html_message
    )


@shared_task
def send_change_account_email_mail_message(email: str) -> None:
    send_mail_with_subject_and_body_html(
        'users/change_account_email_subject.html',
        'users/change_account_email_message.html',
        email,
        context={'email': email}
    )


@shared_task
def send_2fa_code_mail_message(email: str, code: int) -> None:
    send_mail_with_subject_and_body_html(
        "users/2fa_code_email_subject.html",
        "users/2fa_code_email_message.html",
        email,
        context={"code": code}
    )
