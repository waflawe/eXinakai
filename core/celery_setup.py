import os

from celery import Celery
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery(
    'eXinakai',
    include=['exinakai.tasks', 'users.tasks'],
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)
app.conf.task_routes = {
    "users.tasks.send_reset_password_mail": {"queue": "main_queue"},
}
app.autodiscover_tasks()
