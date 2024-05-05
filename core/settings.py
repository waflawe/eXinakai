"""
███████╗██╗░░██╗██╗███╗░░██╗░█████╗░██╗░░██╗░█████╗░██╗
██╔════╝╚██╗██╔╝██║████╗░██║██╔══██╗██║░██╔╝██╔══██╗██║
█████╗░░░╚███╔╝░██║██╔██╗██║███████║█████═╝░███████║██║
██╔══╝░░░██╔██╗░██║██║╚████║██╔══██║██╔═██╗░██╔══██║██║
███████╗██╔╝╚██╗██║██║░╚███║██║░░██║██║░╚██╗██║░░██║██║
╚══════╝╚═╝░░╚═╝╚═╝╚═╝░░╚══╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝
"""

import os
from pathlib import Path

from environ import Env

BASE_DIR = Path(__file__).resolve().parent.parent

env = Env()
Env.read_env(os.path.join(BASE_DIR, '.env'))

SECRET_KEY = env("SECRET_KEY")
DEBUG = int(env("DEBUG"))
ALLOWED_HOSTS = env("ALLOWED_HOSTS").split(", ")


# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    "exinakai.apps.ExinakaiConfig",
    "users.apps.UsersConfig"
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "templates/")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                "django.template.context_processors.media",
            ],
            'libraries': {
                'users_tags': 'users.templatetags.crop_user_avatar',
            },
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DATABASE_NAME"),
        "USER": env("DATABASE_USER"),
        "PASSWORD": env("DATABASE_PASSWORD"),
        "HOST": env("DATABASE_HOST"),
        "PORT": env("DATABASE_PORT"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTH_USER_MODEL = "users.ExinakaiUser"

LOGGING = {
    "version": 1,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler"
        }
    },
    "loggers": {
        "django.db.backends": {
            "handlers": ["console"],
            "level": env("DJANGO_LOG_LEVEL", default="DEBUG")
        }
    },
}

# RUNTIME
DEFAULT_USER_TIMEZONE = "Europe/London"
CUSTOM_USER_AVATARS_DIR = "avatars"
DEFAULT_USER_AVATAR_PATH = "default-user-icon.jpg"
INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE = "INVALID_KEY"

# EMAIL
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')

# CELERY
CELERY_BROKER_URL = env("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND")

# SESSIONS
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = "static"
MEDIA_URL = "/media/"
MEDIA_ROOT = "media"

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
