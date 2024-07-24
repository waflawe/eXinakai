import typing

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from pytest_factoryboy import register
from rest_framework.test import APIClient

from tests.factories import PasswordFactory, PasswordsCollectionFactory, UserFactory

User = get_user_model()

register(UserFactory)
register(PasswordsCollectionFactory)
register(PasswordFactory)


@pytest.fixture
def api_client() -> typing.Type[APIClient]:
    return APIClient


@pytest.fixture
def passwords_tester() -> User:
    return UserFactory(username=settings.TESTER_USERNAME)


@pytest.fixture
def cryptographic_key() -> str:
    return settings.TESTER_CRYPTOGRAPHIC_KEY
