from pytest_factoryboy import register

from tests.factories import UserFactory, PasswordsCollectionFactory, PasswordFactory

register(UserFactory)
register(PasswordsCollectionFactory)
register(PasswordFactory)
