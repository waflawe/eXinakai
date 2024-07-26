import json
import os
import random
import string
import typing

import pytest
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.urls import reverse_lazy
from pytz import common_timezones
from rest_framework import status
from rest_framework.test import APIClient

from tests.factories import PasswordFactory, PasswordsCollectionFactory, UserFactory

pytestmark = [pytest.mark.django_db]
User = get_user_model()


class TestsMixin(object):
    activate_key_endpoint = reverse_lazy("api:activate-key")
    endpoint = None

    tests_count = 3  # 1 to 20 only if test tests data arrays (pagination limit)

    def get_authenticated_client(self, client: APIClient, authenticate_as: User, cryptographic_key: str) -> APIClient:
        client.force_authenticate(user=authenticate_as)
        res = client.post(self.activate_key_endpoint, {"cryptographic_key": cryptographic_key})
        assert res.status_code == status.HTTP_200_OK
        return client

    def send_unsafe_request(
            self,
            client: APIClient,
            method: str,
            url: typing.Optional[str] = None,
            data: typing.Optional[typing.Dict] = None,
            status__: typing.Optional[int] = status.HTTP_200_OK
    ) -> None:
        res = getattr(client, method)(url or self.endpoint, data)
        assert res.status_code == status__

    def create_and_get_testing_objects(self, factory: typing.Callable) -> typing.Tuple[typing.List, typing.List]:
        instances = factory.build_batch(self.tests_count * 2)
        return instances[:self.tests_count], instances[self.tests_count:]

    def get_and_check_objects_in_db(self, client: APIClient, needed_len: typing.Optional[int] = None) -> typing.List:
        res = client.get(self.endpoint)
        assert res.status_code == status.HTTP_200_OK
        db_passwords = json.loads(res.content)["results"]
        assert len(db_passwords) == needed_len if needed_len else self.tests_count
        return db_passwords


class TestPasswordsViews(TestsMixin):
    endpoint = reverse_lazy("api:passwords-list")

    edited_collection_name = "TEST_UPDATE_COLLECTION"

    def test_password_crud(
            self,
            passwords_tester: User,
            cryptographic_key: str,
            password_factory: typing.Type[PasswordFactory],
            passwords_collection_factory: typing.Type[PasswordsCollectionFactory],
            api_client: typing.Type[APIClient]
    ):
        passwords_collection_factory(owner=passwords_tester, name=settings.DEFAULT_PASSWORDS_COLLECTION_NAME)
        client = self.get_authenticated_client(api_client(), passwords_tester, cryptographic_key)
        passwords, edited_passwords = self.create_and_get_testing_objects(password_factory)
        for password in passwords:
            data = {"note": password.note, "password": password.password}
            self.send_unsafe_request(client, "post", data=data, status__=status.HTTP_201_CREATED)
        db_passwords = self.get_and_check_objects_in_db(client)
        for db_password, password in zip(db_passwords[::-1], passwords):
            assert db_password["note"] == password.note
        new_collection = passwords_collection_factory(owner=passwords_tester, name=self.edited_collection_name)
        for counter, password in zip(range(1, self.tests_count + 1), edited_passwords):
            data = {"note": password.note, "collection": new_collection.pk}
            self.send_unsafe_request(client, "patch", self.endpoint + f"{counter}/", data)
        db_passwords = self.get_and_check_objects_in_db(client)
        for db_password, password in zip(db_passwords[::-1], edited_passwords):
            assert db_password["note"] == password.note
            assert db_password["collection"] == self.edited_collection_name
        for counter in range(1, self.tests_count + 1):
            self.send_unsafe_request(client, "delete", self.endpoint + f"{counter}/", {}, status.HTTP_204_NO_CONTENT)
        self.get_and_check_objects_in_db(client, 0)


class TestPasswordsCollectionsViews(TestsMixin):
    endpoint = reverse_lazy("api:collections-list")

    def test_passwords_collections_crud(
            self,
            passwords_tester: User,
            cryptographic_key: str,
            passwords_collection_factory: typing.Type[PasswordsCollectionFactory],
            api_client: typing.Type[APIClient]
    ):
        client = self.get_authenticated_client(api_client(), passwords_tester, cryptographic_key)
        collections, _ = self.create_and_get_testing_objects(passwords_collection_factory)
        for collection in collections:
            self.send_unsafe_request(client, "post", data={"name": collection.name}, status__=status.HTTP_201_CREATED)
        db_collections = self.get_and_check_objects_in_db(client)
        for db_collection, collection in zip(db_collections, collections):
            assert db_collection["name"] == collection.name
        for collection in db_collections:
            counter = collection['id']
            self.send_unsafe_request(client, "delete", self.endpoint + f"{counter}/", {}, status.HTTP_204_NO_CONTENT)
        self.get_and_check_objects_in_db(client, 0)


class TestAccountSettings(TestsMixin):
    endpoint = reverse_lazy("api:settings-update")

    test_avatar_path = "default-user-icon-test.jpg"

    def test_account_settings_crud(
            self,
            user_factory: typing.Type[UserFactory],
            cryptographic_key: str,
            api_client: typing.Type[APIClient]
    ):
        users = user_factory.create_batch(self.tests_count)
        for user in users:
            client = self.get_authenticated_client(api_client(), user, cryptographic_key)
            self.check_user_settings(
                client,
                settings.MEDIA_URL + settings.DEFAULT_USER_AVATAR_PATH,
                settings.DEFAULT_USER_TIMEZONE,
                False
            )
            with open(os.path.join(settings.MEDIA_ROOT, self.test_avatar_path), "rb") as avatar:
                data = {
                    "avatar": avatar,
                    "timezone": random.choice(common_timezones),
                    "is_2fa_enabled": True
                }
                self.send_unsafe_request(client, "post", data=data)
            self.check_user_settings(
                client,
                settings.MEDIA_URL + str(user.avatar),
                data["timezone"],
                data["is_2fa_enabled"]
            )

    def check_user_settings(self, client: APIClient, avatar: str, timezone: str, is_2fa_enabled: bool) -> None:
        res = client.get(self.endpoint)
        assert res.status_code == status.HTTP_200_OK
        content = json.loads(res.content)
        assert content["avatar"] == avatar
        assert content["timezone"] == timezone
        assert content["is_2fa_enabled"] is is_2fa_enabled


class TestPasswordsGeneration(TestsMixin):
    endpoint = reverse_lazy("api:passwords-generate")

    def test_passwords_generation(
            self,
            api_client: typing.Type[APIClient],
            user_factory: typing.Type[UserFactory],
            cryptographic_key: str
    ):
        user = user_factory()
        client = self.get_authenticated_client(api_client(), user, cryptographic_key)
        for counter in range(self.tests_count):
            length = self.get_password_length()
            symbols = list(self.get_password_symbols().values())
            symbols_query = "&".join(f"{i}=True" for i in symbols)
            res = client.get(f"{self.endpoint}?length={length}&{symbols_query}")
            assert res.status_code == status.HTTP_200_OK
            password = json.loads(res.content)["password"]
            assert len(password) == length
            valid_values = "".join(
                getattr(string, symbol, getattr(string, "ascii_" + symbol, "")) for symbol in symbols
            )
            for symbol in password:
                assert symbol in valid_values

    def get_password_length(self) -> int: return random.randrange(8, 32 + 1)

    def get_password_symbols(self):
        default_characters = {"l": "lowercase", "u": "uppercase", "d": "digits", "p": "punctuation"}
        keys = list(default_characters.keys())
        symbols = []
        for _ in range(1, random.randrange(2, 4 + 1)):
            symbols.append(random.choice(keys))
        return {symbol: default_characters[symbol] for symbol in symbols}


class TestAccountPasswordChange(TestsMixin):
    endpoint = reverse_lazy("api:password-change")

    def test_account_password_change(
            self,
            api_client: typing.Type[APIClient],
            user_factory: typing.Type[UserFactory],
            cryptographic_key: str
    ):
        for _ in range(self.tests_count):
            username = user_factory.stub().username
            old_password, new_password = user_factory.stub().password, user_factory.stub().password
            user = user_factory.create(username=username, password=old_password)
            assert authenticate(username=username, password=new_password) is None
            client = self.get_authenticated_client(api_client(), user, cryptographic_key)
            data = {
                "new_password1": new_password,
                "new_password2": new_password
            }
            self.send_unsafe_request(client, "post", data=data)
            assert authenticate(username=username, password=new_password) is not None
