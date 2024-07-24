import typing
import pytest

from rest_framework.test import APIClient
from tests.factories import PasswordFactory, PasswordsCollectionFactory
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status

import json

from django.urls import reverse_lazy

pytestmark = [pytest.mark.django_db]
User = get_user_model()


class TestPasswordsViews:
    login_endpoint = reverse_lazy("api:token-login")
    activate_key_endpoint = reverse_lazy("api:activate-key")
    endpoint = reverse_lazy("api:passwords-list")

    tests_count = 20   # 1 to 20 (pagination limit)
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
        passwords, edited_passwords = self.get_testing_passwords(password_factory)
        for password in passwords:
            data = {"note": password.note, "password": password.password}
            self.send_unsafe_request(client, "post", self.endpoint, data, status.HTTP_201_CREATED)
        db_passwords = self.get_and_check_db_passwords(client)
        for db_password, password in zip(db_passwords[::-1], passwords):
            assert db_password["note"] == password.note
        new_collection = passwords_collection_factory(owner=passwords_tester, name=self.edited_collection_name)
        for counter, password in zip(range(1, self.tests_count+1), edited_passwords):
            data = {"note": password.note, "collection": new_collection.pk}
            self.send_unsafe_request(client, "patch", self.endpoint + f"{counter}/", data)
        db_passwords = self.get_and_check_db_passwords(client)
        for db_password, password in zip(db_passwords[::-1], edited_passwords):
            assert db_password["note"] == password.note
            assert db_password["collection"] == self.edited_collection_name
        for counter in range(1, self.tests_count+1):
            self.send_unsafe_request(client, "delete", self.endpoint + f"{counter}/", {}, status.HTTP_204_NO_CONTENT)
        self.get_and_check_db_passwords(client, 0)

    def get_authenticated_client(self, client: APIClient, authenticate_as: User, cryptographic_key: str) -> APIClient:
        client.force_authenticate(user=authenticate_as)
        res = client.post(self.activate_key_endpoint, {"cryptographic_key": cryptographic_key})
        assert res.status_code == status.HTTP_200_OK
        return client

    def get_testing_passwords(self, password_factory: typing.Callable) -> typing.Tuple[typing.List, typing.List]:
        passwords = password_factory.build_batch(self.tests_count * 2)
        return passwords[:self.tests_count], passwords[self.tests_count:]

    def get_and_check_db_passwords(self, client: APIClient, needed_len: typing.Optional[int] = None) -> typing.List:
        res = client.get(self.endpoint)
        assert res.status_code == status.HTTP_200_OK
        db_passwords = json.loads(res.content)["results"]
        assert len(db_passwords) == needed_len if needed_len else self.tests_count
        return db_passwords

    def send_unsafe_request(
            self,
            client: APIClient,
            method: str,
            url: str,
            data: typing.Optional[typing.Dict] = None,
            status__: typing.Optional[int] = status.HTTP_200_OK
    ):
        res = getattr(client, method)(url, data)
        assert res.status_code == status__
