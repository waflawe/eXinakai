from dataclasses import dataclass
from typing import KeysView, Mapping, NamedTuple, Optional, Tuple

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models.query import QuerySet
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls.base import reverse

from exinakai.models import Password, PasswordsCollection
from exinakai.passgen import Options, generate_random_password

User = get_user_model()


class CryptographicKeyRequiredMixin(AccessMixin):
    """Mixin that verifies that the user has a password decryption key."""

    def handle_no_permission(self) -> HttpResponseRedirect:
        return redirect(reverse("accounts:activate-cryptographic-key"))

    def dispatch(self, request: HttpRequest, *args, **kwargs):
        if not request.session.get("cryptographic_key", False):
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class SearchService(object):
    """
    Search examples (n - password note search, c - password collection search):

    1. mental (n)
    2. MENTALSxSWIM (n)
    3. /cq=MENTAL COLLECTION (c)
    4. /cq=MENTAL COLLECTION:MENTAL NOTE (c and n)
    """

    def make_search(self, queryset: QuerySet, search: Optional[str] = None) -> QuerySet:
        if not search:
            return queryset

        if search.startswith(settings.COLLECTION_SEARCH_COMMAND):
            return self.__make_collection_search(queryset, search.replace(settings.COLLECTION_SEARCH_COMMAND, ""))
        return self.__make_password_search(queryset, search)

    def __make_collection_search(self, queryset: QuerySet, search: str) -> QuerySet:
        searchq = search.split(settings.COLLECTION_SEARCH_DELIMITER)
        collection = searchq[0]
        queryset = queryset.filter(collection__name__icontains=collection)
        if len(searchq) > 1:
            queryset = self.__make_password_search(queryset, searchq[1])
        return queryset

    def __make_password_search(self, queryset: QuerySet, search: str) -> QuerySet:
        return queryset.filter(note__icontains=search)


class PasswordRender(NamedTuple):
    """Data structure for storing the password in a render-ready form."""

    password: Password
    decrypted_password: str


@dataclass
class PasswordsCollectionRender:
    """Data structure for storing the passwords collection in a render-ready form."""

    collection: PasswordsCollection
    decrypted_passwords: Optional[Tuple[PasswordRender]] = None
    count_decrypted_passwords: Optional[int] = 0


def encrypt_and_save_password(
        user: User,
        cryptographic_key: str,
        password: str,
        note: str,
        collection: Optional[int] = None
) -> None:
    """
    Service for encrypting and saving the password to the database.

    :param user: The user to whom the password is attached.
    :param cryptographic_key: The key with which the password will be encrypted.
    :param password: Password for encryption and saving.
    :param note: Password note.
    :param collection: Password collection id.
    """

    fernet = Fernet(bytes(cryptographic_key, "utf-8"))
    encrypted_password = fernet.encrypt(bytes(password, "utf-8")).decode("utf-8")
    if collection:
        collection = PasswordsCollection.objects.get(pk=collection)
    else:
        collection = get_user_collections(user).filter(name=settings.DEFAULT_PASSWORDS_COLLECTION_NAME).first()
    collection.passwords.create(owner=user, note=note, password=encrypted_password, collection=collection)
    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    cache.delete(key=key)
    return


def get_decrypted_password(cryptographic_key: str, password: str) -> str:
    """
    Password decryption service.

    :param cryptographic_key: The key to decrypt the password.
    :param password: Password for decryption.
    :return: Decrypted password.
    """

    try:
        fernet = Fernet(bytes(cryptographic_key, "utf-8"))
    except ValueError:
        return settings.INVALID_CRYPTOGRAPHIC_KEY_ERROR_MESSAGE
    return fernet.decrypt(bytes(password, "utf-8")).decode("utf-8")


def get_all_passwords(user: User, search: Optional[str] = None) -> QuerySet:
    """
    A service to retrieve all saved user passwords.

    :param user: The user whose passwords are to be collected.
    :param search: Search query on password notes.
    :return: QuerySet of encrypted passwords.
    """

    key = f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}{settings.ALL_USER_PASSWORDS_CACHE_NAME}"
    queryset = cache.get(key=key)

    if not queryset:
        queryset = Password.storable.filter(owner=user).select_related("collection")
        cache.set(key, queryset)
    return SearchService().make_search(queryset, search)


def get_password(**kwargs) -> Password: return get_object_or_404(Password, **kwargs)


def check_user_perms_to_edit_password(user: User, **kwargs) -> Password:
    """
    Service for checking user's rights to change password.

    :param user: User to verify permissions.
    :param kwargs: Password identifiers (like pk, note, and others).
    :return: Password whose permissions to change have been checked or PermissionDenied error.
    """

    password = get_password(**kwargs)
    if not password.owner == user:
        raise PermissionDenied("Вы не можете редактировать этот пароль.")
    return password


def generate_random_password_from_request_data(request_data: Mapping) -> tuple[str, KeysView, int]:
    """
    Service for random password generation according to user filters.

    :param request_data: Ready password information from request (request.GET for django.http.request.HttpRequest
    and request.query_params for rest_framework.request.Request)
    :return: Tuple of the generated password, the characters used in the generation,
    and the length of the generated password.
    """

    default_characters = {"l": "lowercase", "u": "uppercase", "d": "digits", "p": "punctuation"}
    submited_sumbols = request_data.keys()
    characters = "".join(alias for alias, sumbols in default_characters.items() if sumbols in submited_sumbols)

    length: str = request_data.get("length", "0")
    clean_length: int = length if length.isnumeric() and 8 <= int(length) <= 32 else 16

    return (
        generate_random_password(Options(clean_length, characters or "ludp")),
        submited_sumbols,
        clean_length
    )


def create_passwords_collection(owner: User, name: str) -> None:
    """
    Create passwords collection from owner, name and passwords.

    :param owner: Owner of passwords collection.
    :param name: Name of passwords collection.
    """

    collection = PasswordsCollection(owner=owner, name=name)
    collection.save()
    key = (f"{owner.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
           f"{settings.ALL_USER_PASSWORDS_COLLECTIONS_CACHE_NAME}")
    cache.delete(key=key)
    return


def get_user_collections(user: User) -> QuerySet[PasswordsCollection]:
    """
    Get collections where user is owner.

    :param user: Some user.
    :return: QuerySet of collections.
    """

    key = (f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
           f"{settings.ALL_USER_PASSWORDS_COLLECTIONS_CACHE_NAME}")
    collections = cache.get(key)

    if not collections:
        collections = PasswordsCollection.objects.filter(owner=user).prefetch_related("passwords")
        cache.set(key, collections)

    return collections


def get_render_ready_collections(user: User, search: str | None, cryptographic_key: str) \
        -> Tuple[PasswordsCollectionRender, ...]:
    """
    Service to get collections in render-ready form.

    :param user: Owner of a collections.
    :param search: Query to seach passwords.
    :param cryptographic_key: Owner cryptographic key.
    :return: Tuple of PasswordsCollectionRender objects with collections.
    """

    collection_renders: Tuple[PasswordsCollectionRender, ...] = tuple(
        PasswordsCollectionRender(collection, tuple(
            PasswordRender(
                password,
                get_decrypted_password(cryptographic_key, password.password)
            ) for password in SearchService().make_search(collection.passwords.filter(), search)
        )) for collection in get_user_collections(user)
    )

    for collection_render in collection_renders:
        collection_render.count_decrypted_passwords = len(collection_render.decrypted_passwords)

    return collection_renders


def clear_user_cache(user: User) -> None:
    key = (f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
           f"{settings.ALL_USER_PASSWORDS_CACHE_NAME}")
    cache.delete(key=key)
    key = (f"{user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
           f"{settings.ALL_USER_PASSWORDS_COLLECTIONS_CACHE_NAME}")
    cache.delete(key=key)
    return


def change_password_collection(user: User, query_params: Mapping, collection: int) -> None:
    """
    Service to change password collection.

    :param user: Owner of password.
    :param query_params: Mapping with pk of password or just password.
    :param collection: New password collection.
    """

    pk = query_params.get("pk")
    password = check_user_perms_to_edit_password(user, pk=pk) if pk else query_params.get("password", None)
    collection = get_object_or_404(PasswordsCollection, pk=collection)

    with transaction.atomic():
        old_collection = password.collection
        password.collection = collection
        password.save()
        old_collection.passwords.remove(password)
        collection.passwords.add(password)

    clear_user_cache(user)
    return


def delete_password_collection(
        user: User,
        collections: QuerySet[PasswordsCollection],
        collection_to_delete: PasswordsCollection
) -> bool:
    """
    Service to delete collection with passwords.

    :param user: Owner of the collection to delete.
    :param collections: All user owner passwords collections.
    :param collection_to_delete: Passwords collection to be deleted.
    :return: Flag is collection success deleted.
    """

    if not (collection_to_delete and collection_to_delete.name != settings.DEFAULT_PASSWORDS_COLLECTION_NAME):
        return False

    default_collection = collections.filter(name=settings.DEFAULT_PASSWORDS_COLLECTION_NAME).first()
    passwords = collection_to_delete.passwords.all()
    with transaction.atomic():
        passwords.update(collection=default_collection)
        for password in passwords:
            default_collection.passwords.add(password)
        collection_to_delete.delete()

    clear_user_cache(user)
    return True


def update_password(password: Password | int, note: str, user: User) -> None:
    """
    Service for update password.

    :param password: Password object or promary key.
    :param note: New password note
    :param user: User needs to check his perms on the password edition.
    """

    password = password if isinstance(password, Password) else check_user_perms_to_edit_password(user, pk=password)
    password.note = note
    password.save()

    clear_user_cache(user)
    return


def delete_password(user: User, **kwargs) -> None:
    """
    Service for deleting passwords from the database.

    :param user: User to verify permissions.
    :param kwargs: Password identifiers (like pk, note, password instance and others).
    """

    password = kwargs["password"] if kwargs.get("password", None) else check_user_perms_to_edit_password(user, **kwargs)
    password.delete()

    clear_user_cache(user)
    return
