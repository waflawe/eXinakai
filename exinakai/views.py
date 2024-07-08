from typing import Dict, Optional, Type

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.forms import BaseForm
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.shortcuts import redirect, render
from django.urls.base import reverse
from django.views.generic import TemplateView, View

from exinakai.forms import AddPasswordForm, AddPasswordsCollectionForm
from exinakai.services import (
    CryptographicKeyRequiredMixin,
    check_user_perms_to_edit_password,
    create_passwords_collection,
    delete_password,
    encrypt_and_save_password,
    generate_random_password_from_request_data,
    get_render_ready_collections,
    get_user_collections,
)
from users.services import check_is_redirect_url_valid


class IndexView(TemplateView):
    template_name = "exinakai/index.html"

    def get_context_data(self, **kwargs) -> Dict:
        context = super().get_context_data(**kwargs)
        context["action"] = self.request.GET.get("action", None)
        return context


class CustomCreateView(LoginRequiredMixin, CryptographicKeyRequiredMixin, View):
    template_name: str
    form_class: Type

    def get(self, request: HttpRequest, data: Optional[Dict] = None, error: Optional[bool] = False) -> HttpResponse:
        return render(request, self.template_name, context=self.get_context(request, data, error))

    def post(self, request: HttpRequest) -> HttpResponse:
        form = self.form_class(**self.get_form_kwargs(request), data=request.POST)
        if form.is_valid():
            self.form_valid(request, form)
            return redirect(self.get_success_url())
        return self.form_invalid(request, form)

    def get_context(self, request: HttpRequest, data: Dict, error: bool) -> Dict:
        return {
            "form": self.form_class(**self.get_form_kwargs(request), data=data),
            "error": error
        }

    def get_form_kwargs(self, request: HttpRequest) -> Dict:
        return {}

    def form_valid(self, request: HttpRequest, form: BaseForm) -> None:
        pass

    def get_success_url(self) -> str:
        return ""

    def form_invalid(self, request: HttpRequest, form: BaseForm) -> HttpResponse:
        return HttpResponse()


class AddPasswordView(CustomCreateView):
    template_name = "exinakai/add_password.html"
    form_class = AddPasswordForm

    def get_form_kwargs(self, request: HttpRequest) -> Dict:
        return {
            "collections": get_user_collections(request.user)
        }

    def form_valid(self, request: HttpRequest, form: BaseForm) -> None:
        encrypt_and_save_password(
            request.user,
            request.session["cryptographic_key"],
            form.cleaned_data["password1"],
            form.cleaned_data["note"],
            form.cleaned_data["collection"]
        )

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:all-passwords')}?action=add-password-success"

    def form_invalid(self, request: HttpRequest, form: BaseForm) -> HttpResponse:
        if check_is_redirect_url_valid(request, reverse("exinakai:generate-password"), raise_exception=False):
            return self.get(request, request.POST)
        return self.get(request, request.POST, True)


class AddPasswordsCollectionView(CustomCreateView):
    template_name = "exinakai/add_collection.html"
    form_class = AddPasswordsCollectionForm

    def form_valid(self, request: HttpRequest, form: BaseForm) -> None:
        create_passwords_collection(
            request.user,
            form.cleaned_data["name"]
        )

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:all-passwords')}?action=add-collection-success"

    def form_invalid(self, request: HttpRequest, form: BaseForm) -> HttpResponse:
        return self.get(request, request.POST, True)


class AllPasswordsView(LoginRequiredMixin, CryptographicKeyRequiredMixin, TemplateView):
    template_name = "exinakai/all_passwords.html"

    def get_context_data(self, **kwargs) -> Dict:
        search = self.request.GET.get("search", None)
        collections = get_render_ready_collections(
            self.request.user,
            search,
            self.request.session["cryptographic_key"]
        )
        context = {
            "collections": collections,
            "action": self.request.GET.get("action", None),
            "search": search
        }
        return context


class DeletePasswordView(LoginRequiredMixin, CryptographicKeyRequiredMixin, View):
    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        password = check_user_perms_to_edit_password(request.user, pk=pk)
        return render(request, "exinakai/removing.html", context={"password": password})

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        delete_password(request.user, pk=pk)
        return redirect(f"{reverse('exinakai:all-passwords')}?action=delete-password-success")


class DeletePasswordsCollectionView(LoginRequiredMixin, CryptographicKeyRequiredMixin, View):
    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        collection = get_user_collections(request.user).filter(pk=pk).first()
        if collection:
            return render(request, "exinakai/removing.html", context={"collection": collection})
        raise PermissionDenied()

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        collections = get_user_collections(request.user)
        collection = collections.filter(pk=pk).first()
        if collection and collection.name != settings.DEFAULT_PASSWORDS_COLLECTION_NAME:
            default_collection = collections.filter(name=settings.DEFAULT_PASSWORDS_COLLECTION_NAME).first()
            passwords = collection.passwords.all()
            with transaction.atomic() as _:
                passwords.update(collection=default_collection)
                for password in passwords:
                    default_collection.passwords.add(password)
                collection.delete()
            key = (f"{self.request.user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
                   f"{settings.ALL_USER_PASSWORDS_CACHE_NAME}")
            cache.delete(key=key)
            key = (f"{self.request.user.pk}{settings.DELIMITER_OF_LINKED_TO_USER_CACHE_NAMES}"
                   f"{settings.ALL_USER_PASSWORDS_COLLECTIONS_CACHE_NAME}")
            cache.delete(key=key)
            return redirect(f"{reverse('exinakai:all-passwords')}?action=delete-collection-success")
        raise PermissionDenied()


class GeneratePasswordView(TemplateView):
    template_name = "exinakai/exinakai_generate_password.html"

    def get_context_data(self, **kwargs) -> Dict:
        context = super().get_context_data(**kwargs)

        random_password, submited_sumbols, length = generate_random_password_from_request_data(self.request.GET)
        context["random_password"] = random_password
        context["submited_sumbols"] = submited_sumbols
        context["length"] = length

        return context
