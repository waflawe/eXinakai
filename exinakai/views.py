from typing import Dict, Optional, Type

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.forms import BaseForm
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.shortcuts import redirect, render
from django.urls.base import reverse
from django.views.generic import TemplateView, View

from exinakai.forms import AddPasswordForm, AddPasswordsCollectionForm, ChangePasswordCollectionForm, UpdatePasswordForm
from exinakai.services import (
    CryptographicKeyRequiredMixin,
    change_password_collection,
    check_user_perms_to_edit_password,
    create_passwords_collection,
    delete_password,
    delete_password_collection,
    encrypt_and_save_password,
    get_render_ready_collections,
    get_user_collections,
    update_password,
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

    def get(self, request: HttpRequest, data: Optional[Dict] = None, error: Optional[bool] = False, **kwargs) \
            -> HttpResponse:
        return render(request, self.template_name, context=self.get_context(request, data, error, **kwargs))

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        form = self.form_class(**self.get_form_kwargs(request, **kwargs), data=request.POST)
        if form.is_valid():
            self.form_valid(request, form, *args, **kwargs)
            return redirect(self.get_success_url())
        return self.form_invalid(request, form)

    def get_context(self, request: HttpRequest, data: Dict, error: bool, **kwargs) -> Dict:
        return {
            "form": self.form_class(**self.get_form_kwargs(request, **kwargs), data=data),
            "error": error
        }

    def get_form_kwargs(self, request: HttpRequest, **kwargs) -> Dict:
        return {}

    def form_valid(self, request: HttpRequest, form: BaseForm, *args, **kwargs) -> None:
        pass

    def get_success_url(self) -> str:
        return ""

    def form_invalid(self, request: HttpRequest, form: BaseForm) -> HttpResponse:
        return self.get(request, data=request.POST, error=True)


class AddPasswordView(CustomCreateView):
    template_name = "exinakai/add_password.html"
    form_class = AddPasswordForm

    def get_form_kwargs(self, request: HttpRequest, **kwargs) -> Dict:
        return {
            "collections": get_user_collections(request.user)
        }

    def form_valid(self, request: HttpRequest, form: BaseForm, *args, **kwargs) -> None:
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
            return self.get(request, data=request.POST)
        return super().form_invalid(request, form)


class AddPasswordsCollectionView(CustomCreateView):
    template_name = "exinakai/add_collection.html"
    form_class = AddPasswordsCollectionForm

    def form_valid(self, request: HttpRequest, form: BaseForm, *args, **kwargs) -> None:
        create_passwords_collection(
            request.user,
            form.cleaned_data["name"]
        )

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:all-passwords')}?action=add-collection-success"


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
        if not collection:
            raise PermissionDenied()
        return render(request, "exinakai/removing.html", context={"collection": collection})

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        collections = get_user_collections(request.user)
        is_deleted = delete_password_collection(
            request.user,
            collections,
            collections.filter(pk=pk).first()
        )
        if is_deleted:
            return redirect(f"{reverse('exinakai:all-passwords')}?action=delete-collection-success")
        raise PermissionDenied()


class ChangePasswordCollectionView(CustomCreateView):
    template_name = "exinakai/change_password_collection.html"
    form_class = ChangePasswordCollectionForm

    def get_form_kwargs(self, request: HttpRequest, **kwargs) -> Dict:
        return {
            "collections": get_user_collections(request.user)
        }

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:all-passwords')}?action=change-password-collection-success"

    def form_valid(self, request: HttpRequest, form: BaseForm, *args, **kwargs) -> None:
        change_password_collection(
            request.user,
            {"pk": kwargs.get("pk", 0)},
            form.cleaned_data["collection"]
        )


class UpdatePasswordView(CustomCreateView):
    template_name = "exinakai/update_password.html"
    form_class = UpdatePasswordForm

    def get_form_kwargs(self, request: HttpRequest, **kwargs) -> Dict:
        return {
            "instance": check_user_perms_to_edit_password(request.user, **kwargs)
        }

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:all-passwords')}?action=update-password-success"

    def form_valid(self, request: HttpRequest, form: BaseForm, *args, **kwargs) -> None:
        update_password(
            kwargs.pop("pk"),
            form.cleaned_data["note"],
            request.user
        )


class GeneratePasswordView(TemplateView):
    template_name = "exinakai/generate_password.html"
