from typing import Dict, Optional

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.shortcuts import redirect, render
from django.urls.base import reverse
from django.views.generic import TemplateView, View

from exinakai.forms import AddPasswordForm
from exinakai.services import (
    CryptographicKeyRequiredMixin,
    check_user_perms_to_edit_password,
    delete_password,
    encrypt_and_save_password,
    get_all_passwords,
    generate_random_password_from_request
)


class IndexView(TemplateView):
    template_name = "exinakai/index.html"

    def get_context_data(self, **kwargs) -> Dict:
        context = super().get_context_data(**kwargs)
        context["action"] = self.request.GET.get("action", None)
        return context


class AddPasswordView(LoginRequiredMixin, CryptographicKeyRequiredMixin, View):
    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        context = {
            "form": AddPasswordForm(data),
            "bad_data": True if data else False
        }
        return render(request, "exinakai/add_password.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        form = AddPasswordForm(request.POST)
        if form.is_valid():
            encrypt_and_save_password(
                request.user,
                request.session["cryptographic_key"],
                form.cleaned_data["password1"],
                form.cleaned_data["note"]
            )
            return redirect(f"{reverse('exinakai:all-passwords')}?action=add-password-success")
        return self.get(request, request.POST)


class AllPasswordsView(LoginRequiredMixin, CryptographicKeyRequiredMixin, TemplateView):
    template_name = "exinakai/all_passwords.html"

    def get_context_data(self, **kwargs) -> Dict:
        search = self.request.GET.get("search", None)
        passwords = get_all_passwords(
            self.request.user,
            search,
            cryptographic_key=self.request.session["cryptographic_key"],
        )
        context = {
            "passwords": passwords,
            "action": self.request.GET.get("action", None),
            "search": search
        }
        return context


class DeletePasswordView(LoginRequiredMixin, CryptographicKeyRequiredMixin, View):
    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        password = check_user_perms_to_edit_password(request.user, pk=pk)
        return render(request, "exinakai/delete_password.html", context={"password": password})

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        delete_password(request.user, pk=pk)
        return redirect(f"{reverse('exinakai:all-passwords')}?action=delete-password-success")


class GeneratePasswordView(TemplateView):
    template_name = "exinakai/exinakai_generate_password.html"

    def get_context_data(self, **kwargs) -> Dict:
        context = super().get_context_data(**kwargs)

        random_password, submited_sumbols, length = generate_random_password_from_request(self.request.GET)
        context["random_password"] = random_password
        context["submited_sumbols"] = submited_sumbols
        context["length"] = length

        return context
