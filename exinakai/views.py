from typing import Dict, Optional

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.shortcuts import render, redirect, reverse
from django.views.generic import TemplateView, View

from exinakai.forms import AddPasswordForm
from exinakai.services import CryptographicKeyRequiredMixin, EncryptPasswordService


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

    def post(self, request: HttpRequest):
        form = AddPasswordForm(request.POST)
        if form.is_valid():
            EncryptPasswordService.encrypt_and_insert(
                request.user,
                request.session["cryptographic_key"],
                form.cleaned_data["password1"],
                form.cleaned_data["note"]
            )
            return redirect(f"{reverse('exinakai:all-passwords')}?action=add-password-success")
        return self.get(request, request.POST)
