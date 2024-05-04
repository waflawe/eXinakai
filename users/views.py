from typing import Dict, Optional

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, FormView, View

from users.forms import (
    ActivateCryptographicKeyForm,
    PasswordChangeForm,
    PasswordResetForm,
    UpdateSettingsForm,
    UserAuthenticationForm,
    UserCreationForm,
)
from users.services import (
    GenerateCryptographicKeyService,
    SetSessionCryptographicKey,
    CryptographicKeyEmptyRequiredMixin
)


class SingUpView(CreateView):
    template_name = 'users/sing-up.html'
    form_class = UserCreationForm

    def get_success_url(self) -> str:
        return reverse("accounts:sing-up-success")


class SuccessSingUpView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        referer = (request.META.get("HTTP_REFERER", "")
                   .replace(request.get_host(), "")
                   .replace("http://", "")
                   .replace("https://", ""))
        if referer == reverse("accounts:register"):
            context = {
                "crypto_key": GenerateCryptographicKeyService.generate()
            }
            return render(request, "users/success_sing_up.html", context=context)
        raise Http404


class LoginView(View):
    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        form = UserAuthenticationForm(data)
        context = {
            "form": form,
            "action": request.GET.get("action", None),
            "bad_details": True if data else False
        }
        return render(request, "users/login.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        form = UserAuthenticationForm(request.POST)

        if form.is_valid():
            user = authenticate(username=request.POST["username"], password=request.POST["password"])
            if user is not None:
                login(request, user)
                return redirect(reverse('accounts:activate-cryptographic-key'))

        return self.get(request, request.POST)


class ActivateCryptographicKeyView(CryptographicKeyEmptyRequiredMixin, FormView):
    template_name = "users/activate_key.html"
    form_class = ActivateCryptographicKeyForm

    def get_success_url(self):
        return f"{reverse('exinakai:index')}?action=activate-cryptographic-key-success"

    def form_valid(self, form):
        SetSessionCryptographicKey.set_key(self.request.session, form.cleaned_data["cryptographic_key"])
        return super().form_valid(form)


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        return redirect(f"{reverse('exinakai:index')}?action=logout")


class ResetPasswordView(PasswordResetView):
    form_class = PasswordResetForm
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email_message.html'
    subject_template_name = 'users/password_reset_subject_message.html'

    def get_success_url(self) -> str:
        return f"{reverse('accounts:login')}?action=password-reset-done"


class ConfirmPasswordResetView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'

    def get_success_url(self) -> str:
        return f"{reverse('accounts:login')}?action=password-reset-complete"


class ChangePasswordView(LoginRequiredMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = 'users/password_change.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-change-done"


class SettingsView(LoginRequiredMixin, View):
    login_url = reverse_lazy("accounts:login")

    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        form = UpdateSettingsForm(data)
        context = {
            "form": form,
            "bad_data": True if data else False
        }
        return render(request, "users/settings.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        old_timezone = request.user.timezone
        form = UpdateSettingsForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            if form.instance.timezone == "":
                form.instance.timezone = old_timezone
            form.instance.save(update_fields=["avatar", "timezone"])
            return redirect(f"{reverse('exinakai:index')}?action=settings-updated")
        return self.get(request, request.POST)
