from random import randrange
from typing import Dict, Optional

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, FormView, View

from exinakai.services import create_passwords_collection
from users.forms import (
    ActivateCryptographicKeyForm,
    PasswordChangeForm,
    PasswordResetForm,
    TwoFactorAuthenticationForm,
    UpdateSettingsForm,
    UserAuthenticationForm,
    UserCreationForm,
)
from users.services import (
    CryptographicKeyEmptyRequiredMixin,
    check_is_redirect_url_valid,
    generate_cryptographic_key,
    is_cryptographic_key_valid,
    make_2fa_authentication,
    process_avatar_and_email_if_updated,
    validate_2fa_code,
)
from users.tasks import (
    send_2fa_code_mail_message,
    send_change_account_email_mail_message,
    send_change_account_password_mail_message,
)
from users.templatetags.crop_user_avatar import get_upload_crop_path

User = get_user_model()


class SingUpView(CreateView):
    template_name = 'users/sing_up.html'
    form_class = UserCreationForm

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        super().get(request, *args, **kwargs)
        context = {
            "error": kwargs.get("bad_details", False)
        }
        return self.render_to_response(self.get_context_data(**context))

    def form_valid(self, form: UserCreationForm):
        send_change_account_email_mail_message.delay(form.instance.email)
        form_valid = super().form_valid(form)
        create_passwords_collection(form.instance, settings.DEFAULT_PASSWORDS_COLLECTION_NAME)
        return form_valid

    def form_invalid(self, form: UserCreationForm) -> HttpResponse:
        return self.get(self.request, bad_details=True, form=form)

    def get_success_url(self) -> str:
        return reverse("accounts:sing-up-success")


class SuccessSingUpView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        check_is_redirect_url_valid(request, reverse("accounts:register"))
        context = {
            "crypto_key": generate_cryptographic_key()
        }
        return render(request, "users/success_sing_up.html", context=context)


class LoginView(View):
    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        form = UserAuthenticationForm(data)
        context = {
            "form": form,
            "action": request.GET.get("action", None),
            "error": True if data else False
        }
        return render(request, "users/login.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        form = UserAuthenticationForm(request.POST)

        if form.is_valid():
            user = authenticate(username=request.POST["username"], password=request.POST["password"])
            if user is not None:
                if not user.is_2fa_enabled:
                    login(request, user)
                    return redirect(reverse('accounts:activate-cryptographic-key'))
                code = make_2fa_authentication(request.session, user)
                send_2fa_code_mail_message.delay(user.email, code)
                return redirect(reverse("accounts:two-factor-authentication"))

        return self.get(request, request.POST)


class TwoFactorAuthenticationView(View):
    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        check_is_redirect_url_valid(request, reverse("accounts:login"), reverse("accounts:two-factor-authentication"))
        context = ({"form": TwoFactorAuthenticationForm()} | data) if data else {"form": TwoFactorAuthenticationForm()}
        return render(request, "users/two_factor_authentication.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        user = validate_2fa_code(request.session, request.POST)
        if user:
            login(request, user)
            return redirect(reverse('accounts:activate-cryptographic-key'))
        return self.get(request, {"error": True})


class ActivateCryptographicKeyView(LoginRequiredMixin, CryptographicKeyEmptyRequiredMixin, FormView):
    template_name = "users/activate_key.html"
    form_class = ActivateCryptographicKeyForm

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        context = {
            "bad_key": kwargs.get("bad_key", False)
        }
        return self.render_to_response(self.get_context_data(**context))

    def form_valid(self, form: ActivateCryptographicKeyForm) -> HttpResponse:
        key = form.cleaned_data["cryptographic_key"]
        if not is_cryptographic_key_valid(self.request.user, key):
            return self.get(self.request, bad_key=True)
        self.request.session["cryptographic_key"] = key
        return super().form_valid(form)

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=activate-cryptographic-key-success"


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        return redirect(f"{reverse('exinakai:index')}?action=logout")


class ResetPasswordView(PasswordResetView):
    form_class = PasswordResetForm
    template_name = 'users/password_reset.html'
    email_template_name = 'users/mails/password_reset_email_message.html'
    subject_template_name = 'users/mails/password_reset_subject_message.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-reset-done"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["hide_form"] = True
        context["api_reset_url"] = reverse("api:password-reset")
        return context


class ConfirmPasswordResetView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-reset-complete"


class ChangePasswordView(LoginRequiredMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = 'users/password_change.html'

    def form_valid(self, form: PasswordChangeForm) -> HttpResponse:
        redirect_ = super().form_valid(form)
        domain = get_current_site(self.request).domain
        send_change_account_password_mail_message.delay(form.user.email, domain)
        return redirect_

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-change-done"


class SettingsView(LoginRequiredMixin, View):
    login_url = reverse_lazy("accounts:login")

    def get(self, request: HttpRequest, error: Optional[bool] = False) -> HttpResponse:
        form = UpdateSettingsForm(user=request.user)
        context = {
            "form": form,
            "user_avatar": get_upload_crop_path(str(request.user.avatar)),
            "any_random_integer": randrange(100000),
            "bad_data": True if error else False,
            "action": request.GET.get("action", None)
        }
        return render(request, "users/settings.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        old_timezone, old_avatar_path, old_email = request.user.timezone, str(request.user.avatar), request.user.email
        form = UpdateSettingsForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            self.check_is_timezone_and_email_updated(form.instance, old_timezone, old_email)
            form.instance.save(update_fields=["email", "avatar", "timezone", "is_2fa_enabled"])
            process_avatar_and_email_if_updated(form.instance, old_avatar_path, old_email)
            return redirect(f"{reverse('exinakai:all-passwords')}?action=settings-updated")
        return self.get(request, True)

    def check_is_timezone_and_email_updated(self, user: User, old_timezone: str, old_email: str) -> None:
        if user.timezone == "":
            user.timezone = old_timezone
        if user.email == "":
            user.email = old_email
