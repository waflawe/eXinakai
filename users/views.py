from random import randrange
from typing import Dict, Optional

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.forms.widgets import TextInput
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
    CryptographicKeyEmptyRequiredMixin,
    GenerateCryptographicKeyService,
    SetSessionCryptographicKeyService,
    get_upload_crop_path,
)
from users.tasks import make_center_crop, send_change_account_email_mail_message

User = get_user_model()


class SingUpView(CreateView):
    template_name = 'users/sing-up.html'
    form_class = UserCreationForm

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        super().get(request, *args, **kwargs)
        context = {
            "bad_details": kwargs.get("bad_details", False)
        }
        return self.render_to_response(self.get_context_data(**context))

    def form_valid(self, form: UserCreationForm):
        send_change_account_email_mail_message.delay(form.instance.email)
        return super().form_valid(form)

    def form_invalid(self, form: UserCreationForm):
        return self.get(self.request, bad_details=True, form=form)

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


class ActivateCryptographicKeyView(LoginRequiredMixin, CryptographicKeyEmptyRequiredMixin, FormView):
    template_name = "users/activate_key.html"
    form_class = ActivateCryptographicKeyForm

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        context = {
            "bad_key": kwargs.get("bad_key", False)
        }
        return self.render_to_response(self.get_context_data(**context))

    def form_valid(self, form: ActivateCryptographicKeyForm) -> HttpResponse:
        if not SetSessionCryptographicKeyService.is_key_valid(
                self.request.user,
                form.cleaned_data["cryptographic_key"]
        ):
            return self.get(self.request, bad_key=True)
        SetSessionCryptographicKeyService.set_key(self.request.session, form.cleaned_data["cryptographic_key"])
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
    email_template_name = 'users/password_reset_email_message.html'
    subject_template_name = 'users/password_reset_subject_message.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-reset-done"


class ConfirmPasswordResetView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-reset-complete"


class ChangePasswordView(LoginRequiredMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = 'users/password_change.html'

    def get_success_url(self) -> str:
        return f"{reverse('exinakai:index')}?action=password-change-done"


class SettingsView(LoginRequiredMixin, View):
    login_url = reverse_lazy("accounts:login")

    def get(self, request: HttpRequest, data: Optional[Dict] = None) -> HttpResponse:
        form = UpdateSettingsForm(data)
        if not data:
            form.fields["email"].widget = TextInput(attrs={"placeholder": request.user.email})
        context = {
            "form": form,
            "user_avatar": get_upload_crop_path(str(request.user.avatar)),
            "any_random_integer": randrange(100000),
            "bad_data": True if data else False,
            "action": request.GET.get("action", None)
        }
        return render(request, "users/settings.html", context=context)

    def post(self, request: HttpRequest) -> HttpResponse:
        old_timezone, old_avatar_path, old_email = request.user.timezone, str(request.user.avatar), request.user.email
        form = UpdateSettingsForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            self.check_is_timezone_and_email_updated(form.instance, old_timezone, old_email)
            form.instance.save(update_fields=["email", "avatar", "timezone"])
            self.process_avatar_and_email_if_updated(form.instance, old_avatar_path, old_email)
            return redirect(f"{reverse('accounts:settings')}?action=settings-updated")
        return self.get(request, request.POST)

    def check_is_timezone_and_email_updated(self, user: User, old_timezone: str, old_email: str) -> None:
        if user.timezone == "":
            user.timezone = old_timezone
        if user.email == "":
            user.email = old_email

    def process_avatar_and_email_if_updated(self, user: User, old_avatar_path: str, old_email: str) -> None:
        if str(user.avatar) != old_avatar_path:
            make_center_crop.delay(str(user.avatar))
        if user.email != old_email:
            send_change_account_email_mail_message.delay(user.email)
