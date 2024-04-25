from django.views.generic import CreateView, View
from django.http import HttpRequest, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.urls import reverse, reverse_lazy
from django.shortcuts import render, redirect

from typing import Optional, Dict

from users.forms import UserCreationForm, UserAuthenticationForm


class SingUpView(CreateView):
    template_name = 'users/sing-up.html'
    form_class = UserCreationForm

    def get_success_url(self) -> str:
        return reverse("accounts:login")


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
                return redirect(f"{reverse('exinakai:index')}?action=login")

        return self.get(request, request.POST)


class LogoutView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        logout(request)
        return redirect(f"{reverse('exinakai:index')}?action=logout")


class ResetPasswordView(PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email_message.html'
    subject_template_name = 'users/password_reset_subject_message.html'
    success_message = ""

    def get_success_url(self):
        return f"{reverse('accounts:login')}?action=password-reset-done"


class ConfirmPasswordResetView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'

    def get_success_url(self):
        return f"{reverse('accounts:login')}?action=password-reset-complete"
