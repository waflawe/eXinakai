from django.urls import path

from users.views import (
    ActivateCryptographicKeyView,
    ChangePasswordView,
    ConfirmPasswordResetView,
    LoginView,
    LogoutView,
    ResetPasswordView,
    SettingsView,
    SingUpView,
    SuccessSingUpView,
    TwoFactorAuthenticationView,
)

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("two-factor-authentication/", TwoFactorAuthenticationView.as_view(), name="two-factor-authentication"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("sing-up/", SingUpView.as_view(), name="register"),
    path("sing-up-success/", SuccessSingUpView.as_view(), name="sing-up-success"),
    path("password-reset/", ResetPasswordView.as_view(), name="password-reset"),
    path('password-reset-confirm/<uidb64>/<token>/', ConfirmPasswordResetView.as_view(), name='password-reset-confirm'),
    path("password-change/", ChangePasswordView.as_view(), name="password-change"),
    path("settings/", SettingsView.as_view(), name="settings"),
    path("activate-cryptographic-key/", ActivateCryptographicKeyView.as_view(), name="activate-cryptographic-key")
]
