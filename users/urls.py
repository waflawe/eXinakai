from django.urls import path

from users.views import ConfirmPasswordResetView, LoginView, LogoutView, ResetPasswordView, SettingsView, SingUpView

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("sing-up/", SingUpView.as_view(), name="register"),
    path("password-reset/", ResetPasswordView.as_view(), name="password-reset"),
    path('password-reset-confirm/<uidb64>/<token>/', ConfirmPasswordResetView.as_view(), name='password-reset-confirm'),
    path("settings/", SettingsView.as_view(), name="settings")
]
