from django.urls import path

from users.views import SingUpView, LoginView, LogoutView, ResetPasswordView, ConfirmPasswordResetView

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("sing-up/", SingUpView.as_view(), name="register"),
    path("password-reset/", ResetPasswordView.as_view(), name="password-reset"),
    path('password-reset-confirm/<uidb64>/<token>/', ConfirmPasswordResetView.as_view(), name='password-reset-confirm')
]
