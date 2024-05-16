from django.urls import include, path
from rest_framework.routers import SimpleRouter

from api.views import (
    ActivateCryptographicKeyAPIView,
    PasswordViewSet,
    UserLoginAPIView,
    UserLogoutAPIView,
    UserTwoFactorAuthenticationAPIView,
    PasswordResetView,
    PasswordResetConfirmView,
    PasswordChangeView,
    GeneratePasswordAPIView
)

router = SimpleRouter()
router.register(r"passwords", PasswordViewSet, basename="passwords")

urlpatterns = [
    path("", include(router.urls)),
    path("generate/password/", GeneratePasswordAPIView.as_view(), name="passwords-generate"),
    path("token/login/", UserLoginAPIView.as_view(), name="token-login"),
    path("token/2fa/", UserTwoFactorAuthenticationAPIView.as_view(), name="token-2fa"),
    path("key/activate/", ActivateCryptographicKeyAPIView.as_view(), name="activate-key"),
    path("token/logout/", UserLogoutAPIView.as_view(), name="token-logout"),
    path('password/reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password/change/', PasswordChangeView.as_view(), name='rest_password_change')
]
