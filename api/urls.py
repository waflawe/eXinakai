from django.urls import include, path
from rest_framework.routers import SimpleRouter

from api.views import (
    ActivateCryptographicKeyAPIView,
    PasswordViewSet,
    UserLoginAPIView,
    UserLogoutAPIView,
    UserTwoFactorAuthenticationAPIView,
)

router = SimpleRouter()
router.register(r"passwords", PasswordViewSet, basename="passwords")

urlpatterns = [
    path("", include(router.urls)),
    path("token-login/", UserLoginAPIView.as_view(), name="token-login"),
    path("token-2fa/", UserTwoFactorAuthenticationAPIView.as_view(), name="token-2fa"),
    path("activate-key/", ActivateCryptographicKeyAPIView.as_view(), name="activate-key"),
    path("token-logout/", UserLogoutAPIView.as_view(), name="token-logout"),
]