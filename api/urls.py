from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.routers import SimpleRouter

from api.views import (
    ActivateCryptographicKeyAPIView,
    PasswordChangeAPIView,
    PasswordResetAPIView,
    PasswordResetConfirmAPIView,
    PasswordsCollectionViewSet,
    PasswordViewSet,
    UpdateSettingsAPIView,
    UserLoginAPIView,
    UserLogoutAPIView,
    UserTwoFactorAuthenticationAPIView,
)

app_name = "api"

router = SimpleRouter()
router.register(r"passwords", PasswordViewSet, basename="passwords")
router.register(r"collections", PasswordsCollectionViewSet, basename="collections")

urlpatterns = [
    path("", include(router.urls)),
    path("settings/", UpdateSettingsAPIView.as_view(), name="settings-update"),
    path("token/login/", UserLoginAPIView.as_view(), name="token-login"),
    path("token/2fa/", UserTwoFactorAuthenticationAPIView.as_view(), name="token-2fa"),
    path("key/activate/", ActivateCryptographicKeyAPIView.as_view(), name="activate-key"),
    path("token/logout/", UserLogoutAPIView.as_view(), name="token-logout"),
    path('password/reset/', PasswordResetAPIView.as_view(), name='password-reset'),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm'),
    path('password/change/', PasswordChangeAPIView.as_view(), name='password-change'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/docs/', SpectacularSwaggerView.as_view(url_name='api:schema'), name="schema-docs"),
]
