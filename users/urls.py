from django.urls import path

from users.views import SingUpView, LoginView, LogoutView

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("sing-up/", SingUpView.as_view(), name="register")
]
