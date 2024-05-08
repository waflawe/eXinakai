from django.urls import path

from exinakai.views import AddPasswordView, AllPasswordsView, DeletePasswordView, IndexView

app_name = "exinakai"

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("add-password/", AddPasswordView.as_view(), name="add-password"),
    path("delete-password/<int:pk>/", DeletePasswordView.as_view(), name="delete-password"),
    path("all-passwords/", AllPasswordsView.as_view(), name="all-passwords")
]
