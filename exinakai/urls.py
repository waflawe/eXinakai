from django.urls import path

from exinakai.views import AddPasswordView, IndexView

app_name = "exinakai"

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("add-password/", AddPasswordView.as_view(), name="add-password")
]
