from django.urls import path

from exinakai.views import IndexView

app_name = "exinakai"

urlpatterns = [
    path("", IndexView.as_view(), name="index")
]
