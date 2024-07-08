from django.urls import path

from exinakai.views import (
    AddPasswordsCollectionView,
    AddPasswordView,
    AllPasswordsView,
    DeletePasswordsCollectionView,
    DeletePasswordView,
    GeneratePasswordView,
    IndexView,
)

app_name = "exinakai"

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("add-password/", AddPasswordView.as_view(), name="add-password"),
    path("add-collection/", AddPasswordsCollectionView.as_view(), name="add-collection"),
    path("delete-password/<int:pk>/", DeletePasswordView.as_view(), name="delete-password"),
    path("delete-collection/<int:pk>/", DeletePasswordsCollectionView.as_view(), name="delete-collection"),
    path("generate-password/", GeneratePasswordView.as_view(), name="generate-password"),
    path("all-passwords/", AllPasswordsView.as_view(), name="all-passwords")
]
