from django.urls import path

from exinakai.views import (
    AddPasswordsCollectionView,
    AddPasswordView,
    AllPasswordsView,
    ChangePasswordCollectionView,
    DeletePasswordsCollectionView,
    DeletePasswordView,
    GeneratePasswordView,
    IndexView,
    UpdatePasswordView
)

app_name = "exinakai"

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("add-password/", AddPasswordView.as_view(), name="add-password"),
    path("add-collection/", AddPasswordsCollectionView.as_view(), name="add-collection"),
    path("change-password-collection/<int:pk>/", ChangePasswordCollectionView.as_view(),
         name="change-password-collection"),
    path("update-password/<int:pk>/", UpdatePasswordView.as_view(), name="update-password"),
    path("delete-password/<int:pk>/", DeletePasswordView.as_view(), name="delete-password"),
    path("delete-collection/<int:pk>/", DeletePasswordsCollectionView.as_view(), name="delete-collection"),
    path("generate-password/", GeneratePasswordView.as_view(), name="generate-password"),
    path("all-passwords/", AllPasswordsView.as_view(), name="all-passwords")
]
