from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import hashlib


class CustomAuthenticationBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None,
                     shared_secret_key=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            return None

        if user.password == password:
            return user

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
