from django.db import models
from django.conf import settings


# Create your models here.
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                on_delete=models.CASCADE)
    photos = models.ManyToManyField('Photo', blank=True)


class Photo(models.Model):
    image = models.ImageField(upload_to='users/%Y/%m/%d/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
