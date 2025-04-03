from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    password_set = models.BooleanField(default=False)  # Track if user has set a password

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
