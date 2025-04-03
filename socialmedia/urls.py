# from django.urls import path
# from .views import google_auth, google_callback, register, login

# urlpatterns = [
#     path("google/", google_auth, name="google-auth"),
#     path("google/callback/", google_callback, name="google-callback"),

# ]
from django.urls import path
from .views import GoogleAuthView

urlpatterns = [
    path('auth/google/', GoogleAuthView.as_view(), name='google-auth'),
]
