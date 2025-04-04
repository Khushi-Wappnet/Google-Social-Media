from django.urls import path
from .views import GoogleLoginRedirect, GoogleAuthCallback, LogoutView,AuthenticateUserView
 
urlpatterns = [
    path("google/login/", GoogleLoginRedirect.as_view(), name="google_login"),
    path("google/callback/", GoogleAuthCallback.as_view(), name="google_callback"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("authenticate/", AuthenticateUserView.as_view(), name="authenticate_user"),
]