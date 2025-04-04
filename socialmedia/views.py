from django.contrib.auth import login
from django.shortcuts import redirect
from rest_framework.response import Response
from rest_framework.views import APIView
from social_django.utils import psa
from rest_framework.permissions import AllowAny
from django.conf import settings
from urllib.parse import urlencode
import requests
from socialmedia.models import CustomUser
 
 
class GoogleLoginRedirect(APIView):
    """
    Redirects user to Google's OAuth2 login page
    """
    permission_classes = [AllowAny]
 
    def get(self, request):
        google_auth_url = "https://accounts.google.com/o/oauth2/auth"
        params = {
            "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            "redirect_uri": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent"
        }
        return redirect(f"{google_auth_url}?{urlencode(params)}")
 
 
class GoogleAuthCallback(APIView):
    """
    Handles OAuth2 callback from Google
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            # Get the authorization code from the request
            code = request.GET.get("code")
            if not code:
                return Response({"error": "No authorization code provided"}, status=400)

            # Exchange authorization code for access and refresh tokens
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "code": code,
                "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
                "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
                "redirect_uri": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI,
                "grant_type": "authorization_code",
            }
            token_response = requests.post(token_url, data=token_data)
            token_json = token_response.json()

            # Check for errors in the token response
            if "error" in token_json:
                return Response({"error": token_json["error"], "details": token_json}, status=400)

            # Extract access token and refresh token
            access_token = token_json.get("access_token")
            refresh_token = token_json.get("refresh_token")

            if not access_token:
                return Response({"error": "Failed to retrieve access token"}, status=400)

            # Optionally, fetch user info using the access token
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_info_response = requests.get(user_info_url, headers=headers)
            user_info = user_info_response.json()

            if "email" not in user_info:
                return Response({"error": "Failed to retrieve user info"}, status=400)

            # Create or retrieve the user in the database
            user, created = CustomUser.objects.get_or_create(
                email=user_info["email"],
                defaults={"username": user_info["email"].split("@")[0]},
            )

            # Explicitly set the backend for the user
            user.backend = "social_core.backends.google.GoogleOAuth2"

            # Log the user in
            login(request, user)

            # Return the tokens and user info
            return Response({
                "message": "Login successful",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": {
                    "email": user.email,
                    "username": user.username,
                },
            })

        except Exception as e:
            # Log the error and return a 500 response
            return Response({"error": "An unexpected error occurred", "details": str(e)}, status=500)
 
class LogoutView(APIView):
    """
    Logs out the user
    """
    def post(self, request):
        request.session.flush()
        return Response({"message": "Logged out successfully"})

class AuthenticateUserView(APIView):
    """
    Verifies the access token and authenticates the user
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Get the access token from the request body
            access_token = request.data.get("access_token")
            if not access_token:
                return Response({"error": "Access token is required"}, status=400)

            # Use Google's userinfo endpoint to validate the token
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_info_response = requests.get(user_info_url, headers=headers)

            # Check if the token is valid
            if user_info_response.status_code != 200:
                return Response({"error": "Invalid access token"}, status=401)

            # Parse the user info
            user_info = user_info_response.json()
            email = user_info.get("email")
            if not email:
                return Response({"error": "Failed to retrieve user info"}, status=400)

            # Check if the user exists in the database
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=404)

            # Return success response with user details
            return Response({
                "message": "Access token is valid",
                "user": {
                    "email": user.email,
                    "username": user.username,
                },
            })

        except Exception as e:
            # Log the error and return a 500 response
            return Response({"error": "An unexpected error occurred", "details": str(e)}, status=500)