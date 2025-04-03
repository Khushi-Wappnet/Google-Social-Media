from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from google.auth.transport import requests
from google.oauth2 import id_token
import os

User = get_user_model()


def generate_tokens(user):
    """Generate JWT tokens"""
    refresh = RefreshToken.for_user(user)
    return {
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
    }


class GoogleAuthView(APIView):
    def get(self, request):
        """
        Step 1: Redirect to Google Login Page
        """
        google_auth_url = (
            f"https://accounts.google.com/o/oauth2/auth?"
            f"client_id={os.getenv('GOOGLE_CLIENT_ID')}"
            f"&redirect_uri={os.getenv('GOOGLE_REDIRECT_URI')}"
            f"&response_type=code"
            f"&scope=email%20profile"
        )
        return redirect(google_auth_url)

    def post(self, request):
        """
        Step 2: Handle Google OAuth Callback and Register/Login User
        """
        token = request.data.get("token")
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Verify Google token
            google_info = id_token.verify_oauth2_token(
                token, requests.Request(), os.getenv("GOOGLE_CLIENT_ID")
            )

            if "email" not in google_info:
                return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

            email = google_info["email"]
            name = google_info.get("name", "")

            user, created = User.objects.get_or_create(
                email=email, defaults={"username": email, "first_name": name}
            )

            if created:
                message = "User registered successfully"
            else:
                message = "User logged in successfully"

            tokens = generate_tokens(user)

            return Response(
                {
                    "message": message,
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "user": {"email": user.email, "name": user.first_name},
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
