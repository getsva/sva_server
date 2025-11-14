# authentication/custom_auth.py

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .token_utils import get_user_from_token

class CustomTokenAuthentication(BaseAuthentication):
    """
    Custom token authentication.

    Clients should authenticate by passing the token in the "Authorization"
    HTTP header, prepended with the string "Bearer ". For example:

        Authorization: Bearer <your_access_token>
    """
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        
        # Case 1: No credentials were provided.
        # Returning None allows access to public endpoints and lets DRF
        # try other authentication methods if configured.
        if not auth_header:
            return None
            
        # Case 2: The Authorization header is malformed.
        # This is an explicit authentication attempt that failed.
        parts = auth_header.split()
        if len(parts) == 0:
            # Header is empty, treat as no credentials provided
            return None
        
        if len(parts) != 2:
            raise AuthenticationFailed(
                'Invalid Authorization header. Expected "Bearer <token>".'
            )

        auth_type, token = parts
        
        # Case 3: Incorrect token scheme.
        # This is also a failed authentication attempt.
        if auth_type.lower() != 'bearer':
            raise AuthenticationFailed(
                'Invalid token scheme. Expected "Bearer".'
            )
        
        # Case 4: The token itself is invalid (expired, bad signature, etc.).
        # get_user_from_token will return None for any invalid token.
        user = get_user_from_token(token)
        
        if not user:
            raise AuthenticationFailed('Invalid or expired token.')
            
        # Case 5: Success!
        # Return the user and the token to set request.user and request.auth.
        return (user, token)