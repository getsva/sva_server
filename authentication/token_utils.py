# authentication/token_utils.py

"""
Token Utilities for Zero-Knowledge Authentication

This module handles:
- Access token generation (JWT-like tokens)
- Refresh token generation and management
- Token validation and user retrieval

Security Notes:
- Access tokens are short-lived (15 minutes)
- Refresh tokens are long-lived (7 days) and stored in database
- Tokens use HMAC-SHA256 signatures
- User ID references ZKUser, not Django User
"""

import base64
import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

import jwt

from django.conf import settings

from .models import ZKRefreshToken, ZKUser


def generate_access_token(user):
    """
    Generates a custom, signed access token for a ZK user.
    
    Token format: header.payload.signature (JWT-like)
    
    Args:
        user: ZKUser instance
    
    Returns:
        str: Base64-encoded signed token
    
    Payload contains:
        - user_id: UUID of the ZKUser
        - exp: Expiration timestamp
        - iat: Issued at timestamp
        - type: Token type ('access')
    """
    # Calculate expiration time
    expiration = datetime.now(timezone.utc) + settings.ACCESS_TOKEN_LIFETIME
    issued_at = datetime.now(timezone.utc)
    
    payload = {
        'user_id': str(user.id),  # Convert UUID to string
        'exp': int(expiration.timestamp()),
        'iat': int(issued_at.timestamp()),
        'type': 'access',
    }
    
    # Create header
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_json = json.dumps(header, separators=(',', ':'))
    encoded_header = base64.urlsafe_b64encode(header_json.encode()).rstrip(b'=')
    
    # Encode payload
    payload_json = json.dumps(payload, separators=(',', ':'))
    encoded_payload = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b'=')
    
    # Create signature
    signature_input = encoded_header + b'.' + encoded_payload
    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        signature_input,
        hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    # Combine all parts
    token = f"{encoded_header.decode()}.{encoded_payload.decode()}.{encoded_signature.decode()}"
    
    return token


def generate_refresh_token(user, auth_method='master_key', device_fingerprint=None):
    """
    Generates and stores a new refresh token in the database.
    
    Refresh tokens are:
    - UUID-based (secure random)
    - Stored in database for validation
    - Long-lived (7 days by default)
    - Invalidated on logout
    - Track device fingerprint for session management
    
    Args:
        user: ZKUser instance
        auth_method: Authentication method used ('master_key' or 'passkey')
        device_fingerprint: SHA-256 hash of device fingerprint (optional)
    
    Returns:
        str: UUID string of the refresh token
    
    Note: Old refresh tokens for this user are deleted (single device login)
          Remove the delete() call below to allow multiple devices
    """
    # Invalidate any old refresh tokens for this user (optional)
    ZKRefreshToken.objects.filter(user=user).delete()
    
    # Create new refresh token with auth method and device fingerprint
    refresh_token = ZKRefreshToken.objects.create(
        user=user,
        auth_method=auth_method,
        device_fingerprint=device_fingerprint
    )
    
    return str(refresh_token.token)


def get_user_from_token(token_str):
    """
    Validates an access token and returns the corresponding ZK user.
    
    Validation steps:
    1. Parse token into header, payload, signature
    2. Verify signature matches (HMAC-SHA256)
    3. Check token hasn't expired
    4. Retrieve user from database
    5. Verify user is active
    
    Args:
        token_str: The access token string (JWT-like format)
    
    Returns:
        ZKUser instance if valid, None otherwise
    
    Security:
    - Uses constant-time comparison for signatures (prevents timing attacks)
    - Validates expiration timestamp
    - Checks user account status
    """
    try:
        # Split token into parts
        parts = token_str.split('.')
        if len(parts) != 3:
            return None
            
        encoded_header, encoded_payload, encoded_signature = parts
        
        # Recreate the signature to verify authenticity
        signature_input = encoded_header.encode() + b'.' + encoded_payload.encode()
        expected_signature = hmac.new(
            settings.SECRET_KEY.encode(),
            signature_input,
            hashlib.sha256
        ).digest()
        
        # Decode the received signature
        # Add padding if needed (base64 requires padding)
        padding = '=' * (4 - len(encoded_signature) % 4)
        decoded_signature = base64.urlsafe_b64decode(encoded_signature + padding)

        # Securely compare signatures to prevent timing attacks
        if not hmac.compare_digest(expected_signature, decoded_signature):
            return None
            
        # Decode and parse payload
        padding = '=' * (4 - len(encoded_payload) % 4)
        payload_bytes = base64.urlsafe_b64decode(encoded_payload + padding)
        payload = json.loads(payload_bytes)
        
        # Check expiration
        current_timestamp = datetime.now(timezone.utc).timestamp()
        if current_timestamp > payload['exp']:
            return None  # Token has expired
        
        # Verify token type
        if payload.get('type') != 'access':
            return None
            
        # Retrieve user from database
        user = ZKUser.objects.get(id=payload['user_id'])
        
        # Check if user account is active
        if not user.is_active:
            return None
        
        return user
        
    except (ValueError, KeyError, ZKUser.DoesNotExist, json.JSONDecodeError) as e:
        # Log the error if needed (but don't expose details to client)
        # logger.error(f"Token validation error: {str(e)}")
        return None
    except Exception as e:
        # Catch any other unexpected errors
        # logger.error(f"Unexpected token validation error: {str(e)}")
        return None


def validate_refresh_token(token_str):
    """
    Validates a refresh token and returns the associated user.
    
    Args:
        token_str: UUID string of the refresh token
    
    Returns:
        ZKUser instance if valid, None otherwise
    
    Note: This also checks token expiration
    """
    try:
        token = ZKRefreshToken.objects.get(token=token_str)
        
        # Check if expired
        if token.is_expired:
            token.delete()  # Clean up expired token
            return None
        
        # Check if user is active
        if not token.user.is_active:
            return None
        
        return token.user
        
    except ZKRefreshToken.DoesNotExist:
        return None


def revoke_refresh_token(token_str):
    """
    Revokes (deletes) a refresh token.
    Used during logout.
    
    Args:
        token_str: UUID string of the refresh token
    
    Returns:
        bool: True if token was revoked, False if not found
    """
    try:
        token = ZKRefreshToken.objects.get(token=token_str)
        token.delete()
        return True
    except ZKRefreshToken.DoesNotExist:
        return False


def revoke_all_user_tokens(user):
    """
    Revokes all refresh tokens for a specific user.
    Useful for "logout from all devices" functionality.
    
    Args:
        user: ZKUser instance
    
    Returns:
        int: Number of tokens revoked
    """
    count = ZKRefreshToken.objects.filter(user=user).count()
    ZKRefreshToken.objects.filter(user=user).delete()
    return count


def cleanup_expired_tokens():
    """
    Cleanup utility to remove expired refresh tokens from database.
    Should be run periodically (e.g., via cron job or Celery task).
    
    Returns:
        int: Number of expired tokens deleted
    """
    from django.utils import timezone
    expired_tokens = ZKRefreshToken.objects.filter(expires_at__lt=timezone.now())
    count = expired_tokens.count()
    expired_tokens.delete()
    return count


# Optional: Token blacklisting (for extra security)
class TokenBlacklist:
    """
    Simple in-memory token blacklist.
    In production, use Redis or database-backed solution.
    
    Usage:
        blacklist = TokenBlacklist()
        blacklist.add(token)
        if blacklist.is_blacklisted(token):
            # Reject token
    """
    def __init__(self):
        self._blacklist = set()
    
    def add(self, token):
        """Add token to blacklist"""
        self._blacklist.add(token)
    
    def is_blacklisted(self, token):
        """Check if token is blacklisted"""
        return token in self._blacklist
    
    def clear(self):
        """Clear all blacklisted tokens"""
        self._blacklist.clear()


# Global blacklist instance (in production, use Redis)
token_blacklist = TokenBlacklist()


def generate_data_token(user, claims, audience, auth_request_id, expires_in=None):
    """Generate a signed data token attesting to user claims for downstream clients."""

    if not isinstance(claims, dict):
        raise ValueError('claims must be a dictionary of asserted values')

    ttl_seconds = expires_in or settings.DATA_TOKEN_TTL_SECONDS
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)

    payload = {
        'iss': settings.DATA_TOKEN_ISSUER,
        'sub': str(user.id),
        'aud': audience,
        'iat': int(issued_at.timestamp()),
        'exp': int(expires_at.timestamp()),
        'claims': claims,
        'auth_request_id': str(auth_request_id),
    }

    token = jwt.encode(
        payload,
        settings.DATA_TOKEN_SECRET,
        algorithm=settings.DATA_TOKEN_ALGORITHM,
    )

    return token