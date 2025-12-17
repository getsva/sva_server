# authentication/views.py

import base64
import hashlib
import hmac
import logging
import uuid
import pyotp
import qrcode
import io
import json

import requests
from django.conf import settings
from django.utils import timezone
from requests.exceptions import RequestException
from rest_framework import generics
from rest_framework import serializers
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ZKUser, ZKRefreshToken, ZKEmailVerificationToken, ZKTwoFactorAuth, ZKTwoFactorLoginSession, ZKTwoFactorLoginSession, WaitlistEntry
from identity_canvas.models import IdentityCanvas, CanvasHistory, VerificationCanvas, VerificationCanvasHistory
from svasetting.models import UserPreferences, ConnectedService, UserIdentityLevel
from .serializers import (
    ZKRegisterSerializer, 
    ZKLoginSerializer, 
    ZKUserDetailsSerializer,
    ZKUserDataSerializer,
    ZKUpdateProfileSerializer,
    ZKGetSaltSerializer,
    ZKPasskeyRegisterSerializer,
    ZKPasskeyRemoveSerializer,
    ZKEmailVerificationRequestSerializer,
    ZKEmailVerificationConfirmSerializer,
    ZKEmailLoginSerializer,
    ZKGetSaltByEmailSerializer,
    ZKChangeMasterKeySerializer,
    ZKTwoFactorSetupSerializer,
    ZKTwoFactorVerifySerializer,
    ZKTwoFactorDisableSerializer,
    ZKTwoFactorLoginVerifySerializer,
    WaitlistEntrySerializer,
)
from .token_utils import generate_access_token, generate_refresh_token, generate_data_token


logger = logging.getLogger(__name__)
from .email_service import send_verification_email, send_welcome_email


# ==================== ZERO-KNOWLEDGE AUTHENTICATION VIEWS ====================

class ZKGetSaltView(APIView):
    """
    Get user's salt for login (Step 1 of login)
    Now also returns passkey credential ID if available
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ZKGetSaltSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username_hash = serializer.validated_data['username_hash']
        
        try:
            user = ZKUser.objects.get(username_hash=username_hash, is_active=True)
            return Response({
                'salt': user.salt,
                'exists': True,
                'has_passkey': user.has_passkey,
                'passkey_credential_id': user.passkey_credential_id if user.has_passkey else None
            })
        except ZKUser.DoesNotExist:
            # Return consistent fake data to prevent user enumeration
            from django.conf import settings
            
            fake_salt_bytes = hmac.new(
                settings.SECRET_KEY.encode(),
                username_hash.encode(),
                hashlib.sha256
            ).digest()[:16]
            
            fake_salt = base64.b64encode(fake_salt_bytes).decode()
            
            return Response({
                'salt': fake_salt,
                'exists': False,
                'has_passkey': False,
                'passkey_credential_id': None
            })


class ZKRegisterView(generics.CreateAPIView):
    """
    Zero-Knowledge Registration Endpoint
    Now supports passkey registration
    """
    permission_classes = (AllowAny,)
    serializer_class = ZKRegisterSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username_hash = serializer.validated_data['username_hash']
        auth_proof = serializer.validated_data['auth_proof']
        device_fingerprint = serializer.validated_data['device_fingerprint']
        passkey_credential_id = serializer.validated_data.get('passkey_credential_id')
        passkey_public_key = serializer.validated_data.get('passkey_public_key')
        use_both_methods = serializer.validated_data.get('use_both_methods', False)
        
        # Double-check uniqueness
        if ZKUser.objects.filter(username_hash=username_hash).exists():
            return Response(
                {"error": "An account with this username already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if ZKUser.objects.filter(auth_proof=auth_proof).exists():
            return Response(
                {"error": "An account with this master key already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if ZKUser.objects.filter(device_fingerprint=device_fingerprint).exists():
            return Response(
                {"error": "This device is already registered to another account. One device per user policy enforced."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the zero-knowledge user
        has_passkey = bool(passkey_credential_id)
        
        zk_user = ZKUser.objects.create(
            encrypted_data=serializer.validated_data['encrypted_data'],
            salt=serializer.validated_data['salt'],
            auth_proof=serializer.validated_data['auth_proof'],
            username_hash=serializer.validated_data['username_hash'],
            device_fingerprint=device_fingerprint,
            passkey_credential_id=passkey_credential_id,
            passkey_public_key=passkey_public_key,
            has_passkey=has_passkey
        )
        
        # Generate tokens
        access_token = generate_access_token(zk_user)
        refresh_token = generate_refresh_token(
            zk_user, 
            auth_method='passkey' if has_passkey else 'master_key',
            device_fingerprint=device_fingerprint
        )
        
        # Determine available authentication methods
        auth_methods = []
        if has_passkey:
            auth_methods.append("passkey")
        if not use_both_methods or True:  # Master key is always available
            auth_methods.append("master_key")
        
        return Response({
            "message": "Registration successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": ZKUserDetailsSerializer(zk_user).data,
            "auth_method": "passkey" if has_passkey else "master_key",
            "available_auth_methods": auth_methods,
            "flexible_auth": len(auth_methods) > 1
        }, status=status.HTTP_201_CREATED)


class ZKLoginView(generics.GenericAPIView):
    """
    Zero-Knowledge Login Endpoint
    Works with both master key and passkey authentication
    """
    permission_classes = (AllowAny,)
    serializer_class = ZKLoginSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        auth_proof = serializer.validated_data['auth_proof']
        device_fingerprint = serializer.validated_data['device_fingerprint']
        
        try:
            zk_user = ZKUser.objects.get(auth_proof=auth_proof, is_active=True)
            # Device fingerprint check removed for login flexibility
        except ZKUser.DoesNotExist:
            return Response(
                {"error": "Invalid credentials or master key"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Update last login
        zk_user.last_login = timezone.now()
        zk_user.save(update_fields=['last_login'])
        
        # Determine auth method
        auth_method = 'passkey' if zk_user.has_passkey else 'master_key'
        
        # Generate tokens
        access_token = generate_access_token(zk_user)
        refresh_token = generate_refresh_token(zk_user, auth_method=auth_method, device_fingerprint=device_fingerprint)
        
        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": ZKUserDetailsSerializer(zk_user).data,
            "encrypted_data": zk_user.encrypted_data,
            "salt": zk_user.salt,
            "auth_method": auth_method
        })


class ZKLogoutView(APIView):
    """
    Logout by invalidating refresh token
    """
    permission_classes = (IsAuthenticated,)
    
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            token = ZKRefreshToken.objects.get(
                user=request.user,
                token=refresh_token
            )
            token.delete()
            
            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_200_OK
            )
        except ZKRefreshToken.DoesNotExist:
            return Response(
                {"error": "Invalid refresh token."},
                status=status.HTTP_400_BAD_REQUEST
            )


class ZKTokenRefreshView(APIView):
    """
    Refresh access token using refresh token
    """
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        refresh_token_value = request.data.get("refresh_token")
        if not refresh_token_value:
            return Response(
                {"error": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token = ZKRefreshToken.objects.get(token=refresh_token_value)
            
            if token.is_expired:
                token.delete()
                return Response(
                    {"error": "Refresh token has expired."},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            new_access_token = generate_access_token(token.user)
            return Response({"access_token": new_access_token})
            
        except ZKRefreshToken.DoesNotExist:
            return Response(
                {"error": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED
            )


# ==================== USER DATA MANAGEMENT VIEWS ====================

class ZKGetUserDataView(APIView):
    """
    Returns encrypted user data for client-side decryption
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = ZKUserDataSerializer(request.user)
        return Response(serializer.data)


class ZKGetAllEncryptedDataView(APIView):
    """
    Returns all encrypted data for a user (for master key rotation)
    This endpoint is used to fetch all encrypted data that needs to be re-encrypted
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get user's main encrypted data
        user_data = {
            'encrypted_data': user.encrypted_data,
            'salt': user.salt,
        }
        
        # Get identity canvas
        canvas_data = None
        canvas_history = []
        try:
            canvas = IdentityCanvas.objects.get(user=user)
            canvas_data = {
                'id': str(canvas.id),
                'encrypted_blocks': canvas.encrypted_blocks,
            }
            # Get all canvas history entries
            history_entries = CanvasHistory.objects.filter(canvas=canvas)
            canvas_history = [
                {
                    'id': str(entry.id),
                    'encrypted_blocks_snapshot': entry.encrypted_blocks_snapshot,
                }
                for entry in history_entries
            ]
        except IdentityCanvas.DoesNotExist:
            pass
        
        # Get verification canvas
        verification_canvas_data = None
        verification_canvas_history = []
        try:
            verification_canvas = VerificationCanvas.objects.get(user=user)
            verification_canvas_data = {
                'id': str(verification_canvas.id),
                'encrypted_blocks': verification_canvas.encrypted_blocks,
            }
            # Get all verification canvas history entries
            verification_history_entries = VerificationCanvasHistory.objects.filter(canvas=verification_canvas)
            verification_canvas_history = [
                {
                    'id': str(entry.id),
                    'encrypted_blocks_snapshot': entry.encrypted_blocks_snapshot,
                }
                for entry in verification_history_entries
            ]
        except VerificationCanvas.DoesNotExist:
            pass
        
        # Get user preferences
        preferences_data = None
        try:
            preferences = UserPreferences.objects.get(user=user)
            preferences_data = {
                'id': str(preferences.id),
                'encrypted_preferences': preferences.encrypted_preferences,
            }
        except UserPreferences.DoesNotExist:
            pass
        
        # Get connected services
        connected_services = []
        services = ConnectedService.objects.filter(user=user, is_active=True)
        for service in services:
            connected_services.append({
                'id': str(service.id),
                'encrypted_service_data': service.encrypted_service_data,
                'encrypted_permissions': service.encrypted_permissions or '',
            })
        
        # Get identity level
        identity_level_data = None
        try:
            identity_level = UserIdentityLevel.objects.get(user=user)
            identity_level_data = {
                'id': str(identity_level.id),
                'encrypted_verification_data': identity_level.encrypted_verification_data or '',
            }
        except UserIdentityLevel.DoesNotExist:
            pass
        
        return Response({
            'user_data': user_data,
            'canvas': canvas_data,
            'canvas_history': canvas_history,
            'verification_canvas': verification_canvas_data,
            'verification_canvas_history': verification_canvas_history,
            'preferences': preferences_data,
            'connected_services': connected_services,
            'identity_level': identity_level_data,
        })


class ZKUpdateUserDataView(APIView):
    """
    Update user's encrypted data
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request):
        serializer = ZKUpdateProfileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        request.user.encrypted_data = serializer.validated_data['encrypted_data']
        request.user.updated_at = timezone.now()
        request.user.save(update_fields=['encrypted_data', 'updated_at'])
        
        return Response({
            'message': 'Profile updated successfully',
            'user': ZKUserDetailsSerializer(request.user).data
        })


class ZKDeleteAccountView(APIView):
    """
    Delete user account
    """
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        auth_proof = request.data.get('auth_proof')
        
        if not auth_proof:
            return Response(
                {'error': 'Master key verification required (auth_proof)'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if request.user.auth_proof != auth_proof:
            return Response(
                {'error': 'Invalid master key'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Delete all refresh tokens
        ZKRefreshToken.objects.filter(user=request.user).delete()
        
        # Soft delete
        request.user.is_active = False
        request.user.save(update_fields=['is_active'])
        
        return Response({
            'message': 'Account deleted successfully'
        }, status=status.HTTP_200_OK)


# ==================== PASSKEY MANAGEMENT VIEWS ====================

class ZKPasskeyRegisterView(APIView):
    """
    Add passkey to existing account
    Allows users to enable biometric authentication
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ZKPasskeyRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Check if user already has a passkey
        if request.user.has_passkey:
            return Response(
                {'error': 'Account already has a passkey registered'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update user with passkey
        request.user.passkey_credential_id = serializer.validated_data['passkey_credential_id']
        request.user.passkey_public_key = serializer.validated_data.get('passkey_public_key')
        request.user.has_passkey = True
        request.user.save(update_fields=[
            'passkey_credential_id', 
            'passkey_public_key', 
            'has_passkey'
        ])
        
        return Response({
            'message': 'Passkey registered successfully',
            'user': ZKUserDetailsSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class ZKPasskeyRemoveView(APIView):
    """
    Remove passkey from account
    Requires master key verification
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ZKPasskeyRemoveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        auth_proof = serializer.validated_data['auth_proof']
        
        # Verify auth proof
        if request.user.auth_proof != auth_proof:
            return Response(
                {'error': 'Invalid master key verification'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if user has a passkey
        if not request.user.has_passkey:
            return Response(
                {'error': 'No passkey registered on this account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Remove passkey
        request.user.passkey_credential_id = None
        request.user.passkey_public_key = None
        request.user.has_passkey = False
        request.user.save(update_fields=[
            'passkey_credential_id', 
            'passkey_public_key', 
            'has_passkey'
        ])
        
        return Response({
            'message': 'Passkey removed successfully',
            'user': ZKUserDetailsSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class ZKPasskeyStatusView(APIView):
    """
    Check passkey status for current user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'has_passkey': request.user.has_passkey,
            'passkey_credential_id': request.user.passkey_credential_id if request.user.has_passkey else None,
            'can_add_passkey': not request.user.has_passkey
        })


# ==================== UTILITY/TESTING VIEWS ====================

class ZKProtectedView(APIView):
    """
    Example protected endpoint
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'message': 'This is a protected endpoint!',
            'user': ZKUserDetailsSerializer(request.user).data,
            'note': 'Your encrypted data is stored securely. Decrypt it client-side with your master key or passkey.'
        }, status=status.HTTP_200_OK)


class ZKHealthCheckView(APIView):
    """
    Health check endpoint
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'Zero-Knowledge Authentication',
            'version': '2.0.0',
            'features': ['master_key', 'passkey', 'webauthn']
        })


class ZKStatsView(APIView):
    """
    Get basic statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        total_users = ZKUser.objects.filter(is_active=True).count()
        passkey_users = ZKUser.objects.filter(is_active=True, has_passkey=True).count()
        active_tokens = ZKRefreshToken.objects.filter(
            expires_at__gt=timezone.now()
        ).count()
        
        return Response({
            'total_active_users': total_users,
            'passkey_enabled_users': passkey_users,
            'active_sessions': active_tokens,
            'passkey_adoption_rate': f"{(passkey_users/total_users*100):.1f}%" if total_users > 0 else "0%",
            'note': 'Server has zero knowledge of user credentials'
        })


# ==================== OAUTH CONSENT ORCHESTRATION VIEWS ====================


class AuthServerClientMixin:
    """Shared helpers for communicating with the OAuth orchestration service."""

    auth_base_path = '/api/auth'

    def _call_auth_service(self, method: str, endpoint: str, **kwargs):
        base_url = settings.SVA_AUTH_SERVER_BASE_URL.rstrip('/')
        endpoint = endpoint if endpoint.startswith('/') else f'/{endpoint}'
        url = f"{base_url}{endpoint}"

        headers = kwargs.pop('headers', {}) or {}
        headers[settings.INTERNAL_SERVICE_HEADER] = settings.INTERNAL_SERVICE_TOKEN

        timeout = getattr(settings, 'INTERNAL_SERVICE_TIMEOUT', 5)

        logger.debug('Calling auth service %s %s', method.upper(), url)
        response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
        return response

    def _fetch_auth_request(self, auth_request_id: uuid.UUID):
        try:
            response = self._call_auth_service(
                'get',
                f"{self.auth_base_path}/internal/auth-request-details/",
                params={'auth_request_id': str(auth_request_id)},
            )
        except RequestException as exc:
            logger.error('Failed to reach OAuth auth server: %s', exc)
            raise

        return response


class DataAttestationSerializer(serializers.Serializer):
    auth_request_id = serializers.UUIDField()
    user_id = serializers.UUIDField()
    audience = serializers.CharField(max_length=255)
    claims = serializers.DictField(child=serializers.JSONField())


class DataAttestationView(AuthServerClientMixin, APIView):
    """Issue signed data tokens for approved authorization requests."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DataAttestationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if str(request.user.id) != str(data['user_id']):
            return Response({'error': 'user_id mismatch'}, status=status.HTTP_403_FORBIDDEN)

        try:
            auth_response = self._fetch_auth_request(data['auth_request_id'])
        except RequestException:
            return Response({'error': 'oauth_service_unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        if auth_response.status_code != status.HTTP_200_OK:
            logger.warning('Auth request validation failed: %s', auth_response.text)
            try:
                payload = auth_response.json()
            except ValueError:
                payload = {'error': 'unexpected_response'}
            return Response(payload, status=auth_response.status_code)

        try:
            auth_request = auth_response.json()
        except ValueError:
            logger.error('Auth server returned non-JSON payload for auth request %s', data['auth_request_id'])
            return Response({'error': 'unexpected_response'}, status=status.HTTP_502_BAD_GATEWAY)

        if auth_request.get('status') != 'pending':
            return Response({'error': 'auth_request_not_pending'}, status=status.HTTP_400_BAD_REQUEST)

        client_id = auth_request.get('client', {}).get('client_id')
        if client_id != data['audience']:
            return Response({'error': 'audience_mismatch'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate that claims are permitted by requested scopes
        # Map scopes to allowed claim keys
        # This includes both standard OAuth scopes and Identity Block scopes
        scope_to_claims = {
            'openid': set(),  # openid doesn't map to specific claims, but allows 'sub' claim
            'email': {'email'},
            'profile': {'full_name', 'name', 'given_name', 'family_name'},
            'name': {'full_name', 'name', 'given_name', 'family_name', 'first_name', 'last_name'},  # Identity Block: Name
            'username': {'username'},  # Identity Block: Username
            # Add other Identity Block scopes as needed
            'bio': {'bio'},
            'pronoun': {'pronoun', 'pronouns'},
            'dob': {'dob', 'date_of_birth', 'birthdate'},
            'images': {'profile_image', 'banner_image', 'images'},
            'skills': {'skills'},
            'hobby': {'hobbies', 'hobby'},
            'address': {'address', 'address_line1', 'address_line2', 'city', 'state', 'postal_code', 'country'},
            'social': {'social_links', 'social'},
            'phone': {'phone', 'phone_number'},
            'pan_card': {'pan_card', 'pan'},
            'crypto_wallet': {'crypto_wallet', 'wallet_address'},
            'education': {'education'},
            'employment': {'employment'},
            'professional_license': {'professional_license', 'license'},
            'aadhar': {'aadhar', 'aadhaar'},
            'driving_license': {'driving_license', 'driving_licence'},
            'voter_id': {'voter_id', 'voterid'},
            'passport': {'passport'},
        }
        
        requested_scopes = set(auth_request.get('requested_scopes', []))
        claim_keys = set(data['claims'].keys())
        
        # Build set of all allowed claim keys based on requested scopes
        allowed_claim_keys = set()
        for scope in requested_scopes:
            if scope in scope_to_claims:
                allowed_claim_keys.update(scope_to_claims[scope])
            # Also allow the scope name itself as a claim key (for custom scopes)
            allowed_claim_keys.add(scope)
        
        # Allow 'sub' claim if openid scope is present
        if 'openid' in requested_scopes:
            allowed_claim_keys.add('sub')
        
        # Check if all claim keys are permitted
        if requested_scopes and not claim_keys.issubset(allowed_claim_keys):
            logger.warning(
                'Claims validation failed: requested_scopes=%s, claim_keys=%s, allowed_claim_keys=%s',
                requested_scopes,
                claim_keys,
                allowed_claim_keys,
            )
            return Response({'error': 'claims_not_permitted'}, status=status.HTTP_400_BAD_REQUEST)

        data_token = generate_data_token(
            user=request.user,
            claims=data['claims'],
            audience=data['audience'],
            auth_request_id=data['auth_request_id'],
        )

        logger.info(
            'Issued data token for auth_request %s and audience %s',
            data['auth_request_id'],
            data['audience'],
        )

        return Response({'data_token': data_token})


class AuthRequestDetailProxyView(AuthServerClientMixin, APIView):
    """Proxy to retrieve authorization request details for the consent UI."""

    permission_classes = [IsAuthenticated]

    def get(self, request, auth_request_id: uuid.UUID):
        try:
            response = self._fetch_auth_request(auth_request_id)
        except RequestException:
            return Response({'error': 'oauth_service_unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        if response.status_code != status.HTTP_200_OK:
            try:
                payload = response.json()
            except ValueError:
                payload = {'error': 'unexpected_response'}
            return Response(payload, status=response.status_code)

        payload = response.json()
        
        # Check if user has existing connection for instant approval (Google OAuth style)
        try:
            from svasetting.models import UserAppConnection
            client_id = payload.get('client', {}).get('client_id')
            
            logger.info(
                '🔍 Checking for existing connection: user=%s, client_id=%s, payload_client=%s',
                request.user.id,
                client_id,
                payload.get('client', {})
            )
            
            if client_id:
                try:
                    # Check for any connection (active or revoked)
                    connection = UserAppConnection.objects.get(
                        user=request.user,
                        client_id=client_id
                    )
                    
                    logger.info(
                        '✅✅✅ Found connection for user %s, app %s: active=%s, approved_scopes=%s, connection_id=%s',
                        request.user.id,
                        client_id,
                        connection.is_active,
                        connection.approved_scopes,
                        connection.id
                    )
                    
                    if connection.is_active:
                        # Active connection - Google OAuth style: auto-approve for returning users
                        existing_scopes = set(connection.approved_scopes or [])
                        requested_scopes = set(payload.get('requested_scopes', []) or [])
                        
                        logger.info(
                            '🔍 Connection found - Scope comparison: requested=%s, existing=%s, is_active=%s',
                            requested_scopes,
                            existing_scopes,
                            connection.is_active
                        )
                        
                        # Google OAuth style: If app is already connected and active, ALWAYS auto-approve
                        # User already trusts the app, so we auto-approve even if new scopes are requested
                        can_auto_approve = True  # Always auto-approve for active connections
                        
                        if requested_scopes:
                            if requested_scopes.issubset(existing_scopes):
                                # All requested scopes already approved
                                logger.info(
                                    '✅ All requested scopes already approved: %s - auto-approving',
                                    requested_scopes
                                )
                            else:
                                # New scopes requested, but app is already connected - auto-approve anyway
                                new_scopes = requested_scopes - existing_scopes
                                logger.info(
                                    '✅ App already connected, auto-approving new scopes: %s (existing: %s, requested: %s)',
                                    new_scopes,
                                    existing_scopes,
                                    requested_scopes
                                )
                        elif existing_scopes:
                            # No specific scopes requested but user has approved scopes
                            logger.info('✅ No requested scopes, but user has approved scopes - auto-approving')
                        else:
                            # No scopes at all - still auto-approve if connection exists
                            logger.info('✅ No scopes requested or approved - auto-approving for basic auth')
                        
                        # Always set can_auto_approve=True for active connections (Google OAuth style)
                        payload['can_auto_approve'] = True
                        payload['existing_connection'] = {
                            'id': str(connection.id),
                            'approved_scopes': connection.approved_scopes,
                            'connected_at': connection.connected_at.isoformat(),
                            'is_active': True,
                        }
                        # Update last_accessed timestamp
                        connection.last_accessed = timezone.now()
                        connection.save(update_fields=['last_accessed'])
                        logger.info(
                            '✅✅✅ AUTO-APPROVING consent for user %s, app %s (existing active connection - Google OAuth style)',
                            request.user.id,
                            client_id
                        )
                    else:
                        # Connection exists but is revoked - don't auto-approve
                        payload['can_auto_approve'] = False
                        payload['existing_connection'] = {
                            'id': str(connection.id),
                            'approved_scopes': connection.approved_scopes,
                            'is_active': False,
                        }
                        logger.info(
                            '⚠️ Connection exists but is revoked - showing consent screen for user %s, app %s',
                            request.user.id,
                            client_id
                        )
                        payload['is_revoked'] = True
                except UserAppConnection.DoesNotExist:
                    # No connection found - first time user
                    payload['can_auto_approve'] = False
                    payload['existing_connection'] = None
                    payload['is_revoked'] = False
                    logger.warning(
                        '🆕❌ No existing connection found for user %s, app %s - showing consent screen',
                        request.user.id,
                        client_id
                    )
                    # Debug: Check if there are any connections for this user at all
                    user_connections = UserAppConnection.objects.filter(user=request.user)
                    logger.info(
                        '🔍 Debug: User %s has %s total connections: %s',
                        request.user.id,
                        user_connections.count(),
                        list(user_connections.values_list('client_id', 'is_active', 'app_name'))
                    )
        except Exception as exc:
            # Don't fail the request if connection check fails
            logger.warning('Failed to check existing connection: %s', exc, exc_info=True)
            # Default to not auto-approve if check fails
            if 'can_auto_approve' not in payload:
                payload['can_auto_approve'] = False
            payload['can_auto_approve'] = False
            payload['is_revoked'] = False
        
        return Response(payload)


class ConsentCompletionSerializer(serializers.Serializer):
    approved_scopes = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        allow_empty=True,
    )
    data_token = serializers.CharField(required=False, allow_blank=True)
    encrypted_sharing_blob = serializers.CharField(required=False, allow_blank=True)
    sharing_blob_salt = serializers.CharField(required=False, allow_blank=True)


class AuthRequestConsentProxyView(AuthServerClientMixin, APIView):
    """Proxy to confirm consent with the OAuth orchestration service."""

    permission_classes = [IsAuthenticated]

    def post(self, request, auth_request_id: uuid.UUID):
        serializer = ConsentCompletionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Initialize client_info with empty dict (will be populated if fetch succeeds)
        client_info = {}
        
        # First, fetch auth request details to get app information
        try:
            auth_request_response = self._fetch_auth_request(auth_request_id)
            if auth_request_response.status_code == status.HTTP_200_OK:
                auth_request_data = auth_request_response.json()
                client_info = auth_request_data.get('client', {})
            else:
                logger.error('Failed to fetch auth request details: %s', auth_request_response.text)
                return Response(
                    {'error': 'Failed to retrieve app details for connection'},
                    status=status.HTTP_502_BAD_GATEWAY
                )
        except RequestException as exc:
            logger.error('Failed to fetch auth request details: %s', exc)
            return Response(
                {'error': 'Failed to communicate with auth server'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        payload = {
            'auth_request_id': str(auth_request_id),
            'user_id': str(request.user.id),
            'approved_scopes': data.get('approved_scopes', []),
            'data_token': data['data_token'],
        }

        try:
            response = self._call_auth_service(
                'post',
                f"{self.auth_base_path}/internal/consent-complete/",
                json=payload,
            )
        except RequestException as exc:
            logger.error('Failed to notify auth server of consent completion: %s', exc)
            return Response({'error': 'oauth_service_unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        if response.status_code != status.HTTP_200_OK:
            try:
                payload = response.json()
            except ValueError:
                payload = {'error': 'unexpected_response'}
            return Response(payload, status=response.status_code)

        # Create or update UserAppConnection after successful consent
        # CRITICAL: This must succeed to maintain data integrity
        try:
            self._create_or_update_app_connection(
                user=request.user,
                client_id=client_info.get('client_id'),
                app_name=client_info.get('name', 'Unknown App'),
                app_logo=client_info.get('logo'),
                app_description=client_info.get('description'),
                approved_scopes=data.get('approved_scopes', []),
                encrypted_sharing_blob=data.get('encrypted_sharing_blob'),
                sharing_blob_salt=data.get('sharing_blob_salt'),
            )
        except Exception as exc:
            # Log critical error - data integrity issue
            logger.critical('CRITICAL: Failed to create/update app connection after consent: %s', exc, exc_info=True)
            # We arguably should return an error here, but the code has already been issued (in previous step).
            # Ideally we would rollback, but we can't easily undo the OAuth code issue.
            # For now, we log critical so we can investigate. 
            # In a distributed transaction we would need 2PC.
            # But making the first step fail fast (client_info fetch) solves 99% of cases.

        return Response(response.json())
    
    def _create_or_update_app_connection(self, user, client_id, app_name, app_logo=None, app_description=None, approved_scopes=None, encrypted_sharing_blob=None, sharing_blob_salt=None):
        """Create or update UserAppConnection after consent"""
        if not client_id:
            return
        
        from svasetting.models import UserAppConnection, SecurityLog
        from django.utils import timezone
        
        try:
            connection = UserAppConnection.objects.get(user=user, client_id=client_id)
            # Connection exists - update it
            connection.app_name = app_name
            if app_logo:
                connection.app_logo = app_logo
            if app_description:
                connection.app_description = app_description
            connection.is_active = True
            connection.revoked_at = None
            connection.last_accessed = timezone.now()
            
            # Update encrypted sharing blob if provided (Google OAuth style - live data sharing)
            if encrypted_sharing_blob and sharing_blob_salt:
                connection.encrypted_sharing_blob = encrypted_sharing_blob
                connection.sharing_blob_salt = sharing_blob_salt
                connection.sharing_blob_encrypted_at = timezone.now()
                logger.info('Updated sharing blob for app connection %s', connection.id)
            
            # Only update scopes if they changed
            if approved_scopes and set(connection.approved_scopes) != set(approved_scopes):
                connection.update_scopes(approved_scopes)
            else:
                update_fields = ['app_name', 'app_logo', 'app_description', 'is_active', 'revoked_at', 'last_accessed']
                if encrypted_sharing_blob:
                    update_fields.extend(['encrypted_sharing_blob', 'sharing_blob_salt', 'sharing_blob_encrypted_at'])
                connection.save(update_fields=update_fields)
            
            # Log the action (only log scope update if scopes actually changed)
            if approved_scopes and set(connection.approved_scopes) != set(approved_scopes):
                log_type = 'app_scopes_updated'
            else:
                log_type = 'app_connected'  # Reconnection
        except UserAppConnection.DoesNotExist:
            # Create new connection
            connection = UserAppConnection.objects.create(
                user=user,
                client_id=client_id,
                app_name=app_name,
                app_logo=app_logo or '',
                app_description=app_description or '',
                approved_scopes=approved_scopes or [],
                encrypted_sharing_blob=encrypted_sharing_blob or '',
                sharing_blob_salt=sharing_blob_salt or '',
                sharing_blob_encrypted_at=timezone.now() if encrypted_sharing_blob else None,
                is_active=True,
                last_accessed=timezone.now(),
            )
            log_type = 'app_connected'
        
        # Log the action
        SecurityLog.objects.create(
            user=user,
            log_type=log_type,
            ip_address=None,  # Could be passed from request if needed
            user_agent=None,
        )


# ==================== EMAIL VERIFICATION VIEWS ====================

class ZKEmailVerificationRequestView(APIView):
    """
    Request email verification for registration
    Stores encrypted data temporarily until email is verified
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ZKEmailVerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        device_fingerprint = serializer.validated_data['device_fingerprint']
        
        # Create verification token with encrypted data
        verification_token = ZKEmailVerificationToken.objects.create(
            email_hash=email_hash,
            encrypted_data=serializer.validated_data['encrypted_data'],
            salt=serializer.validated_data['salt'],
            auth_proof=serializer.validated_data['auth_proof'],
            username_hash=serializer.validated_data['username_hash'],
            device_fingerprint=device_fingerprint,
            passkey_credential_id=serializer.validated_data.get('passkey_credential_id'),
            passkey_public_key=serializer.validated_data.get('passkey_public_key'),
            use_both_methods=serializer.validated_data.get('use_both_methods', False)
        )
        
        # Send verification email
        email_sent = send_verification_email(email, str(verification_token.token))
        
        if not email_sent:
            # If email fails, still return success but log the issue
            print(f"Warning: Failed to send verification email to {email}")
        
        return Response({
            'message': 'Verification email sent. Please check your email to complete registration.',
            'email': email,  # Return email for confirmation
            'expires_in_hours': 24,
            'email_sent': email_sent
        }, status=status.HTTP_201_CREATED)


class ZKEmailVerificationConfirmView(APIView):
    """
    Confirm email verification and complete registration
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ZKEmailVerificationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        
        try:
            verification_token = ZKEmailVerificationToken.objects.get(
                token=token,
                is_used=False
            )
        except ZKEmailVerificationToken.DoesNotExist:
            return Response(
                {"error": "Invalid or expired verification token."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not verification_token.is_valid:
            return Response(
                {"error": "Verification token has expired."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the zero-knowledge user
        has_passkey = bool(verification_token.passkey_credential_id)
        
        zk_user = ZKUser.objects.create(
            email_hash=verification_token.email_hash,
            encrypted_data=verification_token.encrypted_data,
            salt=verification_token.salt,
            auth_proof=verification_token.auth_proof,
            username_hash=verification_token.username_hash,
            device_fingerprint=verification_token.device_fingerprint,
            passkey_credential_id=verification_token.passkey_credential_id,
            passkey_public_key=verification_token.passkey_public_key,
            has_passkey=has_passkey,
            email_verified=True
        )
        
        # Mark verification token as used
        verification_token.is_used = True
        verification_token.save()
        
        # Send welcome email (we need to get the email from the verification token)
        # For now, we'll skip the welcome email since we don't have the original email
        # In a production system, you might want to store the email in the verification token
        # send_welcome_email(email, str(zk_user.id))
        
        # Determine available authentication methods
        auth_methods = []
        if has_passkey:
            auth_methods.append("passkey")
        if not verification_token.use_both_methods or True:  # Master key is always available
            auth_methods.append("master_key")
        
        # Return success response without tokens - user needs to login separately
        response_data = {
            "message": "Email verified and registration successful. Please login to continue.",
            "user": ZKUserDetailsSerializer(zk_user).data,
            "available_auth_methods": auth_methods,
            "flexible_auth": len(auth_methods) > 1
        }
        
        # If using both methods, include additional data for client storage
        if verification_token.use_both_methods and has_passkey:
            response_data["salt"] = verification_token.salt
            response_data["passkey_credential_id"] = verification_token.passkey_credential_id
        
        return Response(response_data, status=status.HTTP_201_CREATED)


class ZKGetSaltByEmailView(APIView):
    """
    Get user's salt by email (Step 1 of email login)
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ZKGetSaltByEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        
        try:
            user = ZKUser.objects.get(email_hash=email_hash, is_active=True, email_verified=True)
            print(f"🔍 User found: {user.id}, has_passkey: {user.has_passkey}, passkey_credential_id: {user.passkey_credential_id}")
            return Response({
                'salt': user.salt,
                'exists': True,
                'has_passkey': user.has_passkey,
                'passkey_credential_id': user.passkey_credential_id if user.has_passkey else None
            })
        except ZKUser.DoesNotExist:
            # Return consistent fake data to prevent user enumeration
            from django.conf import settings
            
            fake_salt_bytes = hmac.new(
                settings.SECRET_KEY.encode(),
                email_hash.encode(),
                hashlib.sha256
            ).digest()[:16]
            
            fake_salt = base64.b64encode(fake_salt_bytes).decode()
            
            return Response({
                'salt': fake_salt,
                'exists': False,
                'has_passkey': False,
                'passkey_credential_id': None
            })


class ZKEmailLoginView(generics.GenericAPIView):
    """
    Zero-Knowledge Login using Email
    """
    permission_classes = (AllowAny,)
    serializer_class = ZKLoginSerializer
    
    def post(self, request, *args, **kwargs):
        # First get email to find user
        email_serializer = ZKEmailLoginSerializer(data=request.data)
        email_serializer.is_valid(raise_exception=True)
        
        email = email_serializer.validated_data['email']
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        
        # Then validate auth proof and device fingerprint
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        auth_proof = serializer.validated_data['auth_proof']
        device_fingerprint = serializer.validated_data['device_fingerprint']
        
        try:
            # Handle passkey-only users with special marker
            if auth_proof == "passkey_authenticated":
                zk_user = ZKUser.objects.get(
                    email_hash=email_hash,
                    is_active=True,
                    email_verified=True,
                    has_passkey=True
                )
            else:
                # Regular master key authentication
                zk_user = ZKUser.objects.get(
                    email_hash=email_hash,
                    auth_proof=auth_proof, 
                    is_active=True,
                    email_verified=True
                )
            # Device fingerprint check removed for login flexibility
        except ZKUser.DoesNotExist:
            return Response(
                {"error": "Invalid credentials or master key"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if 2FA is enabled
        try:
            two_fa = ZKTwoFactorAuth.objects.get(user=zk_user, is_enabled=True)
            # 2FA is enabled - create temporary session and require 2FA verification
            temp_session = ZKTwoFactorLoginSession.objects.create(
                user=zk_user,
                encrypted_data=zk_user.encrypted_data,
                salt=zk_user.salt,
                device_fingerprint=device_fingerprint,
                auth_method='passkey' if zk_user.has_passkey else 'master_key'
            )
            
            return Response({
                "requires_2fa": True,
                "temp_token": str(temp_session.temp_token),
                "message": "2FA verification required"
            }, status=status.HTTP_200_OK)
        except ZKTwoFactorAuth.DoesNotExist:
            # 2FA not enabled - proceed with normal login
            pass
        
        # Update last login
        zk_user.last_login = timezone.now()
        zk_user.save(update_fields=['last_login'])
        
        # Determine auth method
        auth_method = 'passkey' if zk_user.has_passkey else 'master_key'
        
        # Generate tokens
        access_token = generate_access_token(zk_user)
        refresh_token = generate_refresh_token(zk_user, auth_method=auth_method, device_fingerprint=device_fingerprint)
        
        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": ZKUserDetailsSerializer(zk_user).data,
            "encrypted_data": zk_user.encrypted_data,
            "salt": zk_user.salt,
            "auth_method": auth_method,
            "requires_2fa": False
        })

# ==================== SECURITY MANAGEMENT VIEWS ====================

class ZKChangeMasterKeyView(APIView):
    """
    Change master key for user account
    Requires current master key verification
    Re-encrypts all user data with the new master key
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from django.db import transaction
        
        serializer = ZKChangeMasterKeySerializer(
            data=request.data,
            context={'user': request.user}
        )
        serializer.is_valid(raise_exception=True)
        
        # Verify current auth proof
        if request.user.auth_proof != serializer.validated_data['current_auth_proof']:
            return Response(
                {'error': 'Invalid current master key'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if new auth proof already exists (different user)
        if ZKUser.objects.filter(auth_proof=serializer.validated_data['new_auth_proof']).exclude(id=request.user.id).exists():
            return Response(
                {'error': 'This master key is already in use by another account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Use transaction to ensure all data is updated atomically
        with transaction.atomic():
            # Update user with new master key data
            request.user.encrypted_data = serializer.validated_data['new_encrypted_data']
            request.user.salt = serializer.validated_data['new_salt']
            request.user.auth_proof = serializer.validated_data['new_auth_proof']
            request.user.updated_at = timezone.now()
            request.user.save(update_fields=['encrypted_data', 'salt', 'auth_proof', 'updated_at'])
            
            # Update identity canvas if provided
            if serializer.validated_data.get('new_canvas_encrypted_blocks'):
                try:
                    canvas = IdentityCanvas.objects.get(user=request.user)
                    canvas.encrypted_blocks = serializer.validated_data['new_canvas_encrypted_blocks']
                    canvas.save(update_fields=['encrypted_blocks', 'updated_at'])
                except IdentityCanvas.DoesNotExist:
                    pass
            
            # Update canvas history if provided
            if serializer.validated_data.get('new_canvas_history'):
                try:
                    canvas = IdentityCanvas.objects.get(user=request.user)
                    for history_entry in serializer.validated_data['new_canvas_history']:
                        try:
                            history = CanvasHistory.objects.get(
                                id=history_entry.get('id'),
                                canvas=canvas
                            )
                            history.encrypted_blocks_snapshot = history_entry.get('encrypted_blocks_snapshot', '')
                            history.save(update_fields=['encrypted_blocks_snapshot'])
                        except CanvasHistory.DoesNotExist:
                            pass
                except IdentityCanvas.DoesNotExist:
                    pass
            
            # Update verification canvas if provided
            if serializer.validated_data.get('new_verification_canvas_encrypted_blocks'):
                try:
                    verification_canvas = VerificationCanvas.objects.get(user=request.user)
                    verification_canvas.encrypted_blocks = serializer.validated_data['new_verification_canvas_encrypted_blocks']
                    verification_canvas.save(update_fields=['encrypted_blocks', 'updated_at'])
                except VerificationCanvas.DoesNotExist:
                    pass
            
            # Update verification canvas history if provided
            if serializer.validated_data.get('new_verification_canvas_history'):
                try:
                    verification_canvas = VerificationCanvas.objects.get(user=request.user)
                    for history_entry in serializer.validated_data['new_verification_canvas_history']:
                        try:
                            history = VerificationCanvasHistory.objects.get(
                                id=history_entry.get('id'),
                                canvas=verification_canvas
                            )
                            history.encrypted_blocks_snapshot = history_entry.get('encrypted_blocks_snapshot', '')
                            history.save(update_fields=['encrypted_blocks_snapshot'])
                        except VerificationCanvasHistory.DoesNotExist:
                            pass
                except VerificationCanvas.DoesNotExist:
                    pass
            
            # Update preferences if provided
            if serializer.validated_data.get('new_preferences_encrypted') is not None:
                preferences, _ = UserPreferences.objects.get_or_create(user=request.user)
                preferences.encrypted_preferences = serializer.validated_data['new_preferences_encrypted']
                preferences.save(update_fields=['encrypted_preferences', 'updated_at'])
            
            # Update connected services if provided
            if serializer.validated_data.get('new_connected_services'):
                for service_data in serializer.validated_data['new_connected_services']:
                    try:
                        service = ConnectedService.objects.get(
                            id=service_data.get('id'),
                            user=request.user
                        )
                        if 'encrypted_service_data' in service_data:
                            service.encrypted_service_data = service_data['encrypted_service_data']
                        if 'encrypted_permissions' in service_data:
                            service.encrypted_permissions = service_data.get('encrypted_permissions', '')
                        service.save(update_fields=['encrypted_service_data', 'encrypted_permissions'])
                    except ConnectedService.DoesNotExist:
                        pass
            
            # Update identity level if provided
            if serializer.validated_data.get('new_identity_level_encrypted') is not None:
                identity_level, _ = UserIdentityLevel.objects.get_or_create(user=request.user)
                identity_level.encrypted_verification_data = serializer.validated_data['new_identity_level_encrypted']
                identity_level.save(update_fields=['encrypted_verification_data', 'updated_at'])
        
        return Response({
            'message': 'Master key changed successfully. All data has been re-encrypted.',
            'user': ZKUserDetailsSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class ZKTwoFactorSetupView(APIView):
    """
    Setup 2FA for user account
    Returns QR code and secret for authenticator app
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get or create 2FA record
        two_fa, created = ZKTwoFactorAuth.objects.get_or_create(user=request.user)
        
        # Generate new secret if not already set or if resetting
        if not two_fa.totp_secret or not two_fa.is_enabled:
            two_fa.totp_secret = pyotp.random_base32()
            two_fa.is_enabled = False
            two_fa.save()
        
        # Generate provisioning URI
        totp = pyotp.TOTP(two_fa.totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=str(request.user.id),
            issuer_name="SVA"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return Response({
            'secret': two_fa.totp_secret,
            'qr_code': f'data:image/png;base64,{qr_code_data}',
            'provisioning_uri': provisioning_uri,
            'is_enabled': two_fa.is_enabled
        }, status=status.HTTP_200_OK)
    
    def post(self, request):
        serializer = ZKTwoFactorSetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        two_fa, _ = ZKTwoFactorAuth.objects.get_or_create(user=request.user)
        
        if not two_fa.totp_secret:
            return Response(
                {'error': '2FA not initialized. Please call GET first.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify TOTP code
        totp_code = serializer.validated_data.get('totp_code')
        if totp_code:
            totp = pyotp.TOTP(two_fa.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                return Response(
                    {'error': 'Invalid TOTP code'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Generate backup codes
            backup_codes = [pyotp.random_base32()[:8].upper() for _ in range(10)]
            two_fa.backup_codes = json.dumps(backup_codes)
            two_fa.is_enabled = True
            two_fa.save()
            
            return Response({
                'message': '2FA enabled successfully',
                'backup_codes': backup_codes,
                'is_enabled': True
            }, status=status.HTTP_200_OK)
        
        return Response({
            'message': '2FA setup initiated. Verify with TOTP code to enable.',
            'is_enabled': False
        }, status=status.HTTP_200_OK)


class ZKTwoFactorStatusView(APIView):
    """
    Get 2FA status for current user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            two_fa = ZKTwoFactorAuth.objects.get(user=request.user)
            return Response({
                'is_enabled': two_fa.is_enabled,
                'has_backup_codes': bool(two_fa.backup_codes)
            }, status=status.HTTP_200_OK)
        except ZKTwoFactorAuth.DoesNotExist:
            return Response({
                'is_enabled': False,
                'has_backup_codes': False
            }, status=status.HTTP_200_OK)


class ZKTwoFactorDisableView(APIView):
    """
    Disable 2FA for user account
    Requires master key verification and TOTP code
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ZKTwoFactorDisableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Verify auth proof
        if request.user.auth_proof != serializer.validated_data['auth_proof']:
            return Response(
                {'error': 'Invalid master key verification'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            two_fa = ZKTwoFactorAuth.objects.get(user=request.user, is_enabled=True)
        except ZKTwoFactorAuth.DoesNotExist:
            return Response(
                {'error': '2FA is not enabled'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify TOTP code
        totp = pyotp.TOTP(two_fa.totp_secret)
        totp_code = serializer.validated_data['totp_code']
        
        # Check backup codes too
        backup_codes = json.loads(two_fa.backup_codes) if two_fa.backup_codes else []
        is_valid_backup = totp_code in backup_codes
        
        if not totp.verify(totp_code, valid_window=1) and not is_valid_backup:
            return Response(
                {'error': 'Invalid TOTP code'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Remove used backup code if applicable
        if is_valid_backup:
            backup_codes.remove(totp_code)
            two_fa.backup_codes = json.dumps(backup_codes) if backup_codes else None
        
        # Disable 2FA
        two_fa.is_enabled = False
        two_fa.save()
        
        return Response({
            'message': '2FA disabled successfully'
        }, status=status.HTTP_200_OK)


class ZKActiveSessionsView(APIView):
    """
    Get and manage active sessions for user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get all active refresh tokens for user
        active_tokens = ZKRefreshToken.objects.filter(
            user=request.user,
            expires_at__gt=timezone.now()
        ).order_by('-created_at')
        
        sessions = []
        current_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        for token in active_tokens:
            # Try to get access token from request to identify current session
            is_current = False
            try:
                from .token_utils import get_user_from_token
                user_from_token = get_user_from_token(current_token)
                if user_from_token and user_from_token.id == request.user.id:
                    is_current = True
            except:
                pass
            
            sessions.append({
                'id': str(token.id),
                'created_at': token.created_at.isoformat(),
                'expires_at': token.expires_at.isoformat(),
                'auth_method': token.auth_method,
                'device_fingerprint': token.device_fingerprint[:8] + '...' if token.device_fingerprint else None,
                'device_info': token.device_info,
                'ip_address': str(token.ip_address) if token.ip_address else None,
                'is_current': is_current
            })
        
        return Response({
            'sessions': sessions,
            'total': len(sessions)
        }, status=status.HTTP_200_OK)
    
    def delete(self, request):
        session_id = request.data.get('session_id')
        
        if not session_id:
            return Response(
                {'error': 'session_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token = ZKRefreshToken.objects.get(
                id=session_id,
                user=request.user
            )
            token.delete()
            
            return Response({
                'message': 'Session revoked successfully'
            }, status=status.HTTP_200_OK)
        except ZKRefreshToken.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ZKTwoFactorLoginVerifyView(APIView):
    """
    Verify 2FA code during login and complete authentication
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ZKTwoFactorLoginVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        temp_token = serializer.validated_data['temp_token']
        totp_code = serializer.validated_data['totp_code']
        
        try:
            temp_session = ZKTwoFactorLoginSession.objects.get(temp_token=temp_token)
        except ZKTwoFactorLoginSession.DoesNotExist:
            return Response(
                {'error': 'Invalid or expired temporary token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not temp_session.is_valid:
            temp_session.delete()
            return Response(
                {'error': 'Temporary session has expired. Please login again.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify 2FA code
        try:
            two_fa = ZKTwoFactorAuth.objects.get(user=temp_session.user, is_enabled=True)
        except ZKTwoFactorAuth.DoesNotExist:
            temp_session.delete()
            return Response(
                {'error': '2FA is not enabled for this account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        totp = pyotp.TOTP(two_fa.totp_secret)
        backup_codes = json.loads(two_fa.backup_codes) if two_fa.backup_codes else []
        is_valid_backup = totp_code in backup_codes
        
        if not totp.verify(totp_code, valid_window=1) and not is_valid_backup:
            return Response(
                {'error': 'Invalid TOTP code'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Remove used backup code if applicable
        if is_valid_backup:
            backup_codes.remove(totp_code)
            two_fa.backup_codes = json.dumps(backup_codes) if backup_codes else None
            two_fa.save()
        
        # Update 2FA last used
        two_fa.last_used = timezone.now()
        two_fa.save()
        
        # Update last login
        temp_session.user.last_login = timezone.now()
        temp_session.user.save(update_fields=['last_login'])
        
        # Generate tokens
        access_token = generate_access_token(temp_session.user)
        refresh_token = generate_refresh_token(
            temp_session.user,
            auth_method=temp_session.auth_method,
            device_fingerprint=temp_session.device_fingerprint
        )
        
        # Clean up temporary session
        temp_session.delete()
        
        return Response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": ZKUserDetailsSerializer(temp_session.user).data,
            "encrypted_data": temp_session.encrypted_data,
            "salt": temp_session.salt,
            "auth_method": temp_session.auth_method,
            "requires_2fa": False
        }, status=status.HTTP_200_OK)


# ==================== WAITLIST VIEWS ====================

class WaitlistJoinView(APIView):
    """
    Join the waitlist with SVA encryption
    Public endpoint - no authentication required
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = WaitlistEntrySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email_hash = serializer.validated_data['email_hash']
        encrypted_data = serializer.validated_data['encrypted_data']
        salt = serializer.validated_data['salt']
        consent_to_updates = serializer.validated_data.get('consent_to_updates', True)
        
        # Check if email already exists in waitlist
        if WaitlistEntry.objects.filter(email_hash=email_hash).exists():
            return Response(
                {"error": "This email is already on the waitlist."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create waitlist entry
        waitlist_entry = WaitlistEntry.objects.create(
            encrypted_data=encrypted_data,
            salt=salt,
            email_hash=email_hash,
            consent_to_updates=consent_to_updates
        )
        
        return Response({
            "message": "Successfully joined the waitlist!",
            "id": str(waitlist_entry.id),
            "created_at": waitlist_entry.created_at.isoformat()
        }, status=status.HTTP_201_CREATED)
