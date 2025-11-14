# authentication/settings_views.py

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction

from .models import (
    UserIdentityLevel,
    ConnectedService,
    UserPreferences,
    SecurityLog
)
from .serializers import (
    IdentityLevelSerializer,
    ConnectedServiceSerializer,
    SecurityLogSerializer,
    UpdatePreferencesSerializer,
    VerifyIdentitySerializer,
    ConnectServiceSerializer,
    RevokeServiceSerializer,
    ChangePasswordSerializer
)


class GetUserSettingsView(APIView):
    """
    Get all user settings data (encrypted where applicable)
    Returns: identity level, preferences, connected services, security logs
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get or create identity level
        identity_level, _ = UserIdentityLevel.objects.get_or_create(user=user)
        
        # Get or create preferences
        preferences, _ = UserPreferences.objects.get_or_create(
            user=user,
            defaults={'encrypted_preferences': ''}
        )
        
        # Get connected services
        connected_services = ConnectedService.objects.filter(
            user=user,
            is_active=True
        )
        
        # Get recent security logs (last 50)
        security_logs = SecurityLog.objects.filter(user=user)[:50]
        
        return Response({
            'identity_level': IdentityLevelSerializer(identity_level).data,
            'preferences': {
                'id': str(preferences.id),
                'encrypted_preferences': preferences.encrypted_preferences,
                'updated_at': preferences.updated_at
            },
            'connected_services': ConnectedServiceSerializer(
                connected_services, many=True
            ).data,
            'security_logs': SecurityLogSerializer(security_logs, many=True).data
        })


class UpdatePreferencesView(APIView):
    """
    Update user preferences (client sends encrypted blob)
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request):
        serializer = UpdatePreferencesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        preferences, _ = UserPreferences.objects.get_or_create(
            user=request.user
        )
        
        # Store old encrypted_preferences to compare
        old_encrypted_preferences = preferences.encrypted_preferences
        new_encrypted_preferences = serializer.validated_data['encrypted_preferences']
        create_log = serializer.validated_data.get('create_log', False)
        
        preferences.encrypted_preferences = new_encrypted_preferences
        preferences.save()
        
        # Only log if explicitly requested (manual save) and data actually changed
        if create_log and old_encrypted_preferences != new_encrypted_preferences:
            self._create_security_log(
                request.user,
                'account_settings',
                request.META.get('REMOTE_ADDR'),
                request.META.get('HTTP_USER_AGENT')
            )
        
        return Response({
            'message': 'Preferences updated successfully',
            'preferences': {
                'id': str(preferences.id),
                'encrypted_preferences': preferences.encrypted_preferences,
                'updated_at': preferences.updated_at
            }
        })
    
    def _create_security_log(self, user, log_type, ip_address, user_agent):
        SecurityLog.objects.create(
            user=user,
            log_type=log_type,
            ip_address=ip_address,
            user_agent=user_agent
        )


class VerifyIdentityLevelView(APIView):
    """
    Request identity level verification
    Client sends encrypted verification documents/data
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = VerifyIdentitySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        verification_level = serializer.validated_data['verification_level']
        encrypted_data = serializer.validated_data['encrypted_verification_data']
        
        identity_level, _ = UserIdentityLevel.objects.get_or_create(
            user=request.user
        )
        
        # Store encrypted verification data
        identity_level.encrypted_verification_data = encrypted_data
        
        # Update verification timestamps based on level
        now = timezone.now()
        if verification_level == 1:
            identity_level.email_verified_at = now
            identity_level.phone_verified_at = now
        elif verification_level == 2:
            identity_level.govt_id_verified_at = now
        elif verification_level == 3:
            identity_level.professional_verified_at = now
        
        # Update current level if higher
        if verification_level > identity_level.current_level:
            identity_level.current_level = verification_level
        
        identity_level.save()
        
        # Log the action
        SecurityLog.objects.create(
            user=request.user,
            log_type='identity_upgrade',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT')
        )
        
        return Response({
            'message': f'Identity level {verification_level} verification submitted',
            'identity_level': IdentityLevelSerializer(identity_level).data
        })


class ConnectServiceView(APIView):
    """
    Connect a new service/website with specific identity sharing level
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ConnectServiceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Validate user has required identity level
        identity_level = UserIdentityLevel.objects.get(user=request.user)
        requested_level = serializer.validated_data['shared_identity_level']
        
        if requested_level > identity_level.current_level:
            return Response(
                {'error': f'You need identity level {requested_level} to share this data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create connected service
        service = ConnectedService.objects.create(
            user=request.user,
            encrypted_service_data=serializer.validated_data['encrypted_service_data'],
            shared_identity_level=requested_level,
            encrypted_permissions=serializer.validated_data.get('encrypted_permissions', '')
        )
        
        # Log the action
        SecurityLog.objects.create(
            user=request.user,
            log_type='service_connected',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT')
        )
        
        return Response({
            'message': 'Service connected successfully',
            'service': ConnectedServiceSerializer(service).data
        }, status=status.HTTP_201_CREATED)


class RevokeServiceView(APIView):
    """
    Revoke access for a connected service
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = RevokeServiceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        service_id = serializer.validated_data['service_id']
        
        try:
            service = ConnectedService.objects.get(
                id=service_id,
                user=request.user
            )
            
            service.is_active = False
            service.revoked_at = timezone.now()
            service.save()
            
            # Log the action
            SecurityLog.objects.create(
                user=request.user,
                log_type='service_revoked',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'message': 'Service access revoked successfully',
                'service': ConnectedServiceSerializer(service).data
            })
            
        except ConnectedService.DoesNotExist:
            return Response(
                {'error': 'Service not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class DowngradeIdentityLevelView(APIView):
    """
    Downgrade identity level (useful for privacy management)
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        new_level = request.data.get('new_level')
        
        if new_level is None or not isinstance(new_level, int):
            return Response(
                {'error': 'new_level is required and must be an integer'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if new_level < 0 or new_level > 3:
            return Response(
                {'error': 'new_level must be between 0 and 3'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identity_level = UserIdentityLevel.objects.get(user=request.user)
        
        if new_level >= identity_level.current_level:
            return Response(
                {'error': 'New level must be lower than current level'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identity_level.current_level = new_level
        identity_level.save()
        
        # Log the action
        SecurityLog.objects.create(
            user=request.user,
            log_type='identity_downgrade',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT')
        )
        
        return Response({
            'message': f'Identity level downgraded to {new_level}',
            'identity_level': IdentityLevelSerializer(identity_level).data
        })


class ChangePasswordView(APIView):
    """
    Change user password with zero-knowledge approach
    Client must re-encrypt all data with new master key
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Note: In a real implementation, you'd verify the old credentials
        # match the current auth_proof before allowing the change
        
        user = request.user
        
        # Update auth_proof with new one
        user.auth_proof = serializer.validated_data['new_auth_proof']
        
        # Update encrypted_data with re-encrypted data
        user.encrypted_data = serializer.validated_data['encrypted_new_credentials']
        user.save()
        
        # Invalidate all refresh tokens
        from authentication.models import ZKRefreshToken
        ZKRefreshToken.objects.filter(user=user).delete()
        
        # Log the action
        SecurityLog.objects.create(
            user=user,
            log_type='password_change',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT')
        )
        
        return Response({
            'message': 'Password changed successfully. Please log in again.',
            'requires_reauth': True
        })


class ExportUserDataView(APIView):
    """
    Export all user data (GDPR compliance)
    Returns encrypted blobs that user can decrypt locally
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get all user data
        identity_level = UserIdentityLevel.objects.filter(user=user).first()
        preferences = UserPreferences.objects.filter(user=user).first()
        services = ConnectedService.objects.filter(user=user)
        logs = SecurityLog.objects.filter(user=user)
        
        export_data = {
            'user_metadata': {
                'user_id': str(user.id),
                'created_at': user.created_at,
                'last_login': user.last_login,
                'is_active': user.is_active
            },
            'encrypted_user_data': user.encrypted_data,
            'salt': user.salt,
            'identity_level': IdentityLevelSerializer(identity_level).data if identity_level else None,
            'preferences': {
                'encrypted_preferences': preferences.encrypted_preferences if preferences else ''
            },
            'connected_services': ConnectedServiceSerializer(services, many=True).data,
            'security_logs': SecurityLogSerializer(logs, many=True).data,
            'export_timestamp': timezone.now().isoformat()
        }
        
        # Log the export
        SecurityLog.objects.create(
            user=user,
            log_type='data_export',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT')
        )
        
        return Response(export_data)


class GetSecurityLogsView(APIView):
    """
    Get paginated security logs
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        logs = SecurityLog.objects.filter(
            user=request.user
        )[offset:offset + limit]
        
        total_count = SecurityLog.objects.filter(user=request.user).count()
        
        return Response({
            'logs': SecurityLogSerializer(logs, many=True).data,
            'total': total_count,
            'limit': limit,
            'offset': offset
        })