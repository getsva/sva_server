# authentication/settings_views.py

import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)

from .models import (
    UserIdentityLevel,
    ConnectedService,
    UserPreferences,
    SecurityLog,
    UserAppConnection
)
from .serializers import (
    IdentityLevelSerializer,
    ConnectedServiceSerializer,
    SecurityLogSerializer,
    UpdatePreferencesSerializer,
    VerifyIdentitySerializer,
    ConnectServiceSerializer,
    RevokeServiceSerializer,
    ChangePasswordSerializer,
    UserAppConnectionSerializer,
    UpdateAppScopesSerializer,
    RevokeAppConnectionSerializer
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


class ListAppConnectionsView(APIView):
    """
    List all app connections for the authenticated user
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get active connections by default, but allow filtering
        include_revoked = request.query_params.get('include_revoked', 'false').lower() == 'true'
        
        from .connection_service import connection_service
        connections = connection_service.list_connections(
            user=request.user,
            include_revoked=include_revoked
        )
        
        return Response({
            'connections': UserAppConnectionSerializer(connections, many=True).data,
            'total': len(connections)
        })


class GetAppConnectionView(APIView):
    """
    Get details of a specific app connection
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, connection_id):
        from .connection_service import connection_service
        connection = connection_service.get_connection_by_id(
            user=request.user,
            connection_id=connection_id,
            active_only=False
        )
        
        if not connection:
            return Response(
                {'error': 'App connection not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response(UserAppConnectionSerializer(connection).data)


class UpdateAppScopesView(APIView):
    """
    Update approved scopes for an app connection
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request, connection_id):
        serializer = UpdateAppScopesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        from .connection_service import connection_service
        from .data_sharing_service import data_sharing_service
        
        new_scopes = serializer.validated_data['scopes']
        
        connection = connection_service.update_scopes(
            user=request.user,
            connection_id=connection_id,
            new_scopes=new_scopes
        )
        
        if not connection:
            return Response(
                {'error': 'App connection not found or revoked'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Update security log with request metadata (if exists)
        latest_log = SecurityLog.objects.filter(
            user=request.user,
            log_type='app_scopes_updated'
        ).order_by('-created_at').first()
        if latest_log:
            latest_log.ip_address = request.META.get('REMOTE_ADDR')
            latest_log.user_agent = request.META.get('HTTP_USER_AGENT')
            latest_log.save(update_fields=['ip_address', 'user_agent'])
        
        # Mark blob for update (client will handle actual update)
        data_sharing_service.mark_blob_for_update(
            user=request.user,
            connection_id=connection_id
        )
        
        return Response({
            'message': 'App scopes updated successfully',
            'connection': UserAppConnectionSerializer(connection).data
        })


class UpdateSharingBlobView(APIView):
    """
    Update encrypted sharing blob for an app connection (Google OAuth style - live updates)
    Uses DataSharingService for centralized blob management
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, connection_id):
        encrypted_blob = request.data.get('encrypted_blob')
        salt = request.data.get('salt')
        
        if not encrypted_blob or not salt:
            return Response(
                {'error': 'encrypted_blob and salt are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .data_sharing_service import data_sharing_service
        from .connection_service import connection_service
        
        # Validate blob format
        if not data_sharing_service.validate_sharing_blob(encrypted_blob, salt):
            return Response(
                {'error': 'Invalid sharing blob format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get connection
        connection = connection_service.get_connection_by_id(
            user=request.user,
            connection_id=connection_id,
            active_only=True
        )
        
        if not connection:
            return Response(
                {'error': 'App connection not found or revoked'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Update sharing blob
        success = data_sharing_service.update_sharing_blob_for_connection(
            connection=connection,
            encrypted_blob=encrypted_blob,
            salt=salt
        )
        
        if not success:
            return Response(
                {'error': 'Failed to update sharing blob'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Refresh connection to get updated timestamp
        connection.refresh_from_db()
        
        return Response({
            'message': 'Sharing blob updated successfully',
            'encrypted_at': connection.sharing_blob_encrypted_at.isoformat(),
            'timestamp': connection.sharing_blob_encrypted_at.isoformat()  # Alias for compatibility
        })


class RevokeAppConnectionView(APIView):
    """
    Revoke access for an app connection
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, connection_id):
        from .connection_service import connection_service
        
        connection = connection_service.revoke_connection(
            user=request.user,
            connection_id=connection_id
        )
        
        if not connection:
            return Response(
                {'error': 'App connection not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not connection.is_active:
            return Response(
                {'error': 'App connection already revoked'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update security log with request metadata (if exists)
        latest_log = SecurityLog.objects.filter(
            user=request.user,
            log_type='app_revoked'
        ).order_by('-created_at').first()
        if latest_log:
            latest_log.ip_address = request.META.get('REMOTE_ADDR')
            latest_log.user_agent = request.META.get('HTTP_USER_AGENT')
            latest_log.save(update_fields=['ip_address', 'user_agent'])
        
        return Response({
            'message': 'App access revoked successfully',
            'connection': UserAppConnectionSerializer(connection).data
        })


class RestoreAppConnectionView(APIView):
    """
    Restore/Re-enable a revoked app connection
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, connection_id):
        from .connection_service import connection_service
        
        connection = connection_service.restore_connection(
            user=request.user,
            connection_id=connection_id
        )
        
        if not connection:
            return Response(
                {'error': 'App connection not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if connection.is_active:
            return Response(
                {'error': 'App connection is already active'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update security log with request metadata (if exists)
        latest_log = SecurityLog.objects.filter(
            user=request.user,
            log_type='app_connected'
        ).order_by('-created_at').first()
        if latest_log:
            latest_log.ip_address = request.META.get('REMOTE_ADDR')
            latest_log.user_agent = request.META.get('HTTP_USER_AGENT')
            latest_log.save(update_fields=['ip_address', 'user_agent'])
        
        return Response({
            'message': 'App access restored successfully',
            'connection': UserAppConnectionSerializer(connection).data
        })


class GetAppConnectionByClientIdView(APIView):
    """
    Get app connection by client_id (for consent flow)
    Uses ConnectionService for centralized management
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        client_id = request.query_params.get('client_id')
        if not client_id:
            return Response(
                {'error': 'client_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .connection_service import connection_service
        connection = connection_service.get_connection(
            user=request.user,
            client_id=client_id,
            active_only=True
        )
        
        if connection:
            return Response({
                'exists': True,
                'connection': UserAppConnectionSerializer(connection).data
            })
        else:
            return Response({
                'exists': False
            })


class GetAppConnectionForUserInfoView(APIView):
    """
    Internal API endpoint for OAuth server to get UserAppConnection for UserInfo
    Uses ConnectionService for centralized management
    Requires service token authentication
    """
    permission_classes = []  # Will use service token check
    
    def _require_service_token(self, request):
        """Check service token"""
        from django.conf import settings
        header_name = getattr(settings, 'INTERNAL_SERVICE_HEADER', 'X-Service-Token')
        expected = getattr(settings, 'INTERNAL_SERVICE_TOKEN', None)
        
        token = request.headers.get(header_name)
        if not expected:
            return False
        if not token or token != expected:
            return False
        return True
    
    def get(self, request):
        """Get UserAppConnection by client_id and user_id (subject)"""
        if not self._require_service_token(request):
            return Response(
                {'error': 'Invalid service token'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        client_id = request.query_params.get('client_id')
        user_id = request.query_params.get('user_id')  # This is the subject from OAuth
        
        if not client_id or not user_id:
            return Response(
                {'error': 'client_id and user_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .connection_service import connection_service
        sharing_data = connection_service.get_sharing_data(
            user_id=user_id,
            client_id=client_id
        )
        
        if sharing_data.get('exists'):
            return Response(sharing_data)
        else:
            return Response({
                'exists': False
            })


class ConnectionStatsView(APIView):
    """
    Get connection statistics
    Admin or authenticated user can view stats
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        from .connection_registry import connection_registry
        
        # Get stats for current user or all users (if admin)
        user = request.user if not request.user.is_staff else None
        stats = connection_registry.get_connection_stats(user=user)
        
        return Response(stats)


class ConnectionHealthView(APIView):
    """
    Check health of user's connections
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, connection_id=None):
        from .connection_utils import check_connection_health
        from .connection_service import connection_service
        
        if connection_id:
            # Check specific connection
            connection = connection_service.get_connection_by_id(
                user=request.user,
                connection_id=connection_id,
                active_only=False
            )
            
            if not connection:
                return Response(
                    {'error': 'Connection not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            health = check_connection_health(connection)
            return Response(health)
        else:
            # Check all connections
            connections = connection_service.list_connections(
                user=request.user,
                include_revoked=False
            )
            
            results = []
            for connection in connections:
                health = check_connection_health(connection)
                results.append({
                    'connection_id': str(connection.id),
                    'app_name': connection.app_name,
                    'health': health
                })
            
            return Response({
                'connections': results,
                'total': len(results),
                'healthy': sum(1 for r in results if r['health']['is_healthy']),
                'unhealthy': sum(1 for r in results if not r['health']['is_healthy'])
            })


class AppMetadataView(APIView):
    """
    Get app metadata from registry
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        client_id = request.query_params.get('client_id')
        if not client_id:
            return Response(
                {'error': 'client_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .connection_registry import connection_registry
        metadata = connection_registry.get_app_metadata(client_id)
        
        if not metadata:
            return Response(
                {'error': 'App metadata not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response(metadata)


class BatchRevokeConnectionsView(APIView):
    """
    Bulk revoke connections
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        connection_ids = request.data.get('connection_ids', [])
        reason = request.data.get('reason')
        
        if not connection_ids:
            return Response(
                {'error': 'connection_ids is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .batch_operations import batch_operations
        results = batch_operations.bulk_revoke_connections(
            user=request.user,
            connection_ids=connection_ids,
            reason=reason
        )
        
        return Response(results)


class BatchUpdateMetadataView(APIView):
    """
    Bulk update app metadata for all connections with a client_id
    Admin only or app owner
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        client_id = request.data.get('client_id')
        name = request.data.get('name')
        logo = request.data.get('logo')
        description = request.data.get('description')
        
        if not client_id:
            return Response(
                {'error': 'client_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .batch_operations import batch_operations
        results = batch_operations.bulk_update_metadata(
            client_id=client_id,
            name=name,
            logo=logo,
            description=description
        )
        
        return Response(results)


class BatchMarkForBlobUpdateView(APIView):
    """
    Bulk mark connections for blob update
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        connection_ids = request.data.get('connection_ids')
        client_id = request.data.get('client_id')
        
        from .batch_operations import batch_operations
        results = batch_operations.bulk_mark_for_blob_update(
            user=request.user,
            connection_ids=connection_ids,
            client_id=client_id
        )
        
        if 'error' in results:
            return Response(
                {'error': results['error']},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response(results)


class BatchHealthCheckView(APIView):
    """
    Bulk health check for connections
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        client_id = request.query_params.get('client_id')
        
        from .batch_operations import batch_operations
        results = batch_operations.bulk_health_check(
            user=request.user,
            client_id=client_id
        )
        
        return Response(results)


class BatchUpdateScopesView(APIView):
    """
    Bulk update scopes for multiple connections
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        updates = request.data.get('updates', [])
        
        if not updates:
            return Response(
                {'error': 'updates is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from .batch_operations import batch_operations
        results = batch_operations.bulk_update_scopes(
            user=request.user,
            updates=updates
        )
        
        return Response(results)