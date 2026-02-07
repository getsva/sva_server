"""
Connection Management Service
Centralized service for managing all app connections and data sharing.

This service provides:
- Unified connection lifecycle management
- Data sharing blob management
- Connection metadata and registry
- Event-driven updates
- Clean separation from OAuth protocol
"""
import logging
from typing import Optional, List, Dict, Any
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from .models import UserAppConnection, SecurityLog
from authentication.models import ZKUser

logger = logging.getLogger(__name__)


class ConnectionService:
    """
    Centralized service for managing app connections.
    Handles connection lifecycle, permissions, and data sharing.
    """
    
    @staticmethod
    @transaction.atomic
    def create_or_update_connection(
        user: ZKUser,
        client_id: str,
        app_name: str,
        approved_scopes: List[str],
        app_logo: Optional[str] = None,
        app_description: Optional[str] = None,
        encrypted_sharing_blob: Optional[str] = None,
        sharing_blob_salt: Optional[str] = None,
        preserve_existing_scopes: bool = False
    ) -> UserAppConnection:
        """
        Create or update an app connection.
        
        Args:
            user: The user creating/updating the connection
            client_id: OAuth app client ID
            app_name: Display name of the app
            approved_scopes: List of approved scopes
            app_logo: Optional app logo URL
            app_description: Optional app description
            encrypted_sharing_blob: Optional encrypted sharing blob
            sharing_blob_salt: Optional salt for sharing blob
            preserve_existing_scopes: If True, merge with existing scopes instead of replacing
            
        Returns:
            UserAppConnection instance
        """
        # Normalize scopes
        normalized_scopes = sorted(list(set(approved_scopes))) if approved_scopes else []
        
        try:
            connection = UserAppConnection.objects.select_for_update().get(
                user=user,
                client_id=client_id
            )
            
            # Update existing connection
            was_manually_updated = connection.last_scope_update is not None
            
            # Handle scope updates
            if preserve_existing_scopes and was_manually_updated:
                # CRITICAL: Keep ONLY existing scopes when user has manually managed permissions
                # This prevents auto-approval from overwriting user's permission preferences
                # e.g., if user removed 'name' scope, don't add it back during re-login
                existing_scopes = set(connection.approved_scopes or [])
                final_scopes = sorted(list(existing_scopes))
                logger.info(
                    'Preserving existing scopes for connection %s: %s (ignoring requested: %s)',
                    connection.id, final_scopes, normalized_scopes
                )
            else:
                # Replace scopes (or first-time creation)
                final_scopes = normalized_scopes
            
            # Update connection metadata
            connection.app_name = app_name
            if app_logo:
                connection.app_logo = app_logo
            if app_description:
                connection.app_description = app_description
            
            # Update scopes if changed
            if connection.approved_scopes != final_scopes:
                connection.update_scopes(final_scopes)
            else:
                connection.last_accessed = timezone.now()
                connection.save(update_fields=['last_accessed', 'app_name', 'app_logo', 'app_description'])
            
            # Update sharing blob if provided
            if encrypted_sharing_blob and sharing_blob_salt:
                connection.encrypted_sharing_blob = encrypted_sharing_blob
                connection.sharing_blob_salt = sharing_blob_salt
                connection.sharing_blob_encrypted_at = timezone.now()
                connection.save(update_fields=['encrypted_sharing_blob', 'sharing_blob_salt', 'sharing_blob_encrypted_at'])
            
            # Reactivate if was revoked
            if not connection.is_active:
                connection.is_active = True
                connection.revoked_at = None
                connection.save(update_fields=['is_active', 'revoked_at'])
            
            logger.info(
                'Updated connection %s for user %s, app %s',
                connection.id,
                user.id,
                app_name
            )
            
        except UserAppConnection.DoesNotExist:
            # Create new connection
            connection = UserAppConnection.objects.create(
                user=user,
                client_id=client_id,
                app_name=app_name,
                app_logo=app_logo,
                app_description=app_description,
                approved_scopes=normalized_scopes,
                encrypted_sharing_blob=encrypted_sharing_blob,
                sharing_blob_salt=sharing_blob_salt,
                sharing_blob_encrypted_at=timezone.now() if encrypted_sharing_blob else None,
                is_active=True
            )
            
            # Log connection creation
            SecurityLog.objects.create(
                user=user,
                log_type='app_connected',
                ip_address=None,  # Will be set by view
                user_agent=None
            )
            
            logger.info(
                'Created new connection %s for user %s, app %s',
                connection.id,
                user.id,
                app_name
            )
        
        return connection
    
    @staticmethod
    def get_connection(
        user: ZKUser,
        client_id: str,
        active_only: bool = True
    ) -> Optional[UserAppConnection]:
        """
        Get a connection by user and client_id.
        
        Args:
            user: The user
            client_id: OAuth app client ID
            active_only: Only return active connections
            
        Returns:
            UserAppConnection or None
        """
        try:
            queryset = UserAppConnection.objects.filter(user=user, client_id=client_id)
            if active_only:
                queryset = queryset.filter(is_active=True)
            return queryset.get()
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    def get_connection_by_id(
        user: ZKUser,
        connection_id: str,
        active_only: bool = False
    ) -> Optional[UserAppConnection]:
        """
        Get a connection by ID.
        
        Args:
            user: The user
            connection_id: Connection UUID
            active_only: Only return active connections
            
        Returns:
            UserAppConnection or None
        """
        try:
            queryset = UserAppConnection.objects.filter(user=user, id=connection_id)
            if active_only:
                queryset = queryset.filter(is_active=True)
            return queryset.get()
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    def list_connections(
        user: ZKUser,
        include_revoked: bool = False
    ) -> List[UserAppConnection]:
        """
        List all connections for a user.
        
        Args:
            user: The user
            include_revoked: Include revoked connections
            
        Returns:
            List of UserAppConnection instances
        """
        queryset = UserAppConnection.objects.filter(user=user)
        if not include_revoked:
            queryset = queryset.filter(is_active=True)
        return list(queryset.order_by('-connected_at'))
    
    @staticmethod
    @transaction.atomic
    def revoke_connection(
        user: ZKUser,
        connection_id: str
    ) -> Optional[UserAppConnection]:
        """
        Revoke a connection.
        
        Args:
            user: The user
            connection_id: Connection UUID
            
        Returns:
            UserAppConnection or None if not found
        """
        try:
            connection = UserAppConnection.objects.get(
                id=connection_id,
                user=user
            )
            
            if not connection.is_active:
                return connection
            
            connection.revoke()
            
            # Log revocation
            SecurityLog.objects.create(
                user=user,
                log_type='app_revoked',
                ip_address=None,  # Will be set by view
                user_agent=None
            )
            
            logger.info(
                'Revoked connection %s for user %s',
                connection.id,
                user.id
            )
            
            return connection
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    @transaction.atomic
    def restore_connection(
        user: ZKUser,
        connection_id: str
    ) -> Optional[UserAppConnection]:
        """
        Restore a revoked connection.
        
        Args:
            user: The user
            connection_id: Connection UUID
            
        Returns:
            UserAppConnection or None if not found
        """
        try:
            connection = UserAppConnection.objects.get(
                id=connection_id,
                user=user
            )
            
            if connection.is_active:
                return connection
            
            connection.is_active = True
            connection.revoked_at = None
            connection.last_accessed = timezone.now()
            connection.save(update_fields=['is_active', 'revoked_at', 'last_accessed'])
            
            # Log restoration
            SecurityLog.objects.create(
                user=user,
                log_type='app_connected',
                ip_address=None,
                user_agent=None
            )
            
            logger.info(
                'Restored connection %s for user %s',
                connection.id,
                user.id
            )
            
            return connection
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    @transaction.atomic
    def update_scopes(
        user: ZKUser,
        connection_id: str,
        new_scopes: List[str]
    ) -> Optional[UserAppConnection]:
        """
        Update approved scopes for a connection.
        
        Args:
            user: The user
            connection_id: Connection UUID
            new_scopes: New list of approved scopes
            
        Returns:
            UserAppConnection or None if not found
        """
        try:
            connection = UserAppConnection.objects.select_for_update().get(
                id=connection_id,
                user=user,
                is_active=True
            )
            
            # Normalize scopes
            normalized_scopes = sorted(list(set(new_scopes))) if new_scopes else []
            
            # Check if scopes changed
            current_scopes = sorted(list(set(connection.approved_scopes or [])))
            if current_scopes == normalized_scopes:
                return connection  # No change
            
            # Update scopes
            connection.update_scopes(normalized_scopes)
            
            # Log scope update
            SecurityLog.objects.create(
                user=user,
                log_type='app_scopes_updated',
                ip_address=None,
                user_agent=None
            )
            
            logger.info(
                'Updated scopes for connection %s: %s',
                connection.id,
                ', '.join(normalized_scopes)
            )
            
            return connection
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    @transaction.atomic
    def update_sharing_blob(
        user: ZKUser,
        connection_id: str,
        encrypted_blob: str,
        salt: str
    ) -> Optional[UserAppConnection]:
        """
        Update the encrypted sharing blob for a connection.
        
        Args:
            user: The user
            connection_id: Connection UUID
            encrypted_blob: Encrypted sharing blob
            salt: Salt for decryption
            
        Returns:
            UserAppConnection or None if not found
        """
        try:
            connection = UserAppConnection.objects.select_for_update().get(
                id=connection_id,
                user=user,
                is_active=True
            )
            
            now = timezone.now()
            connection.encrypted_sharing_blob = encrypted_blob
            connection.sharing_blob_salt = salt
            connection.sharing_blob_encrypted_at = now
            connection.last_accessed = now
            connection.save(update_fields=[
                'encrypted_sharing_blob',
                'sharing_blob_salt',
                'sharing_blob_encrypted_at',
                'last_accessed'
            ])
            
            logger.info(
                'Updated sharing blob for connection %s',
                connection.id
            )
            
            return connection
        except UserAppConnection.DoesNotExist:
            return None
    
    @staticmethod
    def get_sharing_data(
        user_id: str,
        client_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get sharing data for userinfo endpoint.
        This is called by OAuth server to get sharing blob.
        
        Args:
            user_id: User UUID (subject)
            client_id: OAuth app client ID
            
        Returns:
            Dict with sharing data or None
        """
        try:
            user = ZKUser.objects.get(id=user_id)
            connection = UserAppConnection.objects.get(
                user=user,
                client_id=client_id,
                is_active=True
            )
            
            blob_timestamp = None
            if connection.sharing_blob_encrypted_at:
                blob_timestamp = connection.sharing_blob_encrypted_at.isoformat()
            
            return {
                'exists': True,
                'encrypted_sharing_blob': connection.encrypted_sharing_blob,
                'sharing_blob_salt': connection.sharing_blob_salt,
                'approved_scopes': connection.approved_scopes or [],
                'sharing_blob_encrypted_at': blob_timestamp,
            }
        except (ZKUser.DoesNotExist, UserAppConnection.DoesNotExist):
            return {'exists': False}
    
    @staticmethod
    def get_active_connections_for_user(user: ZKUser) -> List[UserAppConnection]:
        """
        Get all active connections for a user.
        Used for bulk operations like updating all sharing blobs.
        
        Args:
            user: The user
            
        Returns:
            List of active UserAppConnection instances
        """
        return list(
            UserAppConnection.objects.filter(
                user=user,
                is_active=True
            ).order_by('-connected_at')
        )


# Singleton instance
connection_service = ConnectionService()

