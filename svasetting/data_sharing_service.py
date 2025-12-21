"""
Data Sharing Service
Manages encrypted sharing blobs and provides event-driven updates.

This service:
- Manages sharing blob lifecycle
- Provides hooks for automatic updates
- Handles blob versioning and timestamps
- Integrates with connection service
"""
import logging
from typing import Optional, List, Dict, Any, Callable
from django.db import transaction
from django.utils import timezone
from django.dispatch import Signal
from .models import UserAppConnection
from .connection_service import connection_service
from authentication.models import ZKUser

logger = logging.getLogger(__name__)

# Signals for event-driven updates
sharing_blob_updated = Signal()
user_data_changed = Signal()
connection_scopes_changed = Signal()


class DataSharingService:
    """
    Service for managing encrypted sharing blobs.
    Provides event-driven updates when user data changes.
    """
    
    @staticmethod
    def update_sharing_blob_for_connection(
        connection: UserAppConnection,
        encrypted_blob: str,
        salt: str
    ) -> bool:
        """
        Update sharing blob for a specific connection.
        
        Args:
            connection: UserAppConnection instance
            encrypted_blob: Encrypted sharing blob
            salt: Salt for decryption
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with transaction.atomic():
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
                
                # Emit signal
                sharing_blob_updated.send(
                    sender=DataSharingService,
                    connection=connection,
                    timestamp=now
                )
                
                logger.info(
                    'Updated sharing blob for connection %s (app: %s)',
                    connection.id,
                    connection.app_name
                )
                
                return True
        except Exception as e:
            logger.error(
                'Failed to update sharing blob for connection %s: %s',
                connection.id,
                e,
                exc_info=True
            )
            return False
    
    @staticmethod
    def get_sharing_blob(
        connection: UserAppConnection
    ) -> Optional[Dict[str, Any]]:
        """
        Get sharing blob data for a connection.
        
        Args:
            connection: UserAppConnection instance
            
        Returns:
            Dict with blob data or None
        """
        if not connection.encrypted_sharing_blob:
            return None
        
        blob_timestamp = None
        if connection.sharing_blob_encrypted_at:
            blob_timestamp = connection.sharing_blob_encrypted_at.isoformat()
        
        return {
            'encrypted_blob': connection.encrypted_sharing_blob,
            'salt': connection.sharing_blob_salt,
            'timestamp': blob_timestamp,
            'approved_scopes': connection.approved_scopes or [],
        }
    
    @staticmethod
    def mark_blob_for_update(
        user: ZKUser,
        connection_id: Optional[str] = None
    ) -> int:
        """
        Mark sharing blob(s) as needing update.
        This is called when user data changes.
        
        Args:
            user: The user whose data changed
            connection_id: Optional specific connection ID, or None for all
            
        Returns:
            Number of connections marked
        """
        if connection_id:
            try:
                connection = UserAppConnection.objects.get(
                    id=connection_id,
                    user=user,
                    is_active=True
                )
                # Emit signal for specific connection
                user_data_changed.send(
                    sender=DataSharingService,
                    user=user,
                    connection=connection
                )
                return 1
            except UserAppConnection.DoesNotExist:
                return 0
        else:
            # Mark all active connections
            connections = connection_service.get_active_connections_for_user(user)
            count = len(connections)
            
            # Emit signal for all connections
            user_data_changed.send(
                sender=DataSharingService,
                user=user,
                connection=None  # None means all connections
            )
            
            logger.info(
                'Marked %d connections for blob update for user %s',
                count,
                user.id
            )
            
            return count
    
    @staticmethod
    def get_connections_needing_update(
        user: ZKUser
    ) -> List[UserAppConnection]:
        """
        Get all connections that need sharing blob updates.
        Currently returns all active connections, but could be enhanced
        to track which connections actually need updates.
        
        Args:
            user: The user
            
        Returns:
            List of UserAppConnection instances
        """
        return connection_service.get_active_connections_for_user(user)
    
    @staticmethod
    def validate_sharing_blob(
        encrypted_blob: str,
        salt: str
    ) -> bool:
        """
        Validate sharing blob format.
        
        Args:
            encrypted_blob: Encrypted blob string
            salt: Salt string
            
        Returns:
            True if valid, False otherwise
        """
        if not encrypted_blob or not salt:
            return False
        
        if len(encrypted_blob) < 50:  # Minimum reasonable size
            return False
        
        if len(salt) < 10:  # Minimum reasonable size
            return False
        
        return True


# Singleton instance
data_sharing_service = DataSharingService()

