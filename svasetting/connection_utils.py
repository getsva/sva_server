"""
Connection Utilities
Helper functions for connection management and data sharing.
"""
import logging
from typing import List, Set, Dict, Any, Optional
from django.utils import timezone
from .models import UserAppConnection
from .connection_service import connection_service
from .data_sharing_service import data_sharing_service
from authentication.models import ZKUser

logger = logging.getLogger(__name__)


def normalize_scopes(scopes: List[str]) -> List[str]:
    """
    Normalize scopes: remove duplicates, sort, filter empty.
    
    Args:
        scopes: List of scope strings
        
    Returns:
        Normalized sorted list of unique scopes
    """
    if not scopes:
        return []
    
    # Filter and normalize
    normalized = [s.strip() for s in scopes if s and s.strip()]
    
    # Remove duplicates and sort
    return sorted(list(set(normalized)))


def validate_scopes(
    requested_scopes: List[str],
    available_scopes: Optional[List[str]] = None
) -> tuple[bool, List[str], List[str]]:
    """
    Validate requested scopes against available scopes.
    
    Args:
        requested_scopes: Scopes being requested
        available_scopes: Optional list of available scopes (if None, all are valid)
        
    Returns:
        Tuple of (is_valid, valid_scopes, invalid_scopes)
    """
    requested = set(normalize_scopes(requested_scopes))
    
    if available_scopes is None:
        # All scopes are valid
        return True, list(requested), []
    
    available = set(normalize_scopes(available_scopes))
    valid = requested & available
    invalid = requested - available
    
    return len(invalid) == 0, list(valid), list(invalid)


def get_connections_needing_blob_update(user: ZKUser) -> List[UserAppConnection]:
    """
    Get all connections that need sharing blob updates.
    Currently returns all active connections, but could be enhanced
    to track which connections actually need updates.
    
    Args:
        user: The user
        
    Returns:
        List of UserAppConnection instances
    """
    return data_sharing_service.get_connections_needing_update(user)


def bulk_update_sharing_blobs(
    user: ZKUser,
    blob_updater: callable
) -> Dict[str, Any]:
    """
    Bulk update sharing blobs for all active connections.
    
    Args:
        user: The user
        blob_updater: Function that takes (connection, user_data) and returns (encrypted_blob, salt)
        
    Returns:
        Dict with update results
    """
    connections = get_connections_needing_blob_update(user)
    
    results = {
        'total': len(connections),
        'success': 0,
        'failed': 0,
        'errors': []
    }
    
    for connection in connections:
        try:
            # Call updater function
            encrypted_blob, salt = blob_updater(connection, user)
            
            # Update blob
            success = data_sharing_service.update_sharing_blob_for_connection(
                connection=connection,
                encrypted_blob=encrypted_blob,
                salt=salt
            )
            
            if success:
                results['success'] += 1
            else:
                results['failed'] += 1
                results['errors'].append({
                    'connection_id': str(connection.id),
                    'app_name': connection.app_name,
                    'error': 'Update failed'
                })
        except Exception as e:
            results['failed'] += 1
            results['errors'].append({
                'connection_id': str(connection.id),
                'app_name': connection.app_name,
                'error': str(e)
            })
            logger.error(
                f"Failed to update blob for connection {connection.id}: {e}",
                exc_info=True
            )
    
    return results


def get_connection_summary(user: ZKUser) -> Dict[str, Any]:
    """
    Get a summary of user's connections.
    
    Args:
        user: The user
        
    Returns:
        Dict with connection summary
    """
    from .connection_registry import connection_registry
    return connection_registry.get_user_connections_summary(user)


def revoke_all_connections(user: ZKUser, reason: Optional[str] = None) -> int:
    """
    Revoke all connections for a user.
    Useful for account deletion or security incidents.
    
    Args:
        user: The user
        reason: Optional reason for revocation
        
    Returns:
        Number of connections revoked
    """
    connections = connection_service.list_connections(user, include_revoked=False)
    count = 0
    
    for connection in connections:
        try:
            connection_service.revoke_connection(user, str(connection.id))
            count += 1
            logger.info(
                f"Revoked connection {connection.id} for user {user.id}"
                f"{f' (reason: {reason})' if reason else ''}"
            )
        except Exception as e:
            logger.error(
                f"Failed to revoke connection {connection.id}: {e}",
                exc_info=True
            )
    
    return count


def get_app_metadata(client_id: str) -> Optional[Dict[str, Any]]:
    """
    Get app metadata from registry.
    
    Args:
        client_id: OAuth app client ID
        
    Returns:
        App metadata dict or None
    """
    from .connection_registry import connection_registry
    return connection_registry.get_app_metadata(client_id)


def sync_connection_metadata(
    client_id: str,
    name: Optional[str] = None,
    logo: Optional[str] = None,
    description: Optional[str] = None
) -> bool:
    """
    Sync connection metadata across all connections for an app.
    
    Args:
        client_id: OAuth app client ID
        name: App name
        logo: App logo URL
        description: App description
        
    Returns:
        True if synced, False otherwise
    """
    from .connection_registry import connection_registry
    return connection_registry.update_app_metadata(
        client_id=client_id,
        name=name,
        logo=logo,
        description=description
    )


def check_connection_health(connection: UserAppConnection) -> Dict[str, Any]:
    """
    Check health of a connection.
    
    Args:
        connection: UserAppConnection instance
        
    Returns:
        Dict with health information
    """
    health = {
        'is_active': connection.is_active,
        'has_blob': bool(connection.encrypted_sharing_blob),
        'blob_age_days': None,
        'last_accessed_days_ago': None,
        'scopes_count': len(connection.approved_scopes or []),
        'issues': []
    }
    
    # Check blob age
    if connection.sharing_blob_encrypted_at:
        age = (timezone.now() - connection.sharing_blob_encrypted_at).days
        health['blob_age_days'] = age
        if age > 30:
            health['issues'].append('Sharing blob is older than 30 days')
    
    # Check last accessed
    if connection.last_accessed:
        days_ago = (timezone.now() - connection.last_accessed).days
        health['last_accessed_days_ago'] = days_ago
        if days_ago > 90:
            health['issues'].append('Connection not accessed in 90+ days')
    
    # Check if active but no blob
    if connection.is_active and not connection.encrypted_sharing_blob:
        health['issues'].append('Active connection has no sharing blob')
    
    # Check if has scopes but no blob
    if connection.approved_scopes and not connection.encrypted_sharing_blob:
        health['issues'].append('Connection has approved scopes but no sharing blob')
    
    health['is_healthy'] = len(health['issues']) == 0
    
    return health

