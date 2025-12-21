"""
Batch Operations for Connection Management
Provides efficient bulk operations for connections.
"""
import logging
from typing import List, Dict, Any, Optional
from django.db import transaction
from django.utils import timezone
from .models import UserAppConnection
from .connection_service import connection_service
from .data_sharing_service import data_sharing_service
from .connection_registry import connection_registry
from authentication.models import ZKUser

logger = logging.getLogger(__name__)


class BatchConnectionOperations:
    """
    Batch operations for connection management.
    Provides efficient bulk operations.
    """
    
    @staticmethod
    @transaction.atomic
    def bulk_revoke_connections(
        user: ZKUser,
        connection_ids: List[str],
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Bulk revoke connections for a user.
        
        Args:
            user: The user
            connection_ids: List of connection IDs to revoke
            reason: Optional reason for revocation
            
        Returns:
            Dict with results
        """
        results = {
            'total': len(connection_ids),
            'revoked': 0,
            'failed': 0,
            'errors': []
        }
        
        for connection_id in connection_ids:
            try:
                connection = connection_service.revoke_connection(
                    user=user,
                    connection_id=connection_id
                )
                if connection:
                    results['revoked'] += 1
                    logger.info(
                        f"Bulk revoked connection {connection_id} for user {user.id}"
                        f"{f' (reason: {reason})' if reason else ''}"
                    )
                else:
                    results['failed'] += 1
                    results['errors'].append({
                        'connection_id': connection_id,
                        'error': 'Connection not found'
                    })
            except Exception as e:
                results['failed'] += 1
                results['errors'].append({
                    'connection_id': connection_id,
                    'error': str(e)
                })
                logger.error(
                    f"Failed to revoke connection {connection_id}: {e}",
                    exc_info=True
                )
        
        return results
    
    @staticmethod
    @transaction.atomic
    def bulk_update_metadata(
        client_id: str,
        name: Optional[str] = None,
        logo: Optional[str] = None,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Bulk update metadata for all connections with a client_id.
        
        Args:
            client_id: OAuth app client ID
            name: Optional app name
            logo: Optional app logo URL
            description: Optional app description
            
        Returns:
            Dict with results
        """
        try:
            updated = connection_registry.update_app_metadata(
                client_id=client_id,
                name=name,
                logo=logo,
                description=description
            )
            
            return {
                'success': True,
                'client_id': client_id,
                'updated': updated
            }
        except Exception as e:
            logger.error(
                f"Failed to bulk update metadata for {client_id}: {e}",
                exc_info=True
            )
            return {
                'success': False,
                'client_id': client_id,
                'error': str(e)
            }
    
    @staticmethod
    def bulk_mark_for_blob_update(
        user: Optional[ZKUser] = None,
        connection_ids: Optional[List[str]] = None,
        client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Bulk mark connections for blob update.
        
        Args:
            user: Optional user to filter by
            connection_ids: Optional list of specific connection IDs
            client_id: Optional client_id to filter by
            
        Returns:
            Dict with results
        """
        results = {
            'marked': 0,
            'failed': 0,
            'errors': []
        }
        
        try:
            if connection_ids:
                # Mark specific connections
                for connection_id in connection_ids:
                    try:
                        if user:
                            connection = connection_service.get_connection_by_id(
                                user=user,
                                connection_id=connection_id,
                                active_only=True
                            )
                        else:
                            connection = UserAppConnection.objects.get(
                                id=connection_id,
                                is_active=True
                            )
                        
                        if connection:
                            data_sharing_service.mark_blob_for_update(
                                connection.user,
                                str(connection.id)
                            )
                            results['marked'] += 1
                        else:
                            results['failed'] += 1
                            results['errors'].append({
                                'connection_id': connection_id,
                                'error': 'Connection not found or inactive'
                            })
                    except Exception as e:
                        results['failed'] += 1
                        results['errors'].append({
                            'connection_id': connection_id,
                            'error': str(e)
                        })
            elif client_id:
                # Mark all connections for a client_id
                connections = connection_registry.get_app_connections(
                    client_id=client_id,
                    active_only=True
                )
                
                for connection in connections:
                    try:
                        data_sharing_service.mark_blob_for_update(
                            connection.user,
                            str(connection.id)
                        )
                        results['marked'] += 1
                    except Exception as e:
                        results['failed'] += 1
                        results['errors'].append({
                            'connection_id': str(connection.id),
                            'error': str(e)
                        })
            elif user:
                # Mark all connections for a user
                count = data_sharing_service.mark_blob_for_update(user)
                results['marked'] = count
            else:
                return {
                    'error': 'Must provide user, connection_ids, or client_id'
                }
            
            return results
        except Exception as e:
            logger.error(f"Failed to bulk mark for blob update: {e}", exc_info=True)
            return {
                'error': str(e)
            }
    
    @staticmethod
    def bulk_health_check(
        user: Optional[ZKUser] = None,
        client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Bulk health check for connections.
        
        Args:
            user: Optional user to filter by
            client_id: Optional client_id to filter by
            
        Returns:
            Dict with health check results
        """
        from .connection_utils import check_connection_health
        
        queryset = UserAppConnection.objects.filter(is_active=True)
        
        if user:
            queryset = queryset.filter(user=user)
        
        if client_id:
            queryset = queryset.filter(client_id=client_id)
        
        connections = queryset.all()
        
        results = {
            'total': connections.count(),
            'healthy': 0,
            'unhealthy': 0,
            'issues': []
        }
        
        for connection in connections:
            health = check_connection_health(connection)
            
            if health['is_healthy']:
                results['healthy'] += 1
            else:
                results['unhealthy'] += 1
                results['issues'].append({
                    'connection_id': str(connection.id),
                    'app_name': connection.app_name,
                    'user_id': str(connection.user_id),
                    'issues': health['issues']
                })
        
        return results
    
    @staticmethod
    @transaction.atomic
    def bulk_update_scopes(
        user: ZKUser,
        updates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Bulk update scopes for multiple connections.
        
        Args:
            user: The user
            updates: List of dicts with 'connection_id' and 'scopes'
            
        Returns:
            Dict with results
        """
        results = {
            'total': len(updates),
            'updated': 0,
            'failed': 0,
            'errors': []
        }
        
        for update in updates:
            connection_id = update.get('connection_id')
            scopes = update.get('scopes')
            
            if not connection_id or scopes is None:
                results['failed'] += 1
                results['errors'].append({
                    'update': update,
                    'error': 'Missing connection_id or scopes'
                })
                continue
            
            try:
                connection = connection_service.update_scopes(
                    user=user,
                    connection_id=connection_id,
                    new_scopes=scopes
                )
                
                if connection:
                    results['updated'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append({
                        'connection_id': connection_id,
                        'error': 'Connection not found or inactive'
                    })
            except Exception as e:
                results['failed'] += 1
                results['errors'].append({
                    'connection_id': connection_id,
                    'error': str(e)
                })
                logger.error(
                    f"Failed to update scopes for connection {connection_id}: {e}",
                    exc_info=True
                )
        
        return results


# Singleton instance
batch_operations = BatchConnectionOperations()

