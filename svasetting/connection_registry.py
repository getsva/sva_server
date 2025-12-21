"""
Connection Registry
Centralized registry for app metadata and connection information.

This registry provides:
- App metadata caching
- Connection statistics
- App discovery
- Metadata synchronization with OAuth server
"""
import logging
from typing import Optional, Dict, Any, List
from django.db import models
from django.utils import timezone
from django.core.cache import cache
from .models import UserAppConnection
from authentication.models import ZKUser

logger = logging.getLogger(__name__)


class ConnectionRegistry:
    """
    Registry for managing app metadata and connection information.
    Provides caching and synchronization with OAuth server.
    """
    
    CACHE_PREFIX = 'app_metadata:'
    CACHE_TIMEOUT = 3600  # 1 hour
    
    @staticmethod
    def get_app_metadata(client_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get app metadata by client_id.
        First checks cache, then database, then OAuth server.
        
        Args:
            client_id: OAuth app client ID
            use_cache: Whether to use cache
            
        Returns:
            Dict with app metadata or None
        """
        cache_key = f"{ConnectionRegistry.CACHE_PREFIX}{client_id}"
        
        # Try cache first
        if use_cache:
            cached = cache.get(cache_key)
            if cached:
                return cached
        
        # Try database (from UserAppConnection)
        try:
            connection = UserAppConnection.objects.filter(
                client_id=client_id,
                is_active=True
            ).first()
            
            if connection:
                metadata = {
                    'client_id': client_id,
                    'name': connection.app_name,
                    'logo': connection.app_logo,
                    'description': connection.app_description,
                    'cached_at': timezone.now().isoformat(),
                    'source': 'database'
                }
                
                # Cache it
                if use_cache:
                    cache.set(cache_key, metadata, ConnectionRegistry.CACHE_TIMEOUT)
                
                return metadata
        except Exception as e:
            logger.warning(f"Failed to get app metadata from database: {e}")
        
        # Could fetch from OAuth server here if needed
        # For now, return None if not found
        return None
    
    @staticmethod
    def update_app_metadata(
        client_id: str,
        name: Optional[str] = None,
        logo: Optional[str] = None,
        description: Optional[str] = None
    ) -> bool:
        """
        Update app metadata in all connections.
        This is called when app metadata changes in OAuth server.
        
        Args:
            client_id: OAuth app client ID
            name: App name
            logo: App logo URL
            description: App description
            
        Returns:
            True if updated, False otherwise
        """
        try:
            # Update all connections with this client_id
            updated = UserAppConnection.objects.filter(
                client_id=client_id
            ).update(
                app_name=name or models.F('app_name'),
                app_logo=logo or models.F('app_logo'),
                app_description=description or models.F('app_description')
            )
            
            # Invalidate cache
            cache_key = f"{ConnectionRegistry.CACHE_PREFIX}{client_id}"
            cache.delete(cache_key)
            
            logger.info(
                f"Updated metadata for {updated} connections with client_id {client_id}"
            )
            
            return updated > 0
        except Exception as e:
            logger.error(f"Failed to update app metadata: {e}", exc_info=True)
            return False
    
    @staticmethod
    def get_connection_stats(user: Optional[ZKUser] = None) -> Dict[str, Any]:
        """
        Get connection statistics.
        
        Args:
            user: Optional user to filter by
            
        Returns:
            Dict with statistics
        """
        queryset = UserAppConnection.objects.all()
        if user:
            queryset = queryset.filter(user=user)
        
        total = queryset.count()
        active = queryset.filter(is_active=True).count()
        revoked = queryset.filter(is_active=False).count()
        
        # Get unique apps
        unique_apps = queryset.values('client_id').distinct().count()
        
        # Get connections by app
        app_counts = {}
        for connection in queryset.values('client_id', 'app_name').distinct():
            client_id = connection['client_id']
            app_counts[client_id] = {
                'name': connection['app_name'],
                'count': queryset.filter(client_id=client_id).count(),
                'active': queryset.filter(client_id=client_id, is_active=True).count()
            }
        
        return {
            'total_connections': total,
            'active_connections': active,
            'revoked_connections': revoked,
            'unique_apps': unique_apps,
            'app_counts': app_counts
        }
    
    @staticmethod
    def get_user_connections_summary(user: ZKUser) -> Dict[str, Any]:
        """
        Get summary of user's connections.
        
        Args:
            user: The user
            
        Returns:
            Dict with connection summary
        """
        connections = UserAppConnection.objects.filter(user=user)
        active = connections.filter(is_active=True)
        revoked = connections.filter(is_active=False)
        
        # Group by app
        apps = {}
        for conn in active:
            if conn.client_id not in apps:
                apps[conn.client_id] = {
                    'name': conn.app_name,
                    'logo': conn.app_logo,
                    'connections': []
                }
            apps[conn.client_id]['connections'].append({
                'id': str(conn.id),
                'connected_at': conn.connected_at.isoformat(),
                'last_accessed': conn.last_accessed.isoformat(),
                'scopes': conn.approved_scopes or []
            })
        
        return {
            'total': connections.count(),
            'active': active.count(),
            'revoked': revoked.count(),
            'apps': apps
        }
    
    @staticmethod
    def discover_apps(user: ZKUser, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Discover popular apps that user hasn't connected yet.
        Returns apps that other users have connected to.
        
        Args:
            user: The user
            limit: Maximum number of apps to return
            
        Returns:
            List of app metadata dicts
        """
        # Get client_ids that user has already connected
        user_client_ids = set(
            UserAppConnection.objects.filter(user=user)
            .values_list('client_id', flat=True)
        )
        
        # Get popular apps (by connection count) that user hasn't connected
        popular_apps = (
            UserAppConnection.objects
            .exclude(client_id__in=user_client_ids)
            .values('client_id', 'app_name', 'app_logo', 'app_description')
            .annotate(
                connection_count=models.Count('id')
            )
            .order_by('-connection_count')[:limit]
        )
        
        return [
            {
                'client_id': app['client_id'],
                'name': app['app_name'],
                'logo': app['app_logo'],
                'description': app['app_description'],
                'popularity': app['connection_count']
            }
            for app in popular_apps
        ]
    
    @staticmethod
    def sync_app_metadata_from_oauth(
        client_id: str,
        oauth_server_url: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Sync app metadata from OAuth server.
        This can be called periodically to keep metadata up to date.
        
        Args:
            client_id: OAuth app client ID
            oauth_server_url: Optional OAuth server URL
            
        Returns:
            App metadata dict or None
        """
        # This would make an API call to OAuth server
        # For now, return None (to be implemented)
        logger.info(f"Sync app metadata for {client_id} from OAuth server (not implemented)")
        return None
    
    @staticmethod
    def invalidate_cache(client_id: str) -> None:
        """
        Invalidate cache for an app.
        
        Args:
            client_id: OAuth app client ID
        """
        cache_key = f"{ConnectionRegistry.CACHE_PREFIX}{client_id}"
        cache.delete(cache_key)
        logger.debug(f"Invalidated cache for {client_id}")
    
    @staticmethod
    def get_app_connections(client_id: str, active_only: bool = True) -> List[UserAppConnection]:
        """
        Get all connections for an app.
        
        Args:
            client_id: OAuth app client ID
            active_only: Only return active connections
            
        Returns:
            List of UserAppConnection instances
        """
        queryset = UserAppConnection.objects.filter(client_id=client_id)
        if active_only:
            queryset = queryset.filter(is_active=True)
        return list(queryset.order_by('-connected_at'))


# Singleton instance
connection_registry = ConnectionRegistry()

