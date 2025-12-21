"""
Signal handlers for connection management and data sharing.
Provides automatic updates when user data or connections change.
"""
import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import UserAppConnection
from .data_sharing_service import (
    data_sharing_service,
    user_data_changed,
    sharing_blob_updated,
    connection_scopes_changed
)
from .connection_registry import connection_registry

logger = logging.getLogger(__name__)


@receiver(user_data_changed)
def handle_user_data_changed(sender, user, connection, **kwargs):
    """
    Handle user data changed signal.
    Marks connections for blob update.
    """
    if connection:
        # Specific connection needs update
        logger.info(
            f"User data changed for connection {connection.id}, "
            f"marking for blob update"
        )
        # Client will handle the actual update
    else:
        # All connections need update
        count = data_sharing_service.mark_blob_for_update(user)
        logger.info(
            f"User data changed for user {user.id}, "
            f"marked {count} connections for blob update"
        )


@receiver(connection_scopes_changed)
def handle_connection_scopes_changed(sender, connection, old_scopes, new_scopes, **kwargs):
    """
    Handle connection scopes changed signal.
    Marks connection for blob update.
    """
    logger.info(
        f"Scopes changed for connection {connection.id}: "
        f"{old_scopes} -> {new_scopes}, marking for blob update"
    )
    # Client will handle the actual update


@receiver(sharing_blob_updated)
def handle_sharing_blob_updated(sender, connection, timestamp, **kwargs):
    """
    Handle sharing blob updated signal.
    Triggers webhooks if configured.
    """
    logger.debug(
        f"Sharing blob updated for connection {connection.id} at {timestamp}"
    )
    
    # Trigger webhook if configured
    try:
        from .webhooks import webhook_service
        webhook_service.notify_sharing_blob_updated(connection)
    except Exception as e:
        logger.warning(f"Failed to send webhook for blob update: {e}")


@receiver(post_save, sender=UserAppConnection)
def handle_connection_saved(sender, instance, created, **kwargs):
    """
    Handle connection saved signal.
    Invalidates cache and updates registry.
    """
    # Invalidate cache for this app
    connection_registry.invalidate_cache(instance.client_id)
    
    if created:
        logger.info(
            f"New connection created: {instance.id} for app {instance.app_name}"
        )
    else:
        logger.debug(
            f"Connection updated: {instance.id} for app {instance.app_name}"
        )


@receiver(post_delete, sender=UserAppConnection)
def handle_connection_deleted(sender, instance, **kwargs):
    """
    Handle connection deleted signal.
    Invalidates cache.
    """
    connection_registry.invalidate_cache(instance.client_id)
    logger.info(
        f"Connection deleted: {instance.id} for app {instance.app_name}"
    )

