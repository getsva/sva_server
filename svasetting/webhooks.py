"""
Webhook Support for Connection Events
Provides webhook notifications for connection and data sharing events.
"""
import logging
import requests
import json
from typing import Dict, Any, Optional, List
from django.conf import settings
from django.utils import timezone
from .models import UserAppConnection

logger = logging.getLogger(__name__)


class WebhookService:
    """
    Service for sending webhook notifications.
    """
    
    @staticmethod
    def send_webhook(
        url: str,
        event: str,
        data: Dict[str, Any],
        secret: Optional[str] = None,
        timeout: int = 5
    ) -> bool:
        """
        Send webhook notification.
        
        Args:
            url: Webhook URL
            event: Event type
            data: Event data
            secret: Optional webhook secret for signing
            timeout: Request timeout in seconds
            
        Returns:
            True if successful, False otherwise
        """
        payload = {
            'event': event,
            'timestamp': timezone.now().isoformat(),
            'data': data
        }
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'SVA-Webhook/1.0'
        }
        
        # Add signature if secret provided
        if secret:
            import hmac
            import hashlib
            import base64
            
            payload_str = json.dumps(payload, sort_keys=True)
            signature = hmac.new(
                secret.encode('utf-8'),
                payload_str.encode('utf-8'),
                hashlib.sha256
            ).digest()
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            headers['X-Webhook-Signature'] = f'sha256={signature_b64}'
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(
                    f"Webhook sent successfully: {event} to {url}"
                )
                return True
            else:
                logger.warning(
                    f"Webhook failed: {event} to {url}, "
                    f"status: {response.status_code}"
                )
                return False
        except Exception as e:
            logger.error(
                f"Webhook error: {event} to {url}, error: {e}",
                exc_info=True
            )
            return False
    
    @staticmethod
    def notify_connection_created(connection: UserAppConnection) -> bool:
        """
        Notify webhook about connection creation.
        
        Args:
            connection: UserAppConnection instance
            
        Returns:
            True if sent, False otherwise
        """
        webhook_url = getattr(settings, 'CONNECTION_WEBHOOK_URL', None)
        if not webhook_url:
            return False
        
        data = {
            'connection_id': str(connection.id),
            'user_id': str(connection.user_id),
            'client_id': connection.client_id,
            'app_name': connection.app_name,
            'approved_scopes': connection.approved_scopes or [],
            'connected_at': connection.connected_at.isoformat()
        }
        
        return WebhookService.send_webhook(
            url=webhook_url,
            event='connection.created',
            data=data,
            secret=getattr(settings, 'CONNECTION_WEBHOOK_SECRET', None)
        )
    
    @staticmethod
    def notify_connection_revoked(connection: UserAppConnection) -> bool:
        """
        Notify webhook about connection revocation.
        
        Args:
            connection: UserAppConnection instance
            
        Returns:
            True if sent, False otherwise
        """
        webhook_url = getattr(settings, 'CONNECTION_WEBHOOK_URL', None)
        if not webhook_url:
            return False
        
        data = {
            'connection_id': str(connection.id),
            'user_id': str(connection.user_id),
            'client_id': connection.client_id,
            'app_name': connection.app_name,
            'revoked_at': connection.revoked_at.isoformat() if connection.revoked_at else None
        }
        
        return WebhookService.send_webhook(
            url=webhook_url,
            event='connection.revoked',
            data=data,
            secret=getattr(settings, 'CONNECTION_WEBHOOK_SECRET', None)
        )
    
    @staticmethod
    def notify_scopes_updated(
        connection: UserAppConnection,
        old_scopes: List[str],
        new_scopes: List[str]
    ) -> bool:
        """
        Notify webhook about scope updates.
        
        Args:
            connection: UserAppConnection instance
            old_scopes: Previous scopes
            new_scopes: New scopes
            
        Returns:
            True if sent, False otherwise
        """
        webhook_url = getattr(settings, 'CONNECTION_WEBHOOK_URL', None)
        if not webhook_url:
            return False
        
        data = {
            'connection_id': str(connection.id),
            'user_id': str(connection.user_id),
            'client_id': connection.client_id,
            'app_name': connection.app_name,
            'old_scopes': old_scopes,
            'new_scopes': new_scopes,
            'updated_at': timezone.now().isoformat()
        }
        
        return WebhookService.send_webhook(
            url=webhook_url,
            event='connection.scopes_updated',
            data=data,
            secret=getattr(settings, 'CONNECTION_WEBHOOK_SECRET', None)
        )
    
    @staticmethod
    def notify_sharing_blob_updated(connection: UserAppConnection) -> bool:
        """
        Notify webhook about sharing blob update.
        
        Args:
            connection: UserAppConnection instance
            
        Returns:
            True if sent, False otherwise
        """
        webhook_url = getattr(settings, 'CONNECTION_WEBHOOK_URL', None)
        if not webhook_url:
            return False
        
        data = {
            'connection_id': str(connection.id),
            'user_id': str(connection.user_id),
            'client_id': connection.client_id,
            'app_name': connection.app_name,
            'blob_updated_at': connection.sharing_blob_encrypted_at.isoformat() if connection.sharing_blob_encrypted_at else None
        }
        
        return WebhookService.send_webhook(
            url=webhook_url,
            event='connection.blob_updated',
            data=data,
            secret=getattr(settings, 'CONNECTION_WEBHOOK_SECRET', None)
        )


# Singleton instance
webhook_service = WebhookService()

