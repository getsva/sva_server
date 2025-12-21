from django.db import models
from django.utils import timezone
from authentication.models import ZKUser
import uuid
import json


class UserIdentityLevel(models.Model):
    """
    Tracks user's identity verification levels
    Level 0: Anonymous (default)
    Level 1: Email + Phone verified
    Level 2: Government ID verified
    Level 3: Professional credentials verified
    """
    IDENTITY_LEVELS = [
        (0, 'Anonymous'),
        (1, 'Basic Verified'),
        (2, 'Government ID Verified'),
        (3, 'Professionally Verified'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(ZKUser, on_delete=models.CASCADE, related_name='identity_level')
    
    # Current identity level
    current_level = models.IntegerField(choices=IDENTITY_LEVELS, default=0)
    
    # Encrypted verification data (stores proof of verification)
    encrypted_verification_data = models.TextField(blank=True, null=True)
    
    # Verification timestamps
    email_verified_at = models.DateTimeField(null=True, blank=True)
    phone_verified_at = models.DateTimeField(null=True, blank=True)
    govt_id_verified_at = models.DateTimeField(null=True, blank=True)
    professional_verified_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_identity_levels'
        verbose_name = 'User Identity Level'
        verbose_name_plural = 'User Identity Levels'
    
    def __str__(self):
        return f"{self.user.id} - Level {self.current_level}"


class ConnectedService(models.Model):
    """
    Tracks services/websites where user has shared their identity
    Stores encrypted connection details and permission levels
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(ZKUser, on_delete=models.CASCADE, related_name='connected_services')
    
    # Service identification (encrypted)
    encrypted_service_data = models.TextField()
    
    # What level of identity was shared (0-3)
    shared_identity_level = models.IntegerField(default=0)
    
    # Connection metadata
    connected_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(default=timezone.now)
    
    # Revocation status
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    # Access permissions (encrypted)
    encrypted_permissions = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'connected_services'
        verbose_name = 'Connected Service'
        verbose_name_plural = 'Connected Services'
        ordering = ['-connected_at']
    
    def __str__(self):
        return f"{self.user.id} - Service {self.id}"


class UserAppConnection(models.Model):
    """
    Tracks OAuth app connections where user has consented to share data
    This is separate from ConnectedService - this is specifically for OAuth apps
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(ZKUser, on_delete=models.CASCADE, related_name='app_connections')
    
    # OAuth app identification
    client_id = models.CharField(max_length=255, db_index=True, help_text="OAuth app client_id")
    
    # Cached app metadata (from OAuth server)
    app_name = models.CharField(max_length=255)
    app_logo = models.URLField(blank=True, null=True)
    app_description = models.TextField(blank=True, null=True)
    
    # Approved scopes (stored as JSON array)
    approved_scopes = models.JSONField(default=list, help_text="List of scopes user has approved")
    
    # Encrypted sharing blob (Google OAuth style - pre-encrypted data for instant sharing)
    # This blob contains the user data for approved scopes, encrypted client-side
    # When scopes change, this blob is updated instantly (live updates)
    encrypted_sharing_blob = models.TextField(blank=True, null=True, help_text="Pre-encrypted sharing data blob for instant access")
    sharing_blob_salt = models.TextField(blank=True, null=True, help_text="Salt for decrypting the sharing blob (base64 encoded)")
    sharing_blob_encrypted_at = models.DateTimeField(null=True, blank=True, help_text="When the sharing blob was last encrypted/updated")
    
    # Connection metadata
    connected_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(default=timezone.now)
    last_scope_update = models.DateTimeField(null=True, blank=True)
    
    # Revocation status
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'user_app_connections'
        verbose_name = 'User App Connection'
        verbose_name_plural = 'User App Connections'
        ordering = ['-connected_at']
        unique_together = [['user', 'client_id']]
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['client_id', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.user.id} - {self.app_name} ({self.client_id})"
    
    def revoke(self):
        """Revoke access to this app"""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=['is_active', 'revoked_at'])
    
    def update_scopes(self, new_scopes):
        """
        Update approved scopes with proper normalization and validation
        Production-level: Ensures data consistency
        """
        # Normalize: ensure it's a list, remove duplicates, sort for consistency
        if not isinstance(new_scopes, list):
            new_scopes = list(new_scopes) if new_scopes else []
        
        # Remove duplicates and sort for consistency
        normalized_scopes = sorted(list(set(new_scopes)))
        
        # Update fields
        self.approved_scopes = normalized_scopes
        self.last_scope_update = timezone.now()
        self.last_accessed = timezone.now()
        
        # Save with explicit field update
        self.save(update_fields=['approved_scopes', 'last_scope_update', 'last_accessed'])


class UserPreferences(models.Model):
    """
    User preferences and settings (all encrypted)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(ZKUser, on_delete=models.CASCADE, related_name='preferences')
    
    # Encrypted preferences blob
    encrypted_preferences = models.TextField()
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_preferences'
        verbose_name = 'User Preferences'
        verbose_name_plural = 'User Preferences'
    
    def __str__(self):
        return f"Preferences for {self.user.id}"


class SecurityLog(models.Model):
    """
    Security audit log for user actions (minimal PII)
    """
    LOG_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('password_change', 'Password Changed'),
        ('identity_upgrade', 'Identity Level Upgraded'),
        ('identity_downgrade', 'Identity Level Downgraded'),
        ('service_connected', 'Service Connected'),
        ('service_revoked', 'Service Revoked'),
        ('app_connected', 'App Connected'),
        ('app_revoked', 'App Access Revoked'),
        ('app_scopes_updated', 'App Scopes Updated'),
        ('data_export', 'Data Exported'),
        ('account_settings', 'Account Settings Changed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(ZKUser, on_delete=models.CASCADE, related_name='security_logs')
    
    log_type = models.CharField(max_length=50, choices=LOG_TYPES)
    
    # Encrypted details (if needed)
    encrypted_details = models.TextField(blank=True, null=True)
    
    # Metadata (non-encrypted for auditing)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'security_logs'
        verbose_name = 'Security Log'
        verbose_name_plural = 'Security Logs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.log_type} - {self.created_at}"