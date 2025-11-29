# authentication/models.py

from django.db import models
from django.utils import timezone
from django.conf import settings
import uuid


class ZKUser(models.Model):
    """
    Zero-Knowledge User Model with Passkey Support and Device Fingerprinting
    
    Stores ONLY encrypted data and authentication proofs.
    Now supports both master key and passkey authentication.
    Updated to support email-based authentication and device fingerprinting.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Public identifier (SHA-256 hash of email for lookup - easier to remember)
    email_hash = models.CharField(max_length=64, unique=True, db_index=True, null=True, blank=True)
    
    # Legacy username support (optional, for backward compatibility)
    username_hash = models.CharField(max_length=64, unique=True, db_index=True, null=True, blank=True)
    
    # Encrypted user data blob
    encrypted_data = models.TextField()
    
    # Salt used for key derivation
    salt = models.CharField(max_length=255)
    
    # Authentication proof derived from master key
    auth_proof = models.CharField(max_length=255, unique=True)
    
    # Device fingerprint (SHA-256 hash for one device per user)
    device_fingerprint = models.CharField(
        max_length=64, 
        unique=True, 
        db_index=True,
        null=True, 
        blank=True,
        help_text="SHA-256 hash of device fingerprint for one device per user"
    )
    
    # Passkey/WebAuthn support (optional)
    passkey_credential_id = models.CharField(
        max_length=512, 
        null=True, 
        blank=True,
        help_text="WebAuthn credential ID for biometric authentication"
    )
    passkey_public_key = models.TextField(
        null=True, 
        blank=True,
        help_text="Public key for passkey verification (not used for ZK, stored for future verification)"
    )
    has_passkey = models.BooleanField(
        default=False,
        help_text="Whether user has registered a passkey"
    )
    
    # Email verification status
    email_verified = models.BooleanField(
        default=False,
        help_text="Whether the user's email has been verified"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # Account status
    is_active = models.BooleanField(default=True)
    
    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False
    
    class Meta:
        db_table = 'zk_users'
        indexes = [
            models.Index(fields=['auth_proof']),
            models.Index(fields=['email_hash']),
            models.Index(fields=['username_hash']),
            models.Index(fields=['passkey_credential_id']),
            models.Index(fields=['device_fingerprint']),
        ]
        verbose_name = 'Zero-Knowledge User'
        verbose_name_plural = 'Zero-Knowledge Users'
    
    def __str__(self):
        auth_method = "Passkey" if self.has_passkey else "Master Key"
        return f"ZKUser {self.id} ({auth_method})"
    
    def __repr__(self):
        return f"<ZKUser id={self.id} active={self.is_active} passkey={self.has_passkey}>"


class ZKRefreshToken(models.Model):
    """
    Refresh tokens for maintaining user sessions with device fingerprinting
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser, 
        on_delete=models.CASCADE, 
        related_name='refresh_tokens'
    )
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    # Track authentication method used
    auth_method = models.CharField(
        max_length=20,
        choices=[('master_key', 'Master Key'), ('passkey', 'Passkey')],
        default='master_key'
    )
    
    # Device fingerprint for session tracking
    device_fingerprint = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="SHA-256 hash of device fingerprint for session tracking"
    )
    
    # Optional: Track device/IP
    device_info = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    
    class Meta:
        db_table = 'zk_refresh_tokens'
        verbose_name = 'Refresh Token'
        verbose_name_plural = 'Refresh Tokens'
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Refresh Token for {self.user.id} ({self.auth_method})"


class ZKPasswordResetToken(models.Model):
    """
    Password reset tokens
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(ZKUser, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    old_salt = models.CharField(max_length=255)
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'zk_password_reset_tokens'
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'
        ordering = ['-created_at']
    
    @property
    def is_expired(self):
        from datetime import timedelta
        return timezone.now() > (self.created_at + timedelta(hours=1))
    
    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
    
    def __str__(self):
        return f"Password Reset Token for {self.user.id}"


class ZKEmailVerificationToken(models.Model):
    """
    Email verification tokens for registration with device fingerprinting
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email_hash = models.CharField(max_length=64, unique=True, db_index=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_used = models.BooleanField(default=False)
    
    # Store encrypted registration data until verification
    encrypted_data = models.TextField()
    salt = models.CharField(max_length=255)
    auth_proof = models.CharField(max_length=255)
    username_hash = models.CharField(max_length=64)
    
    # Device fingerprint for registration
    device_fingerprint = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="SHA-256 hash of device fingerprint for registration"
    )
    
    # Optional passkey data
    passkey_credential_id = models.CharField(max_length=512, null=True, blank=True)
    passkey_public_key = models.TextField(null=True, blank=True)
    use_both_methods = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'zk_email_verification_tokens'
        verbose_name = 'Email Verification Token'
        verbose_name_plural = 'Email Verification Tokens'
        ordering = ['-created_at']
    
    @property
    def is_expired(self):
        from datetime import timedelta
        return timezone.now() > (self.created_at + timedelta(hours=24))
    
    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
    
    def __str__(self):
        return f"Email Verification Token for {self.email_hash[:8]}..."


class ZKTwoFactorLoginSession(models.Model):
    """
    Temporary session for 2FA verification during login
    Stores encrypted data temporarily until 2FA is verified
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='two_factor_login_sessions'
    )
    temp_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    encrypted_data = models.TextField()
    salt = models.CharField(max_length=255)
    device_fingerprint = models.CharField(max_length=64, null=True, blank=True)
    auth_method = models.CharField(
        max_length=20,
        choices=[('master_key', 'Master Key'), ('passkey', 'Passkey')],
        default='master_key'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'zk_two_factor_login_sessions'
        verbose_name = '2FA Login Session'
        verbose_name_plural = '2FA Login Sessions'
        ordering = ['-created_at']
    
    @property
    def is_expired(self):
        from datetime import timedelta
        return timezone.now() > (self.created_at + timedelta(minutes=5))
    
    @property
    def is_valid(self):
        return not self.is_expired
    
    def __str__(self):
        return f"2FA Login Session for {self.user.id}"


class ZKTwoFactorAuth(models.Model):
    """
    Two-Factor Authentication (TOTP) for ZK Users
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='two_factor_auth'
    )
    
    # TOTP secret key (encrypted or hashed)
    totp_secret = models.CharField(
        max_length=255,
        help_text="TOTP secret key for generating codes"
    )
    
    # Whether 2FA is enabled
    is_enabled = models.BooleanField(
        default=False,
        help_text="Whether 2FA is currently enabled"
    )
    
    # Backup codes (encrypted)
    backup_codes = models.TextField(
        null=True,
        blank=True,
        help_text="JSON array of backup codes (encrypted)"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'zk_two_factor_auth'
        verbose_name = 'Two-Factor Authentication'
        verbose_name_plural = 'Two-Factor Authentications'
    
    def __str__(self):
        return f"2FA for {self.user.id} ({'Enabled' if self.is_enabled else 'Disabled'})"