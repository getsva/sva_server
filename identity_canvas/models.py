from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils import timezone
from authentication.models import ZKUser
import uuid
import secrets
import hashlib


class IdentityCanvas(models.Model):
    """
    Zero-Knowledge Identity Canvas Model
    
    Stores encrypted identity blocks for users.
    All data is encrypted client-side before storage.
    Server never sees unencrypted identity data.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='identity_canvas'
    )
    
    # Encrypted blocks data (JSON array of blocks, encrypted client-side)
    encrypted_blocks = models.TextField(
        help_text="Encrypted JSON array of identity blocks"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Version tracking for optimistic locking (optional)
    version = models.IntegerField(default=1)
    
    class Meta:
        db_table = 'identity_canvas'
        verbose_name = 'Identity Canvas'
        verbose_name_plural = 'Identity Canvases'
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"Identity Canvas for {self.user.id}"
    
    def __repr__(self):
        return f"<IdentityCanvas id={self.id} user={self.user.id} version={self.version}>"


class CanvasHistory(models.Model):
    """
    Optional: Store version history of canvas changes for audit
    Only stores encrypted data, maintaining zero-knowledge
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    canvas = models.ForeignKey(
        IdentityCanvas,
        on_delete=models.CASCADE,
        related_name='history'
    )
    
    # Encrypted snapshot of blocks at this version
    encrypted_blocks_snapshot = models.TextField()
    
    # Version number
    version = models.IntegerField()
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Optional: Action that triggered this version
    action = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Action that created this version (create, update, delete)"
    )
    
    class Meta:
        db_table = 'canvas_history'
        verbose_name = 'Canvas History'
        verbose_name_plural = 'Canvas Histories'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['canvas', '-created_at']),
        ]
    
    def __str__(self):
        return f"Canvas {self.canvas.id} - Version {self.version}"


class VerificationCanvas(models.Model):
    """
    Stores encrypted verification blocks (separate from identity canvas).
    Each user has one verification canvas mirroring the identity canvas lifecycle.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='verification_canvas'
    )

    encrypted_blocks = models.TextField(
        help_text="Encrypted JSON array of verification blocks"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    version = models.IntegerField(default=1)

    class Meta:
        db_table = 'verification_canvas'
        verbose_name = 'Verification Canvas'
        verbose_name_plural = 'Verification Canvases'
        ordering = ['-updated_at']

    def __str__(self):
        return f"Verification Canvas for {self.user.id}"


class VerificationCanvasHistory(models.Model):
    """
    Optional history table for verification canvas updates (audit trail).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    canvas = models.ForeignKey(
        VerificationCanvas,
        on_delete=models.CASCADE,
        related_name='history'
    )
    encrypted_blocks_snapshot = models.TextField()
    version = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    action = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Action that created this version (create, update, delete)"
    )

    class Meta:
        db_table = 'verification_canvas_history'
        verbose_name = 'Verification Canvas History'
        verbose_name_plural = 'Verification Canvas Histories'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['canvas', '-created_at']),
        ]

    def __str__(self):
        return f"Verification Canvas {self.canvas.id} - Version {self.version}"


# ==================== VERIFICATION SYSTEM (Zero-Knowledge OTP) ====================

class VerificationBlockType(models.TextChoices):
    """Types of verifiable blocks - extensible for future blocks"""
    EMAIL = 'email', 'Email'
    PHONE = 'phone', 'Phone'
    PAN_CARD = 'pan_card', 'PAN Card'
    CRYPTO_WALLET = 'crypto_wallet', 'Crypto Wallet'
    EDUCATION = 'education', 'Education'
    EMPLOYMENT = 'employment', 'Employment'
    PROFESSIONAL_LICENSE = 'professional_license', 'Professional License'
    AADHAR = 'aadhar', 'Aadhaar Card'
    DRIVING_LICENSE = 'driving_license', 'Driving License'
    VOTER_ID = 'voter_id', 'Voter ID'
    PASSPORT = 'passport', 'Passport'


class VerifiableBlockOTP(models.Model):
    """
    Zero-Knowledge OTP Verification Model
    
    This model stores OTP verification tokens for verifiable blocks (email, phone, etc.).
    The actual block data (email address, phone number) is NEVER stored - only hashes.
    All data verification happens client-side using zero-knowledge principles.
    
    Architecture:
    - Server stores only hash of the value being verified (email_hash, phone_hash)
    - OTP is sent to the actual email/phone (server needs to temporarily know it)
    - OTP verification confirms ownership without storing the actual value
    - After verification, the verified hash is stored, but the original value is only in encrypted vault
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='verification_otps',
        help_text="User requesting verification"
    )
    
    # Block type being verified (email, phone, etc.)
    block_type = models.CharField(
        max_length=50,
        choices=VerificationBlockType.choices,
        help_text="Type of verifiable block (email, phone, etc.)"
    )
    
    # Hash of the value being verified (never store actual email/phone)
    value_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of the value being verified (email, phone, etc.)"
    )
    
    # OTP code (6-digit numeric code)
    otp_code = models.CharField(
        max_length=6,
        help_text="6-digit OTP code for verification"
    )
    
    # OTP expiration (15 minutes)
    expires_at = models.DateTimeField(
        help_text="When this OTP expires"
    )
    
    # Verification status
    is_verified = models.BooleanField(
        default=False,
        help_text="Whether this OTP has been successfully verified"
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when verification was completed"
    )
    
    # Attempts tracking (prevent brute force)
    attempts = models.IntegerField(
        default=0,
        help_text="Number of verification attempts"
    )
    max_attempts = models.IntegerField(
        default=5,
        help_text="Maximum allowed verification attempts"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'verifiable_block_otps'
        verbose_name = 'Verifiable Block OTP'
        verbose_name_plural = 'Verifiable Block OTPs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'block_type', 'is_verified']),
            models.Index(fields=['value_hash', 'is_verified']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"OTP for {self.block_type} ({self.user.id}) - {'Verified' if self.is_verified else 'Pending'}"
    
    @property
    def is_expired(self):
        """Check if OTP has expired"""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if OTP is valid (not expired, not verified, within attempt limit)"""
        return (
            not self.is_verified and
            not self.is_expired and
            self.attempts < self.max_attempts
        )
    
    @classmethod
    def generate_otp(cls):
        """Generate a 6-digit numeric OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    @classmethod
    def generate_hash(cls, value):
        """Generate SHA-256 hash of a value (for zero-knowledge storage)"""
        return hashlib.sha256(value.encode()).hexdigest()


class VerifiedBlock(models.Model):
    """
    Stores verification status for user's verifiable blocks
    
    This model tracks which blocks have been verified without storing
    the actual block data (which is encrypted in the vault).
    
    Zero-Knowledge Design:
    - Only stores hash of verified value (email_hash, phone_hash)
    - Actual values are encrypted client-side in IdentityCanvas
    - Server never sees unencrypted block data
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='verified_blocks',
        help_text="User who owns this verified block"
    )
    
    # Block type (email, phone, etc.)
    block_type = models.CharField(
        max_length=50,
        choices=VerificationBlockType.choices,
        help_text="Type of verifiable block"
    )
    
    # Hash of the verified value (never store actual value)
    value_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of the verified value"
    )
    
    # Verification metadata
    verified_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this block was verified"
    )
    
    # Optional: Verification method (otp, manual, etc.)
    verification_method = models.CharField(
        max_length=50,
        default='otp',
        help_text="Method used for verification"
    )
    
    class Meta:
        db_table = 'verified_blocks'
        verbose_name = 'Verified Block'
        verbose_name_plural = 'Verified Blocks'
        unique_together = [['user', 'block_type', 'value_hash']]
        indexes = [
            models.Index(fields=['user', 'block_type']),
            models.Index(fields=['value_hash']),
        ]
    
    def __str__(self):
        return f"{self.block_type} verified for {self.user.id}"


# ==================== USERNAME UNIQUENESS PROOF (Zero-Knowledge) ====================

class UsernameProof(models.Model):
    """
    Zero-Knowledge Username Uniqueness Proof Model
    
    Stores cryptographic proof of username uniqueness without revealing the actual username.
    Uses k-anonymity with prefix matching to check uniqueness while maintaining privacy.
    
    Zero-Knowledge Design:
    - Only stores final proof hash (SHA-256(username_hash + SECRET_PEPPER))
    - Username itself is encrypted in vault, never stored on server
    - Uniqueness checking uses prefix matching for k-anonymity
    - Server cannot reverse the proof to get the username
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='username_proof',
        help_text="User who owns this username"
    )
    
    # Final proof hash: SHA-256(username_hash + SECRET_PEPPER)
    # This prevents brute-force attacks while maintaining uniqueness
    proof_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hash of (username_hash + SECRET_PEPPER) for uniqueness proof"
    )
    
    # Hash prefix for k-anonymity lookups (first 8 characters)
    # Used for efficient prefix-based uniqueness checking
    prefix = models.CharField(
        max_length=8,
        db_index=True,
        help_text="First 8 characters of username hash for prefix matching"
    )
    
    # Store username_hash for k-anonymity prefix matching
    # This is needed to return matching hashes to client for local checking
    # Still maintains zero-knowledge as hash cannot be reversed to get username
    username_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of username (with public pepper) for prefix matching"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'username_proofs'
        verbose_name = 'Username Proof'
        verbose_name_plural = 'Username Proofs'
        indexes = [
            models.Index(fields=['prefix']),
            models.Index(fields=['proof_hash']),
        ]
    
    def __str__(self):
        return f"Username proof for {self.user.id}"
    
    @classmethod
    def generate_proof_hash(cls, username_hash: str, secret_pepper: str) -> str:
        """
        Generate final proof hash from username hash and secret pepper
        This is what gets stored on the server
        """
        combined = f"{username_hash}{secret_pepper}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @classmethod
    def get_prefix(cls, username_hash: str) -> str:
        """
        Extract prefix from username hash for k-anonymity lookups
        Using 8 characters provides good k-anonymity (2^32 possibilities)
        """
        return username_hash[:8]


# ==================== AADHAAR UNIQUENESS PROOF (Zero-Knowledge) ====================

class UniquenessProof(models.Model):
    """
    Zero-Knowledge Aadhaar Uniqueness Proof Model
    
    Stores cryptographic proof of Aadhaar uniqueness without revealing the actual Aadhaar number.
    Uses k-anonymity with prefix matching to check global uniqueness while maintaining privacy.
    
    Zero-Knowledge Design:
    - Only stores final_hash (SHA-256(aadhaar_hash + SECRET_PEPPER))
    - Aadhaar number itself is never stored on server
    - Uniqueness checking uses prefix matching for k-anonymity
    - Server cannot reverse the proof to get the Aadhaar number
    - Not linked to any user - just a global list of used Aadhaar hashes
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Final proof hash: SHA-256(aadhaar_hash + SECRET_PEPPER)
    # This prevents brute-force attacks while maintaining uniqueness
    final_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hash of (aadhaar_hash + SECRET_PEPPER) for uniqueness proof"
    )
    
    # Hash prefix for k-anonymity lookups (first 5 characters)
    # Used for efficient prefix-based uniqueness checking
    prefix = models.CharField(
        max_length=5,
        db_index=True,
        help_text="First 5 characters of aadhaar_hash for prefix matching"
    )
    
    # Store aadhaar_hash for k-anonymity prefix matching
    # This is needed to return matching hashes to client for local checking
    # Still maintains zero-knowledge as hash cannot be reversed to get Aadhaar number
    aadhaar_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of Aadhaar number (with public pepper) for prefix matching"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'uniqueness_proofs'
        verbose_name = 'Uniqueness Proof'
        verbose_name_plural = 'Uniqueness Proofs'
        indexes = [
            models.Index(fields=['prefix']),
            models.Index(fields=['final_hash']),
            models.Index(fields=['aadhaar_hash']),
        ]
    
    def __str__(self):
        return f"Uniqueness proof {self.prefix}..."
    
    @classmethod
    def generate_final_hash(cls, aadhaar_hash: str, secret_pepper: str) -> str:
        """
        Generate final proof hash from aadhaar hash and secret pepper
        This is what gets stored on the server
        """
        combined = f"{aadhaar_hash}{secret_pepper}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @classmethod
    def get_prefix(cls, aadhaar_hash: str) -> str:
        """
        Extract prefix from aadhaar hash for k-anonymity lookups
        Using 5 characters provides good k-anonymity (2^20 possibilities)
        """
        return aadhaar_hash[:5]


# ==================== SIGNALS ====================

@receiver(post_delete, sender=IdentityCanvas)
def delete_username_proof_on_canvas_delete(sender, instance, **kwargs):
    """
    Signal handler to delete username proof when identity canvas is deleted.
    
    Since username is stored as part of the encrypted blocks in the canvas,
    when the canvas is deleted, the username proof should also be deleted
    to maintain data consistency.
    """
    # Delete username proof associated with the user
    UsernameProof.objects.filter(user=instance.user).delete()


# ==================== DOCUMENT VERIFICATION MODELS ====================

class DocumentVerification(models.Model):
    """
    Model for storing document verification requests
    Supports manual document upload, third-party API, and institutional verification
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='document_verifications',
        help_text="User requesting document verification"
    )
    
    # Verification details
    block_type = models.CharField(
        max_length=50,
        choices=VerificationBlockType.choices,
        help_text="Type of document being verified"
    )
    
    # Hash of document identifier (never store actual document data)
    document_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of document identifier (e.g., PAN number, license number)"
    )
    
    # Verification method
    VERIFICATION_METHOD_CHOICES = [
        ('manual_upload', 'Manual Upload'),
        ('third_party', 'Third Party API'),
        ('institutional', 'Institutional Verification'),
    ]
    verification_method = models.CharField(
        max_length=50,
        choices=VERIFICATION_METHOD_CHOICES,
        help_text="Method used for verification"
    )
    
    # Verification status
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('verified', 'Verified'),
            ('rejected', 'Rejected'),
            ('expired', 'Expired'),
        ],
        default='pending'
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    
    # Optional: Verification details (encrypted metadata)
    verification_metadata = models.TextField(null=True, blank=True, help_text="Additional verification metadata (encrypted)")
    
    class Meta:
        db_table = 'document_verifications'
        verbose_name = 'Document Verification'
        verbose_name_plural = 'Document Verifications'
        indexes = [
            models.Index(fields=['user', 'block_type', 'status']),
            models.Index(fields=['document_hash', 'status']),
        ]
        unique_together = [['user', 'block_type', 'document_hash']]
    
    def __str__(self):
        return f"{self.block_type} verification for {self.user.id} - {self.status}"


class AadhaarVerificationSession(models.Model):
    """
    Stores metadata for Aadhaar OKYC sessions without persisting sensitive PII.
    Only hashes, reference IDs, and sanitized metadata are stored (zero-knowledge).
    """

    STATUS_PENDING = 'pending'
    STATUS_VERIFIED = 'verified'
    STATUS_FAILED = 'failed'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_VERIFIED, 'Verified'),
        (STATUS_FAILED, 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        ZKUser,
        on_delete=models.CASCADE,
        related_name='aadhaar_kyc_sessions',
        help_text="User that initiated the Aadhaar OKYC flow"
    )
    aadhaar_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of the Aadhaar number"
    )
    aadhaar_hash_with_pepper = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        db_index=True,
        help_text="SHA-256 hash of (Aadhaar number + PUBLIC_PEPPER) for uniqueness proof"
    )
    reference_id = models.CharField(
        max_length=128,
        unique=True,
        help_text="Reference ID returned by Sandbox generate OTP API"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        help_text="Latest status from Sandbox"
    )
    sandbox_transaction_id = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Sandbox transaction identifier (if provided)"
    )
    sandbox_message = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Latest message from Sandbox"
    )
    sandbox_metadata = models.JSONField(
        null=True,
        blank=True,
        help_text="Sanitized metadata returned from Sandbox (no PII)"
    )
    simulated_otp = models.CharField(
        max_length=6,
        null=True,
        blank=True,
        help_text="DEV helper storing OTP when Sandbox is not configured"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'aadhaar_verification_sessions'
        verbose_name = 'Aadhaar Verification Session'
        verbose_name_plural = 'Aadhaar Verification Sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['aadhaar_hash']),
        ]

    def __str__(self):
        return f"Aadhaar session {self.reference_id} ({self.status})"

