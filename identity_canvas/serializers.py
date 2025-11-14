from rest_framework import serializers
from .models import (
    IdentityCanvas, 
    CanvasHistory, 
    VerifiableBlockOTP, 
    VerifiedBlock,
    VerificationBlockType,
    DocumentVerification,
    UsernameProof
)
import hashlib


class IdentityCanvasSerializer(serializers.ModelSerializer):
    """Serializer for Identity Canvas (returns encrypted data)"""
    
    class Meta:
        model = IdentityCanvas
        fields = [
            'id',
            'encrypted_blocks',
            'created_at',
            'updated_at',
            'version'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'version']


class CreateCanvasSerializer(serializers.Serializer):
    """Serializer for creating identity canvas"""
    encrypted_blocks = serializers.CharField(required=True)
    
    def validate_encrypted_blocks(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError("Invalid encrypted data")
        return value


class UpdateCanvasSerializer(serializers.Serializer):
    """Serializer for updating identity canvas"""
    encrypted_blocks = serializers.CharField(required=True)
    version = serializers.IntegerField(required=False)
    create_history = serializers.BooleanField(default=False, required=False)
    
    def validate_encrypted_blocks(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError("Invalid encrypted data")
        return value
    
    def validate_version(self, value):
        if value is not None and value < 1:
            raise serializers.ValidationError("Version must be positive")
        return value


class CanvasHistorySerializer(serializers.ModelSerializer):
    """Serializer for canvas history"""
    
    class Meta:
        model = CanvasHistory
        fields = [
            'id',
            'encrypted_blocks_snapshot',
            'version',
            'action',
            'created_at'
        ]
        read_only_fields = fields


# ==================== VERIFICATION SERIALIZERS ====================

class RequestOTPSerializer(serializers.Serializer):
    """
    Serializer for requesting OTP for verifiable block verification
    Uses zero-knowledge approach - only sends hash of value to verify
    """
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True,
        help_text="Type of block to verify (email, phone, etc.)"
    )
    value = serializers.CharField(
        required=True,
        help_text="Value to verify (email, phone, etc.) - will be hashed client-side ideally, but we receive it to send OTP"
    )
    
    def validate_block_type(self, value):
        """Validate block type is supported"""
        if value not in [choice[0] for choice in VerificationBlockType.choices]:
            raise serializers.ValidationError(f"Unsupported block type: {value}")
        return value
    
    def validate_value(self, value):
        """Basic validation of value format"""
        if not value or len(value.strip()) == 0:
            raise serializers.ValidationError("Value cannot be empty")
        return value.strip()


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for verifying OTP for verifiable block
    Uses zero-knowledge approach - verifies using hash
    """
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True,
        help_text="Type of block being verified"
    )
    value_hash = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of the value being verified (zero-knowledge)"
    )
    otp_code = serializers.CharField(
        required=True,
        max_length=6,
        min_length=6,
        help_text="6-digit OTP code"
    )
    
    def validate_otp_code(self, value):
        """Validate OTP code format"""
        if not value.isdigit():
            raise serializers.ValidationError("OTP code must be numeric")
        if len(value) != 6:
            raise serializers.ValidationError("OTP code must be 6 digits")
        return value
    
    def validate_value_hash(self, value):
        """Validate hash format"""
        if len(value) != 64:
            raise serializers.ValidationError("Hash must be 64 characters (SHA-256)")
        return value


class CheckVerificationStatusSerializer(serializers.Serializer):
    """
    Serializer for checking verification status of a block
    """
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True
    )
    value_hash = serializers.CharField(
        required=True,
        max_length=64
    )
    
    def validate_value_hash(self, value):
        if len(value) != 64:
            raise serializers.ValidationError("Hash must be 64 characters (SHA-256)")
        return value


class VerifiableBlockOTPSerializer(serializers.ModelSerializer):
    """Serializer for VerifiableBlockOTP (limited fields for response)"""
    
    class Meta:
        model = VerifiableBlockOTP
        fields = [
            'id',
            'block_type',
            'expires_at',
            'is_verified',
            'attempts',
            'max_attempts',
            'created_at'
        ]
        read_only_fields = fields


class VerifiedBlockSerializer(serializers.ModelSerializer):
    """Serializer for VerifiedBlock"""
    
    class Meta:
        model = VerifiedBlock
        fields = [
            'id',
            'block_type',
            'value_hash',
            'verified_at',
            'verification_method'
        ]
        read_only_fields = fields


# ==================== DOCUMENT VERIFICATION SERIALIZERS ====================

class DocumentVerificationSerializer(serializers.ModelSerializer):
    """Serializer for DocumentVerification"""
    
    class Meta:
        model = DocumentVerification
        fields = [
            'id',
            'block_type',
            'document_hash',
            'verification_method',
            'status',
            'created_at',
            'verified_at'
        ]
        read_only_fields = ['id', 'created_at', 'verified_at']


class RequestDocumentVerificationSerializer(serializers.Serializer):
    """
    Serializer for requesting document verification
    """
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True
    )
    document_identifier = serializers.CharField(
        required=True,
        help_text="Document identifier (e.g., PAN number, license number) - will be hashed"
    )
    verification_method = serializers.ChoiceField(
        choices=DocumentVerification.VERIFICATION_METHOD_CHOICES,
        required=True
    )
    additional_data = serializers.DictField(
        required=False,
        help_text="Additional data for verification"
    )
    
    def validate_block_type(self, value):
        """Validate block type is supported for document verification"""
        otp_only_types = ['email', 'phone']
        if value in otp_only_types:
            raise serializers.ValidationError(
                f"{value} verification uses OTP method, not document verification"
            )
        return value


class VerifyDocumentSerializer(serializers.Serializer):
    """Serializer for verifying a document"""
    verification_id = serializers.UUIDField(required=True)
    verification_code = serializers.CharField(
        required=False,
        help_text="Verification code if needed (e.g., from third-party callback)"
    )


# ==================== USERNAME UNIQUENESS SERIALIZERS (Zero-Knowledge) ====================

class CheckUsernamePrefixSerializer(serializers.Serializer):
    """
    Serializer for k-anonymity username uniqueness check
    Client sends prefix (first 8 chars) of hashed username
    Server returns list of full hashes matching that prefix
    """
    prefix = serializers.CharField(
        required=True,
        max_length=8,
        min_length=8,
        help_text="First 8 characters of username hash (SHA-256 with public pepper)"
    )
    
    def validate_prefix(self, value):
        """Validate prefix is 8 hex characters"""
        if len(value) != 8:
            raise serializers.ValidationError("Prefix must be exactly 8 characters")
        if not all(c in '0123456789abcdef' for c in value.lower()):
            raise serializers.ValidationError("Prefix must be hexadecimal")
        return value.lower()


class RegisterUsernameSerializer(serializers.Serializer):
    """
    Serializer for registering username uniqueness proof
    Client sends full username hash after confirming uniqueness
    Server computes and stores final proof hash
    """
    username_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        help_text="Full SHA-256 hash of username (with public pepper)"
    )
    
    def validate_username_hash(self, value):
        """Validate hash format"""
        if len(value) != 64:
            raise serializers.ValidationError("Hash must be 64 characters (SHA-256)")
        if not all(c in '0123456789abcdef' for c in value.lower()):
            raise serializers.ValidationError("Hash must be hexadecimal")
        return value.lower()

