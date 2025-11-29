# authentication/serializers.py

from rest_framework import serializers
from .models import ZKUser, ZKEmailVerificationToken
import hashlib
import re


class ZKRegisterSerializer(serializers.Serializer):
    """
    Serializer for zero-knowledge registration
    Now supports optional passkey registration and device fingerprinting
    """
    encrypted_data = serializers.CharField(
        required=True,
        help_text="AES-256-GCM encrypted user data (base64)"
    )
    salt = serializers.CharField(
        required=True,
        max_length=255,
        help_text="Cryptographic salt for key derivation (base64)"
    )
    auth_proof = serializers.CharField(
        required=True,
        max_length=255,
        help_text="Authentication proof derived from master key (base64)"
    )
    username_hash = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of username for lookup"
    )
    
    # Device fingerprint
    device_fingerprint = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of device fingerprint for one device per user"
    )
    
    # Optional passkey fields
    passkey_credential_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        max_length=512,
        help_text="WebAuthn credential ID (base64url)"
    )
    passkey_public_key = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="WebAuthn public key (base64)"
    )
    use_both_methods = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Whether user wants to use both master key and passkey"
    )
    
    def validate_encrypted_data(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError(
                "Encrypted data appears to be invalid or too short."
            )
        return value
    
    def validate_salt(self, value):
        if not value or len(value) < 20:
            raise serializers.ValidationError(
                "Salt appears to be invalid or too short."
            )
        return value
    
    def validate_auth_proof(self, value):
        if not value or len(value) < 40:
            raise serializers.ValidationError(
                "Authentication proof appears to be invalid."
            )
        
        if ZKUser.objects.filter(auth_proof=value).exists():
            raise serializers.ValidationError(
                "An account with this master key combination already exists."
            )
        return value
    
    def validate_username_hash(self, value):
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Username hash appears to be invalid."
            )
        
        if ZKUser.objects.filter(username_hash=value).exists():
            raise serializers.ValidationError(
                "An account with this username already exists."
            )
        return value
    
    def validate_device_fingerprint(self, value):
        """Validate device fingerprint format"""
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Device fingerprint must be a 64-character SHA-256 hash."
            )
        
        # Check if device fingerprint is already registered
        if ZKUser.objects.filter(device_fingerprint=value).exists():
            raise serializers.ValidationError(
                "This device is already registered to another account. One device per user policy enforced."
            )
        return value
    
    def validate_passkey_credential_id(self, value):
        """Ensure passkey credential ID is unique if provided"""
        if value and ZKUser.objects.filter(passkey_credential_id=value).exists():
            raise serializers.ValidationError(
                "This passkey is already registered to another account."
            )
        return value


class ZKLoginSerializer(serializers.Serializer):
    """
    Serializer for zero-knowledge login with device fingerprinting
    """
    auth_proof = serializers.CharField(
        required=True,
        help_text="Authentication proof derived from master key or passkey"
    )
    device_fingerprint = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of device fingerprint"
    )
    
    def validate_auth_proof(self, value):
        # Allow special passkey marker
        if value == "passkey_authenticated":
            return value
        
        if not value or len(value) < 40:
            raise serializers.ValidationError(
                "Authentication proof appears to be invalid."
            )
        return value
    
    def validate_device_fingerprint(self, value):
        """Validate device fingerprint format"""
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Device fingerprint must be a 64-character SHA-256 hash."
            )
        return value


class ZKUserDetailsSerializer(serializers.ModelSerializer):
    """
    Public user details (non-sensitive metadata only)
    """
    class Meta:
        model = ZKUser
        fields = (
            'id', 
            'created_at', 
            'last_login', 
            'is_active', 
            'updated_at',
            'has_passkey'  # Include passkey status
        )
        read_only_fields = fields


class ZKUserDataSerializer(serializers.ModelSerializer):
    """
    Serializer for returning encrypted user data to client
    """
    class Meta:
        model = ZKUser
        fields = (
            'encrypted_data',
            'salt',
            'user_id',
            'created_at',
            'last_login',
            'updated_at',
            'passkey_credential_id',  # Return credential ID for passkey login
            'has_passkey'
        )
        read_only_fields = fields
    
    user_id = serializers.UUIDField(source='id', read_only=True)


class ZKUpdateProfileSerializer(serializers.Serializer):
    """
    Serializer for updating encrypted user data
    """
    encrypted_data = serializers.CharField(
        required=True,
        help_text="Re-encrypted user data with updated information"
    )
    
    def validate_encrypted_data(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError(
                "Encrypted data appears to be invalid or too short."
            )
        return value


class ZKGetSaltSerializer(serializers.Serializer):
    """
    Serializer for getting user's salt (Step 1 of login)
    """
    username_hash = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of username"
    )
    
    def validate_username_hash(self, value):
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Username hash appears to be invalid."
            )
        return value


class ZKDeleteAccountSerializer(serializers.Serializer):
    """
    Serializer for account deletion
    """
    auth_proof = serializers.CharField(
        required=True,
        help_text="Authentication proof to verify master key"
    )
    confirmation = serializers.CharField(
        required=True,
        help_text="Confirmation text (e.g., 'DELETE MY ACCOUNT')"
    )
    
    def validate_confirmation(self, value):
        if value.upper() != "DELETE MY ACCOUNT":
            raise serializers.ValidationError(
                "Please type 'DELETE MY ACCOUNT' to confirm."
            )
        return value


class ZKPasskeyRegisterSerializer(serializers.Serializer):
    """
    Serializer for adding passkey to existing account
    """
    passkey_credential_id = serializers.CharField(
        required=True,
        max_length=512,
        help_text="WebAuthn credential ID"
    )
    passkey_public_key = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="WebAuthn public key (optional)"
    )
    
    def validate_passkey_credential_id(self, value):
        if ZKUser.objects.filter(passkey_credential_id=value).exists():
            raise serializers.ValidationError(
                "This passkey is already registered."
            )
        return value


class ZKPasskeyRemoveSerializer(serializers.Serializer):
    """
    Serializer for removing passkey from account
    """
    auth_proof = serializers.CharField(
        required=True,
        help_text="Authentication proof to verify identity"
    )


# ==================== EMAIL VERIFICATION SERIALIZERS ====================

class ZKEmailVerificationRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting email verification with device fingerprinting
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address to verify"
    )
    encrypted_data = serializers.CharField(
        required=True,
        help_text="AES-256-GCM encrypted user data (base64)"
    )
    salt = serializers.CharField(
        required=True,
        max_length=255,
        help_text="Cryptographic salt for key derivation (base64)"
    )
    auth_proof = serializers.CharField(
        required=True,
        max_length=255,
        help_text="Authentication proof derived from master key (base64)"
    )
    username_hash = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of username for lookup"
    )
    
    # Device fingerprint
    device_fingerprint = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of device fingerprint for one device per user"
    )
    
    # Optional passkey fields
    passkey_credential_id = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        max_length=512,
        help_text="WebAuthn credential ID (base64url)"
    )
    passkey_public_key = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="WebAuthn public key (base64)"
    )
    use_both_methods = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Whether user wants to use both master key and passkey"
    )
    
    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        
        # Check if email is already registered
        email_hash = hashlib.sha256(value.lower().encode()).hexdigest()
        if ZKUser.objects.filter(email_hash=email_hash).exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )
        
        # Check if there's already a pending verification for this email
        if ZKEmailVerificationToken.objects.filter(email_hash=email_hash, is_used=False).exists():
            raise serializers.ValidationError(
                "A verification email has already been sent to this address. Please check your email or wait before requesting another."
            )
        
        return value.lower()
    
    def validate_encrypted_data(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError(
                "Encrypted data appears to be invalid or too short."
            )
        return value
    
    def validate_salt(self, value):
        if not value or len(value) < 20:
            raise serializers.ValidationError(
                "Salt appears to be invalid or too short."
            )
        return value
    
    def validate_auth_proof(self, value):
        if not value or len(value) < 40:
            raise serializers.ValidationError(
                "Authentication proof appears to be invalid."
            )
        
        if ZKUser.objects.filter(auth_proof=value).exists():
            raise serializers.ValidationError(
                "An account with this master key combination already exists."
            )
        return value
    
    def validate_username_hash(self, value):
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Username hash appears to be invalid."
            )
        
        if ZKUser.objects.filter(username_hash=value).exists():
            raise serializers.ValidationError(
                "An account with this username already exists."
            )
        return value
    
    def validate_device_fingerprint(self, value):
        """Validate device fingerprint format"""
        if not value or len(value) != 64:
            raise serializers.ValidationError(
                "Device fingerprint must be a 64-character SHA-256 hash."
            )
        
        # Check if device fingerprint is already registered
        if ZKUser.objects.filter(device_fingerprint=value).exists():
            raise serializers.ValidationError(
                "This device is already registered to another account. One device per user policy enforced."
            )
        return value
    
    def validate_passkey_credential_id(self, value):
        """Ensure passkey credential ID is unique if provided"""
        if value and ZKUser.objects.filter(passkey_credential_id=value).exists():
            raise serializers.ValidationError(
                "This passkey is already registered to another account."
            )
        return value


class ZKEmailVerificationConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming email verification
    """
    token = serializers.UUIDField(
        required=True,
        help_text="Email verification token"
    )
    
    def validate_token(self, value):
        try:
            verification_token = ZKEmailVerificationToken.objects.get(
                token=value,
                is_used=False
            )
            
            if not verification_token.is_valid:
                raise serializers.ValidationError(
                    "Verification token has expired or is invalid."
                )
            
            return value
        except ZKEmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError(
                "Invalid verification token."
            )


class ZKEmailLoginSerializer(serializers.Serializer):
    """
    Serializer for email-based login
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address for login"
    )
    
    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value.lower()


class ZKGetSaltByEmailSerializer(serializers.Serializer):
    """
    Serializer for getting user's salt by email (Step 1 of email login)
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address"
    )
    
    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value.lower()


# ==================== SECURITY MANAGEMENT SERIALIZERS ====================

class ZKChangeMasterKeySerializer(serializers.Serializer):
    """
    Serializer for changing master key
    """
    current_auth_proof = serializers.CharField(
        required=True,
        help_text="Current authentication proof to verify identity"
    )
    new_encrypted_data = serializers.CharField(
        required=True,
        help_text="Re-encrypted user data with new master key"
    )
    new_salt = serializers.CharField(
        required=True,
        max_length=255,
        help_text="New salt for key derivation"
    )
    new_auth_proof = serializers.CharField(
        required=True,
        max_length=255,
        help_text="New authentication proof derived from new master key"
    )
    
    def validate_new_salt(self, value):
        if not value or len(value) < 20:
            raise serializers.ValidationError(
                "New salt appears to be invalid or too short."
            )
        return value
    
    def validate_new_auth_proof(self, value):
        if not value or len(value) < 40:
            raise serializers.ValidationError(
                "New authentication proof appears to be invalid."
            )
        return value


class ZKTwoFactorSetupSerializer(serializers.Serializer):
    """
    Serializer for 2FA setup
    """
    totp_code = serializers.CharField(
        required=False,
        max_length=6,
        help_text="TOTP code to verify during setup"
    )


class ZKTwoFactorVerifySerializer(serializers.Serializer):
    """
    Serializer for 2FA verification
    """
    totp_code = serializers.CharField(
        required=True,
        max_length=6,
        help_text="TOTP code from authenticator app"
    )


class ZKTwoFactorDisableSerializer(serializers.Serializer):
    """
    Serializer for disabling 2FA
    """
    auth_proof = serializers.CharField(
        required=True,
        help_text="Authentication proof to verify master key"
    )
    totp_code = serializers.CharField(
        required=True,
        max_length=6,
        help_text="TOTP code to verify before disabling"
    )


class ZKTwoFactorLoginVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying 2FA during login
    """
    temp_token = serializers.UUIDField(
        required=True,
        help_text="Temporary token from login response"
    )
    totp_code = serializers.CharField(
        required=True,
        max_length=6,
        help_text="TOTP code from authenticator app"
    )