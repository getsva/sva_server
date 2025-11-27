from rest_framework import serializers
from .models import (
    IdentityCanvas,
    CanvasHistory,
    VerificationCanvas,
    VerificationCanvasHistory,
    UsernameProof,
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


class VerificationCanvasSerializer(serializers.ModelSerializer):
    """Serializer for Verification Canvas"""

    class Meta:
        model = VerificationCanvas
        fields = [
            'id',
            'encrypted_blocks',
            'created_at',
            'updated_at',
            'version'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'version']


class CreateVerificationCanvasSerializer(serializers.Serializer):
    encrypted_blocks = serializers.CharField(required=True)

    def validate_encrypted_blocks(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError("Invalid encrypted data")
        return value


class UpdateVerificationCanvasSerializer(serializers.Serializer):
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


class VerificationCanvasHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationCanvasHistory
        fields = [
            'id',
            'encrypted_blocks_snapshot',
            'version',
            'action',
            'created_at'
        ]
        read_only_fields = fields


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

