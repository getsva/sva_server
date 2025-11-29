from rest_framework import serializers
from .models import (
    UserIdentityLevel,
    ConnectedService,
    UserPreferences,
    SecurityLog,
    UserAppConnection
)


class IdentityLevelSerializer(serializers.ModelSerializer):
    """Serializer for identity level (non-sensitive data only)"""
    level_display = serializers.CharField(source='get_current_level_display', read_only=True)
    
    class Meta:
        model = UserIdentityLevel
        fields = [
            'id', 'current_level', 'level_display',
            'email_verified_at', 'phone_verified_at',
            'govt_id_verified_at', 'professional_verified_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields


class ConnectedServiceSerializer(serializers.ModelSerializer):
    """Serializer for connected services (returns encrypted data)"""
    class Meta:
        model = ConnectedService
        fields = [
            'id', 'encrypted_service_data', 'shared_identity_level',
            'connected_at', 'last_accessed', 'is_active', 'revoked_at'
        ]
        read_only_fields = ['id', 'connected_at', 'last_accessed']


class SecurityLogSerializer(serializers.ModelSerializer):
    """Serializer for security logs"""
    log_type_display = serializers.CharField(source='get_log_type_display', read_only=True)
    
    class Meta:
        model = SecurityLog
        fields = [
            'id', 'log_type', 'log_type_display',
            'created_at', 'ip_address'
        ]
        read_only_fields = fields


class UpdatePreferencesSerializer(serializers.Serializer):
    """Serializer for updating encrypted preferences"""
    encrypted_preferences = serializers.CharField(required=True)
    create_log = serializers.BooleanField(default=False, required=False)
    
    def validate_encrypted_preferences(self, value):
        if not value or len(value) < 10:
            raise serializers.ValidationError("Invalid encrypted data")
        return value


class VerifyIdentitySerializer(serializers.Serializer):
    """Serializer for identity verification requests"""
    verification_level = serializers.IntegerField(min_value=1, max_value=3)
    encrypted_verification_data = serializers.CharField(required=True)
    
    def validate_verification_level(self, value):
        if value not in [1, 2, 3]:
            raise serializers.ValidationError("Invalid verification level")
        return value


class ConnectServiceSerializer(serializers.Serializer):
    """Serializer for connecting new services"""
    encrypted_service_data = serializers.CharField(required=True)
    shared_identity_level = serializers.IntegerField(min_value=0, max_value=3)
    encrypted_permissions = serializers.CharField(required=False, allow_blank=True)


class RevokeServiceSerializer(serializers.Serializer):
    """Serializer for revoking service access"""
    service_id = serializers.UUIDField(required=True)
    
    def validate_service_id(self, value):
        if not ConnectedService.objects.filter(id=value).exists():
            raise serializers.ValidationError("Service not found")
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change (encrypted)"""
    encrypted_old_credentials = serializers.CharField(required=True)
    encrypted_new_credentials = serializers.CharField(required=True)
    new_auth_proof = serializers.CharField(required=True)
    
    def validate(self, data):
        if len(data.get('new_auth_proof', '')) < 40:
            raise serializers.ValidationError("Invalid authentication proof")
        return data


class UserAppConnectionSerializer(serializers.ModelSerializer):
    """Serializer for user app connections"""
    class Meta:
        model = UserAppConnection
        fields = [
            'id', 'client_id', 'app_name', 'app_logo', 'app_description',
            'approved_scopes', 'connected_at', 'last_accessed',
            'last_scope_update', 'is_active', 'revoked_at'
        ]
        read_only_fields = ['id', 'connected_at', 'last_accessed', 'last_scope_update']


class UpdateAppScopesSerializer(serializers.Serializer):
    """Serializer for updating app scopes"""
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=True,
        allow_empty=True
    )
    
    def validate_scopes(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Scopes must be a list")
        return value


class RevokeAppConnectionSerializer(serializers.Serializer):
    """Serializer for revoking app connection"""
    connection_id = serializers.UUIDField(required=True)
    
    def validate_connection_id(self, value):
        if not UserAppConnection.objects.filter(id=value).exists():
            raise serializers.ValidationError("App connection not found")
        return value