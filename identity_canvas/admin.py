from django.contrib import admin
from .models import (
    IdentityCanvas, 
    CanvasHistory, 
    VerifiableBlockOTP, 
    VerifiedBlock,
    UsernameProof,
    AadhaarVerificationSession,
)


@admin.register(IdentityCanvas)
class IdentityCanvasAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'version', 'created_at', 'updated_at']
    list_filter = ['created_at', 'updated_at']
    readonly_fields = ['id', 'created_at', 'updated_at', 'version']
    search_fields = ['user__id']
    
    # Don't allow viewing encrypted data for security
    exclude = ['encrypted_blocks']


@admin.register(CanvasHistory)
class CanvasHistoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'canvas', 'version', 'action', 'created_at']
    list_filter = ['created_at', 'action']
    readonly_fields = ['id', 'created_at']
    search_fields = ['canvas__id']
    
    # Don't allow viewing encrypted data for security
    exclude = ['encrypted_blocks_snapshot']


@admin.register(VerifiableBlockOTP)
class VerifiableBlockOTPAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'block_type', 'is_verified', 'attempts', 'expires_at', 'created_at']
    list_filter = ['block_type', 'is_verified', 'created_at']
    readonly_fields = ['id', 'otp_code', 'created_at', 'expires_at']
    search_fields = ['user__id', 'value_hash']
    
    def has_change_permission(self, request, obj=None):
        """Prevent editing OTP codes for security"""
        return False


@admin.register(VerifiedBlock)
class VerifiedBlockAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'block_type', 'verified_at', 'verification_method']
    list_filter = ['block_type', 'verification_method', 'verified_at']
    readonly_fields = ['id', 'verified_at']
    search_fields = ['user__id', 'value_hash']

@admin.register(UsernameProof)
class UsernameProofAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'proof_hash', 'prefix', 'username_hash', 'created_at', 'updated_at']
    list_filter = ['created_at', 'updated_at']
    readonly_fields = ['id', 'proof_hash', 'prefix', 'username_hash', 'created_at', 'updated_at']
    search_fields = ['user__id', 'proof_hash', 'prefix', 'username_hash']


@admin.register(AadhaarVerificationSession)
class AadhaarVerificationSessionAdmin(admin.ModelAdmin):
    list_display = ['reference_id', 'user', 'status', 'sandbox_message', 'created_at', 'verified_at']
    list_filter = ['status', 'created_at']
    readonly_fields = ['reference_id', 'aadhaar_hash', 'sandbox_transaction_id', 'sandbox_message', 'sandbox_metadata', 'simulated_otp', 'created_at', 'updated_at', 'verified_at']
    search_fields = ['reference_id', 'user__id', 'aadhaar_hash']