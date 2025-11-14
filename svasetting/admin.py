# core/admin.py

from django.contrib import admin
from .models import (
    UserIdentityLevel,
    ConnectedService,
    UserPreferences,
    SecurityLog
)


@admin.register(UserIdentityLevel)
class UserIdentityLevelAdmin(admin.ModelAdmin):
    list_display = ('user', 'current_level', 'created_at', 'updated_at')
    list_filter = ('current_level', 'created_at')
    search_fields = ('user__username_hash',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    fieldsets = (
        ('User Info', {'fields': ('user', 'current_level')}),
        ('Verification Data', {
            'fields': (
                'encrypted_verification_data',
                'email_verified_at',
                'phone_verified_at',
                'govt_id_verified_at',
                'professional_verified_at',
            )
        }),
        ('Metadata', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(ConnectedService)
class ConnectedServiceAdmin(admin.ModelAdmin):
    list_display = ('user', 'shared_identity_level', 'is_active', 'connected_at', 'last_accessed')
    list_filter = ('is_active', 'shared_identity_level')
    search_fields = ('user__username_hash',)
    readonly_fields = ('connected_at', 'last_accessed', 'revoked_at')
    ordering = ('-connected_at',)
    fieldsets = (
        ('Connection Info', {'fields': ('user', 'encrypted_service_data', 'shared_identity_level')}),
        ('Permissions', {'fields': ('encrypted_permissions',)}),
        ('Status', {'fields': ('is_active', 'revoked_at', 'connected_at', 'last_accessed')}),
    )


@admin.register(UserPreferences)
class UserPreferencesAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'updated_at')
    search_fields = ('user__username_hash',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    fieldsets = (
        ('Preferences Info', {'fields': ('user', 'encrypted_preferences')}),
        ('Metadata', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'log_type', 'ip_address', 'created_at')
    list_filter = ('log_type', 'created_at')
    search_fields = ('user__username_hash', 'log_type')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
    fieldsets = (
        ('User & Action', {'fields': ('user', 'log_type', 'encrypted_details')}),
        ('Request Info', {'fields': ('ip_address', 'user_agent')}),
        ('Timestamp', {'fields': ('created_at',)}),
    )
