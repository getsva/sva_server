# core/admin.py

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    UserIdentityLevel,
    ConnectedService,
    UserPreferences,
    SecurityLog,
    UserAppConnection
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


@admin.register(UserAppConnection)
class UserAppConnectionAdmin(admin.ModelAdmin):
    list_display = (
        'id', 
        'user', 
        'app_name', 
        'client_id_short', 
        'status_badge', 
        'scopes_count', 
        'connected_at', 
        'last_accessed',
        'has_sharing_blob'
    )
    list_filter = ('is_active', 'connected_at', 'last_accessed', 'last_scope_update')
    search_fields = ('user__username_hash', 'app_name', 'client_id', 'app_description')
    readonly_fields = (
        'id',
        'connected_at', 
        'last_accessed', 
        'last_scope_update', 
        'revoked_at',
        'sharing_blob_encrypted_at',
        'sharing_blob_preview'
    )
    ordering = ('-connected_at',)
    date_hierarchy = 'connected_at'
    
    fieldsets = (
        ('Connection Info', {
            'fields': (
                'id',
                'user',
                'client_id',
                'app_name',
                'app_logo',
                'app_description',
            )
        }),
        ('Permissions & Sharing', {
            'fields': (
                'approved_scopes',
                'encrypted_sharing_blob',
                'sharing_blob_preview',
                'sharing_blob_encrypted_at',
            ),
            'description': 'Approved scopes and encrypted sharing blob (Google OAuth style)'
        }),
        ('Status', {
            'fields': (
                'is_active',
                'connected_at',
                'last_accessed',
                'last_scope_update',
                'revoked_at',
            )
        }),
    )
    
    def client_id_short(self, obj):
        """Display shortened client_id"""
        if obj.client_id:
            return obj.client_id[:20] + '...' if len(obj.client_id) > 20 else obj.client_id
        return '-'
    client_id_short.short_description = 'Client ID'
    
    def status_badge(self, obj):
        """Display status with color coding"""
        if obj.is_active:
            return format_html(
                '<span style="color: green; font-weight: bold;">●</span> Active'
            )
        else:
            return format_html(
                '<span style="color: red; font-weight: bold;">●</span> Revoked'
            )
    status_badge.short_description = 'Status'
    
    def scopes_count(self, obj):
        """Display number of approved scopes"""
        count = len(obj.approved_scopes) if obj.approved_scopes else 0
        return f"{count} scope{'s' if count != 1 else ''}"
    scopes_count.short_description = 'Scopes'
    
    def has_sharing_blob(self, obj):
        """Display if sharing blob exists"""
        if obj.encrypted_sharing_blob:
            return format_html(
                '<span style="color: green;">✓</span> Yes'
            )
        return format_html(
            '<span style="color: gray;">✗</span> No'
        )
    has_sharing_blob.short_description = 'Sharing Blob'
    
    def sharing_blob_preview(self, obj):
        """Display preview of encrypted sharing blob"""
        if obj.encrypted_sharing_blob:
            blob_preview = obj.encrypted_sharing_blob[:100] + '...' if len(obj.encrypted_sharing_blob) > 100 else obj.encrypted_sharing_blob
            return format_html(
                '<div style="font-family: monospace; font-size: 10px; word-break: break-all; background: #f5f5f5; padding: 5px; border-radius: 3px;">{}</div>',
                blob_preview
            )
        return format_html('<span style="color: gray;">No sharing blob</span>')
    sharing_blob_preview.short_description = 'Sharing Blob Preview'
    
    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        qs = super().get_queryset(request)
        return qs.select_related('user')
    
    actions = [
        'mark_as_active', 
        'mark_as_revoked',
        'refresh_sharing_blobs',
        'check_health'
    ]
    
    def mark_as_active(self, request, queryset):
        """Admin action to mark connections as active"""
        from .connection_service import connection_service
        from django.utils import timezone
        
        count = 0
        for connection in queryset:
            if not connection.is_active:
                connection_service.restore_connection(connection.user, str(connection.id))
                count += 1
        
        self.message_user(request, f'{count} connection(s) marked as active.')
    mark_as_active.short_description = 'Mark selected connections as active'
    
    def mark_as_revoked(self, request, queryset):
        """Admin action to revoke connections"""
        from .connection_service import connection_service
        
        count = 0
        for connection in queryset:
            if connection.is_active:
                connection_service.revoke_connection(connection.user, str(connection.id))
                count += 1
        
        self.message_user(request, f'{count} connection(s) revoked.')
    mark_as_revoked.short_description = 'Revoke selected connections'
    
    def refresh_sharing_blobs(self, request, queryset):
        """Admin action to mark connections for blob refresh"""
        from .data_sharing_service import data_sharing_service
        
        count = 0
        for connection in queryset:
            if connection.is_active:
                data_sharing_service.mark_blob_for_update(
                    connection.user,
                    str(connection.id)
                )
                count += 1
        
        self.message_user(
            request, 
            f'{count} connection(s) marked for sharing blob refresh. '
            'Client will update blobs on next access.'
        )
    refresh_sharing_blobs.short_description = 'Mark for sharing blob refresh'
    
    def check_health(self, request, queryset):
        """Admin action to check connection health"""
        from .connection_utils import check_connection_health
        
        healthy = 0
        unhealthy = 0
        issues = []
        
        for connection in queryset:
            health = check_connection_health(connection)
            if health['is_healthy']:
                healthy += 1
            else:
                unhealthy += 1
                issues.append({
                    'connection': connection,
                    'health': health
                })
        
        message = f'Health check: {healthy} healthy, {unhealthy} unhealthy'
        if issues:
            message += '\nIssues found:\n'
            for item in issues[:5]:  # Show first 5
                message += f"  - {item['connection'].app_name}: {', '.join(item['health']['issues'])}\n"
            if len(issues) > 5:
                message += f"  ... and {len(issues) - 5} more"
        
        self.message_user(request, message)
    check_health.short_description = 'Check connection health'
