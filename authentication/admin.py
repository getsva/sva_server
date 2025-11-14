# authentication/admin.py

from django.contrib import admin
from .models import ZKUser, ZKRefreshToken, ZKPasswordResetToken, ZKEmailVerificationToken


@admin.register(ZKUser)
class ZKUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email_hash', 'username_hash', 'email_verified', 'has_passkey', 'is_active', 'created_at', 'last_login')
    search_fields = ('email_hash', 'username_hash')
    list_filter = ('email_verified', 'has_passkey', 'is_active')
    readonly_fields = ('id', 'created_at', 'updated_at', 'last_login')


@admin.register(ZKRefreshToken)
class ZKRefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'token', 'auth_method', 'created_at', 'expires_at', 'device_info', 'ip_address')
    search_fields = ('user__email_hash', 'token')
    list_filter = ('auth_method', 'created_at', 'expires_at')
    readonly_fields = ('id', 'created_at', 'expires_at', 'token')


@admin.register(ZKPasswordResetToken)
class ZKPasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'token', 'created_at', 'is_used', 'is_expired')
    search_fields = ('user__email_hash', 'token')
    list_filter = ('is_used', 'created_at')
    readonly_fields = ('id', 'created_at', 'token')


@admin.register(ZKEmailVerificationToken)
class ZKEmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'email_hash', 'token', 'created_at', 'is_used', 'is_expired')
    search_fields = ('email_hash', 'token')
    list_filter = ('is_used', 'created_at')
    readonly_fields = ('id', 'created_at', 'token')
