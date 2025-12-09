# authentication/urls.py

from django.urls import path
from .views import (
    ZKRegisterView,
    ZKGetSaltView,
    ZKLoginView,
    ZKLogoutView,
    ZKTokenRefreshView,
    ZKGetUserDataView,
    ZKGetAllEncryptedDataView,
    ZKUpdateUserDataView,
    ZKDeleteAccountView,
    ZKPasskeyRegisterView,
    ZKPasskeyRemoveView,
    ZKPasskeyStatusView,
    ZKProtectedView,
    ZKHealthCheckView,
    ZKStatsView,
    ZKEmailVerificationRequestView,
    ZKEmailVerificationConfirmView,
    ZKGetSaltByEmailView,
    ZKEmailLoginView,
    ZKChangeMasterKeyView,
    ZKTwoFactorSetupView,
    ZKTwoFactorStatusView,
    ZKTwoFactorDisableView,
    ZKActiveSessionsView,
    ZKTwoFactorLoginVerifyView,
    WaitlistJoinView,
)

urlpatterns = [
    # ========== Zero-Knowledge Authentication Endpoints ==========
    
    # Registration (legacy username-based)
    path('zk/register/', ZKRegisterView.as_view(), name='zk_register'),
    
    # Login (2-step process, legacy username-based)
    path('zk/get-salt/', ZKGetSaltView.as_view(), name='zk_get_salt'),
    path('zk/login/', ZKLoginView.as_view(), name='zk_login'),
    
    # ========== Email-Based Authentication Endpoints ==========
    
    # Email verification registration flow
    path('zk/email/verify-request/', ZKEmailVerificationRequestView.as_view(), name='zk_email_verify_request'),
    path('zk/email/verify-confirm/', ZKEmailVerificationConfirmView.as_view(), name='zk_email_verify_confirm'),
    
    # Email-based login (2-step process)
    path('zk/email/get-salt/', ZKGetSaltByEmailView.as_view(), name='zk_email_get_salt'),
    path('zk/email/login/', ZKEmailLoginView.as_view(), name='zk_email_login'),
    
    # Logout
    path('zk/logout/', ZKLogoutView.as_view(), name='zk_logout'),
    
    # Token Management
    path('zk/token/refresh/', ZKTokenRefreshView.as_view(), name='zk_token_refresh'),
    
    # ========== User Data Management ==========
    
    # Get encrypted user data
    path('zk/user/data/', ZKGetUserDataView.as_view(), name='zk_user_data'),
    
    # Get all encrypted data (for master key rotation)
    path('zk/user/all-encrypted-data/', ZKGetAllEncryptedDataView.as_view(), name='zk_all_encrypted_data'),
    
    # Update encrypted user data
    path('zk/user/update/', ZKUpdateUserDataView.as_view(), name='zk_user_update'),
    
    # Delete account
    path('zk/user/delete/', ZKDeleteAccountView.as_view(), name='zk_user_delete'),
    
    # ========== Passkey/WebAuthn Management ==========
    
    # Add passkey to account
    path('zk/passkey/register/', ZKPasskeyRegisterView.as_view(), name='zk_passkey_register'),
    
    # Remove passkey from account
    path('zk/passkey/remove/', ZKPasskeyRemoveView.as_view(), name='zk_passkey_remove'),
    
    # Check passkey status
    path('zk/passkey/status/', ZKPasskeyStatusView.as_view(), name='zk_passkey_status'),
    
    # ========== Utility Endpoints ==========
    
    # Protected endpoint example
    path('zk/protected/', ZKProtectedView.as_view(), name='zk_protected'),
    
    # Health check
    path('zk/health/', ZKHealthCheckView.as_view(), name='zk_health'),
    
    # Statistics
    path('zk/stats/', ZKStatsView.as_view(), name='zk_stats'),
    
    # ========== Security Management Endpoints ==========
    
    # Master key management
    path('zk/security/change-master-key/', ZKChangeMasterKeyView.as_view(), name='zk_change_master_key'),
    
    # Two-factor authentication
    path('zk/security/2fa/setup/', ZKTwoFactorSetupView.as_view(), name='zk_2fa_setup'),
    path('zk/security/2fa/status/', ZKTwoFactorStatusView.as_view(), name='zk_2fa_status'),
    path('zk/security/2fa/disable/', ZKTwoFactorDisableView.as_view(), name='zk_2fa_disable'),
    path('zk/security/2fa/verify-login/', ZKTwoFactorLoginVerifyView.as_view(), name='zk_2fa_verify_login'),
    
    # Active sessions management
    path('zk/security/sessions/', ZKActiveSessionsView.as_view(), name='zk_active_sessions'),
    
    # ========== Waitlist Endpoints ==========
    
    # Join waitlist
    path('waitlist/join/', WaitlistJoinView.as_view(), name='waitlist_join'),
]