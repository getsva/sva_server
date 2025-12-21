from django.urls import path
from .views import (
    GetUserSettingsView,
    UpdatePreferencesView,
    VerifyIdentityLevelView,
    ConnectServiceView,
    RevokeServiceView,
    DowngradeIdentityLevelView,
    ChangePasswordView,
    ExportUserDataView,
    GetSecurityLogsView,
    ListAppConnectionsView,
    GetAppConnectionView,
    UpdateAppScopesView,
    UpdateSharingBlobView,
    RevokeAppConnectionView,
    RestoreAppConnectionView,
    GetAppConnectionByClientIdView,
    ConnectionStatsView,
    ConnectionHealthView,
    AppMetadataView,
    BatchRevokeConnectionsView,
    BatchUpdateMetadataView,
    BatchMarkForBlobUpdateView,
    BatchHealthCheckView,
    BatchUpdateScopesView
)

urlpatterns = [
    # Get all settings data
    path('zk/settings/', GetUserSettingsView.as_view(), name='get_settings'),
    
    # Update preferences
    path('zk/settings/preferences/', UpdatePreferencesView.as_view(), name='update_preferences'),
    
    # Identity verification
    path('zk/settings/verify-identity/', VerifyIdentityLevelView.as_view(), name='verify_identity'),
    path('zk/settings/downgrade-identity/', DowngradeIdentityLevelView.as_view(), name='downgrade_identity'),
    
    # Service management
    path('zk/settings/connect-service/', ConnectServiceView.as_view(), name='connect_service'),
    path('zk/settings/revoke-service/', RevokeServiceView.as_view(), name='revoke_service'),
    
    # Password/credentials management
    path('zk/settings/change-password/', ChangePasswordView.as_view(), name='change_password'),
    
    # Data export (GDPR)
    path('zk/settings/export/', ExportUserDataView.as_view(), name='export_data'),
    
    # Security logs
    path('zk/settings/security-logs/', GetSecurityLogsView.as_view(), name='security_logs'),
    
    # App connections management
    path('zk/settings/app-connections/', ListAppConnectionsView.as_view(), name='list_app_connections'),
    path('zk/settings/app-connections/by-client-id/', GetAppConnectionByClientIdView.as_view(), name='get_app_connection_by_client_id'),
    path('zk/settings/app-connections/<uuid:connection_id>/', GetAppConnectionView.as_view(), name='get_app_connection'),
    path('zk/settings/app-connections/<uuid:connection_id>/scopes/', UpdateAppScopesView.as_view(), name='update_app_scopes'),
    path('zk/settings/app-connections/<uuid:connection_id>/sharing-blob/', UpdateSharingBlobView.as_view(), name='update_sharing_blob'),
    path('zk/settings/app-connections/<uuid:connection_id>/revoke/', RevokeAppConnectionView.as_view(), name='revoke_app_connection'),
    path('zk/settings/app-connections/<uuid:connection_id>/restore/', RestoreAppConnectionView.as_view(), name='restore_app_connection'),
    
    # Connection registry and utilities
    path('zk/settings/app-connections/stats/', ConnectionStatsView.as_view(), name='connection_stats'),
    path('zk/settings/app-connections/health/', ConnectionHealthView.as_view(), name='connection_health'),
    path('zk/settings/app-connections/<uuid:connection_id>/health/', ConnectionHealthView.as_view(), name='connection_health_detail'),
    path('zk/settings/app-metadata/', AppMetadataView.as_view(), name='app_metadata'),
    
    # Batch operations
    path('zk/settings/app-connections/batch/revoke/', BatchRevokeConnectionsView.as_view(), name='batch_revoke_connections'),
    path('zk/settings/app-connections/batch/update-metadata/', BatchUpdateMetadataView.as_view(), name='batch_update_metadata'),
    path('zk/settings/app-connections/batch/mark-blob-update/', BatchMarkForBlobUpdateView.as_view(), name='batch_mark_blob_update'),
    path('zk/settings/app-connections/batch/health-check/', BatchHealthCheckView.as_view(), name='batch_health_check'),
    path('zk/settings/app-connections/batch/update-scopes/', BatchUpdateScopesView.as_view(), name='batch_update_scopes'),
]
