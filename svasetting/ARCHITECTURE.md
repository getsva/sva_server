# Connection Management & Data Sharing Architecture

## Overview

This document describes the redesigned architecture for managing app connections and data sharing in SVA. The new architecture provides:

- **Centralized Connection Management**: Single service for all connection lifecycle operations
- **Unified Data Sharing**: Dedicated service for managing encrypted sharing blobs
- **Event-Driven Updates**: Automatic blob updates when user data changes
- **Clean API Boundaries**: Clear separation between OAuth protocol and connection management
- **Extensible Design**: Easy to add new connection types and sharing mechanisms

## Architecture Components

### 1. Connection Service (`connection_service.py`)

The `ConnectionService` is the central service for managing all app connections. It provides:

#### Key Responsibilities:
- Create/update connections
- Manage connection lifecycle (create, revoke, restore)
- Handle scope management with manual override protection
- Provide connection lookup and listing
- Integrate with security logging

#### Key Methods:

```python
# Create or update connection
connection_service.create_or_update_connection(
    user, client_id, app_name, approved_scopes,
    app_logo, app_description, encrypted_sharing_blob, sharing_blob_salt,
    preserve_existing_scopes=False
)

# Get connection
connection_service.get_connection(user, client_id, active_only=True)

# List connections
connection_service.list_connections(user, include_revoked=False)

# Revoke/restore
connection_service.revoke_connection(user, connection_id)
connection_service.restore_connection(user, connection_id)

# Update scopes
connection_service.update_scopes(user, connection_id, new_scopes)

# Get sharing data (for OAuth server)
connection_service.get_sharing_data(user_id, client_id)
```

#### Features:
- **Transaction Safety**: All operations use `@transaction.atomic`
- **Manual Scope Protection**: Preserves manually managed scopes when `preserve_existing_scopes=True`
- **Automatic Logging**: Security logs created automatically
- **Connection Reactivation**: Automatically reactivates revoked connections on update

### 2. Data Sharing Service (`data_sharing_service.py`)

The `DataSharingService` manages encrypted sharing blobs and provides event-driven updates.

#### Key Responsibilities:
- Update sharing blobs for connections
- Validate blob format
- Mark blobs for update when user data changes
- Provide event signals for automatic updates

#### Key Methods:

```python
# Update sharing blob
data_sharing_service.update_sharing_blob_for_connection(
    connection, encrypted_blob, salt
)

# Get sharing blob
data_sharing_service.get_sharing_blob(connection)

# Mark for update (when user data changes)
data_sharing_service.mark_blob_for_update(user, connection_id=None)

# Validate blob
data_sharing_service.validate_sharing_blob(encrypted_blob, salt)
```

#### Event Signals:
- `sharing_blob_updated`: Emitted when a blob is updated
- `user_data_changed`: Emitted when user data changes (triggers blob updates)
- `connection_scopes_changed`: Emitted when scopes change

### 3. API Views (`views.py`)

All views now use the connection and data sharing services instead of direct model access.

#### Updated Views:
- `ListAppConnectionsView`: Uses `connection_service.list_connections()`
- `GetAppConnectionView`: Uses `connection_service.get_connection_by_id()`
- `UpdateAppScopesView`: Uses `connection_service.update_scopes()`
- `UpdateSharingBlobView`: Uses `data_sharing_service.update_sharing_blob_for_connection()`
- `RevokeAppConnectionView`: Uses `connection_service.revoke_connection()`
- `RestoreAppConnectionView`: Uses `connection_service.restore_connection()`
- `GetAppConnectionForUserInfoView`: Uses `connection_service.get_sharing_data()`

## Data Flow

### Connection Creation Flow

```
1. User approves consent
   ↓
2. Client creates encrypted sharing blob
   ↓
3. Client calls SVA Server consent endpoint
   ↓
4. SVA Server calls ConnectionService.create_or_update_connection()
   ↓
5. ConnectionService:
   - Creates/updates UserAppConnection
   - Stores encrypted sharing blob
   - Updates scopes (with manual override protection)
   - Creates security log
   ↓
6. OAuth server issues tokens
```

### UserInfo Flow

```
1. App requests userinfo with access token
   ↓
2. OAuth server validates token
   ↓
3. OAuth server calls SVA Server internal API
   GET /api/internal/app-connections/userinfo/?client_id=X&user_id=Y
   ↓
4. SVA Server uses ConnectionService.get_sharing_data()
   ↓
5. Returns encrypted blob + approved scopes
   ↓
6. OAuth server returns userinfo with blob
   ↓
7. App decrypts blob client-side
```

### Data Update Flow

```
1. User updates profile/canvas data
   ↓
2. Client detects data change
   ↓
3. Client calls DataSharingService.mark_blob_for_update()
   (or directly updates blob via API)
   ↓
4. For each active connection:
   - Client builds claims from new data
   - Client encrypts with app-specific key
   - Client calls UpdateSharingBlobView
   ↓
5. DataSharingService updates blob
   ↓
6. Signal emitted: sharing_blob_updated
```

## Manual Scope Management

The system protects manually managed scopes:

1. **Detection**: `last_scope_update` timestamp indicates manual management
2. **Protection**: When `preserve_existing_scopes=True`, existing scopes are preserved
3. **Reduction Allowed**: Users can reduce scopes (deny in consent), but not add new ones
4. **Consent Override**: Only applies if connection was never manually updated

## Security Features

1. **Transaction Safety**: All operations use database transactions
2. **Select for Update**: Prevents race conditions on concurrent updates
3. **Service Token Auth**: Internal APIs require service token
4. **Scope Validation**: Only approved scopes are returned in userinfo
5. **Connection Validation**: Active connections only for data access
6. **Automatic Logging**: All connection changes logged to SecurityLog

## Benefits of New Architecture

1. **Centralized Logic**: All connection logic in one place
2. **Testability**: Services can be easily unit tested
3. **Maintainability**: Clear separation of concerns
4. **Extensibility**: Easy to add new connection types
5. **Consistency**: All views use same service methods
6. **Event-Driven**: Automatic updates via signals
7. **Type Safety**: Better type hints and validation

## Migration Notes

### For Developers:

1. **Use Services**: Always use `connection_service` and `data_sharing_service` instead of direct model access
2. **Manual Scopes**: Check `last_scope_update` before updating scopes
3. **Blob Updates**: Use `data_sharing_service` for blob operations
4. **Signals**: Listen to signals for automatic updates

### For OAuth Server:

The OAuth server continues to call SVA Server's internal API:
- `GET /api/internal/app-connections/userinfo/` - Get sharing data
- Uses service token authentication
- Returns encrypted blob + approved scopes

### For Client:

Client code should:
1. Use connection APIs for management
2. Update sharing blobs when data changes
3. Handle blob encryption/decryption
4. Respect approved scopes

## Future Enhancements

1. **Connection Registry**: Central registry for app metadata
2. **Webhook Support**: Notify apps when data changes
3. **Connection Analytics**: Track connection usage and patterns
4. **Bulk Operations**: Update multiple connections efficiently
5. **Connection Templates**: Pre-configured connection types
6. **Rate Limiting**: Per-connection rate limits
7. **Connection Health**: Monitor connection status and errors

