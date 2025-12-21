# Migration Guide: Connection Management Redesign

## Summary

The connection management and data sharing architecture has been completely redesigned to provide:
- Centralized connection management via `ConnectionService`
- Unified data sharing via `DataSharingService`
- Event-driven updates
- Better separation of concerns

## What Changed

### New Services

1. **ConnectionService** (`svasetting/connection_service.py`)
   - Centralized service for all connection operations
   - Handles create, update, revoke, restore
   - Manages scopes with manual override protection
   - Provides sharing data for OAuth server

2. **DataSharingService** (`svasetting/data_sharing_service.py`)
   - Manages encrypted sharing blobs
   - Provides event signals for updates
   - Validates blob format
   - Marks blobs for update when data changes

### Updated Views

All views in `svasetting/views.py` now use the services instead of direct model access:
- `ListAppConnectionsView` → `connection_service.list_connections()`
- `GetAppConnectionView` → `connection_service.get_connection_by_id()`
- `UpdateAppScopesView` → `connection_service.update_scopes()`
- `UpdateSharingBlobView` → `data_sharing_service.update_sharing_blob_for_connection()`
- `RevokeAppConnectionView` → `connection_service.revoke_connection()`
- `RestoreAppConnectionView` → `connection_service.restore_connection()`
- `GetAppConnectionForUserInfoView` → `connection_service.get_sharing_data()`

### Updated Consent Flow

The consent flow in `authentication/views.py` now uses `ConnectionService`:
- `_create_or_update_app_connection()` → `connection_service.create_or_update_connection()`
- Preserves manually managed scopes automatically

## API Compatibility

**All APIs remain backward compatible.** No client-side changes required immediately, but using the new services is recommended for:
- Better error handling
- Automatic logging
- Transaction safety
- Manual scope protection

## Breaking Changes

**None.** The redesign is fully backward compatible.

## Benefits

1. **Centralized Logic**: All connection logic in one place
2. **Better Testing**: Services can be easily unit tested
3. **Consistency**: All operations use same methods
4. **Safety**: Transaction safety and race condition prevention
5. **Extensibility**: Easy to add new features

## Usage Examples

### Creating/Updating a Connection

```python
from svasetting.connection_service import connection_service

connection = connection_service.create_or_update_connection(
    user=user,
    client_id='app_123',
    app_name='My App',
    approved_scopes=['email', 'profile'],
    app_logo='https://example.com/logo.png',
    encrypted_sharing_blob=encrypted_blob,
    sharing_blob_salt=salt,
    preserve_existing_scopes=False  # Set True to preserve manual scopes
)
```

### Updating Sharing Blob

```python
from svasetting.data_sharing_service import data_sharing_service

success = data_sharing_service.update_sharing_blob_for_connection(
    connection=connection,
    encrypted_blob=new_encrypted_blob,
    salt=new_salt
)
```

### Marking Blobs for Update

```python
# Mark all connections for update (when user data changes)
count = data_sharing_service.mark_blob_for_update(user=user)

# Mark specific connection
count = data_sharing_service.mark_blob_for_update(
    user=user,
    connection_id=connection_id
)
```

### Getting Sharing Data (OAuth Server)

```python
from svasetting.connection_service import connection_service

sharing_data = connection_service.get_sharing_data(
    user_id='user-uuid',
    client_id='app_123'
)

if sharing_data.get('exists'):
    encrypted_blob = sharing_data['encrypted_sharing_blob']
    salt = sharing_data['sharing_blob_salt']
    approved_scopes = sharing_data['approved_scopes']
```

## Event Signals

Listen to signals for automatic updates:

```python
from svasetting.data_sharing_service import (
    sharing_blob_updated,
    user_data_changed,
    connection_scopes_changed
)

@receiver(sharing_blob_updated)
def on_blob_updated(sender, connection, timestamp, **kwargs):
    # Handle blob update
    pass

@receiver(user_data_changed)
def on_user_data_changed(sender, user, connection, **kwargs):
    # Handle user data change
    # Update sharing blobs for affected connections
    pass
```

## Testing

Services can be easily tested:

```python
from svasetting.connection_service import connection_service
from django.test import TestCase

class ConnectionServiceTest(TestCase):
    def test_create_connection(self):
        connection = connection_service.create_or_update_connection(
            user=self.user,
            client_id='test_app',
            app_name='Test App',
            approved_scopes=['email']
        )
        self.assertIsNotNone(connection)
        self.assertEqual(connection.app_name, 'Test App')
```

## Next Steps

1. **Client Updates** (Optional): Update client code to use new APIs
2. **Monitoring**: Add monitoring for connection operations
3. **Analytics**: Track connection usage patterns
4. **Webhooks**: Add webhook support for data changes
5. **Connection Registry**: Central registry for app metadata

## Questions?

See `ARCHITECTURE.md` for detailed architecture documentation.

