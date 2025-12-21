# Connection Management & Data Sharing

This module provides centralized connection management and data sharing services for SVA.

## Services

### ConnectionService (`connection_service.py`)

Centralized service for managing all app connections.

**Key Features:**
- Create/update connections
- Manage connection lifecycle (revoke, restore)
- Handle scope management with manual override protection
- Provide connection lookup and listing
- Integrate with security logging

**Usage:**
```python
from svasetting.connection_service import connection_service

# Create or update connection
connection = connection_service.create_or_update_connection(
    user=user,
    client_id='app_123',
    app_name='My App',
    approved_scopes=['email', 'profile']
)

# Get connection
connection = connection_service.get_connection(user, 'app_123')

# List connections
connections = connection_service.list_connections(user)

# Revoke connection
connection_service.revoke_connection(user, connection_id)
```

### DataSharingService (`data_sharing_service.py`)

Service for managing encrypted sharing blobs.

**Key Features:**
- Update sharing blobs for connections
- Validate blob format
- Mark blobs for update when user data changes
- Provide event signals for automatic updates

**Usage:**
```python
from svasetting.data_sharing_service import data_sharing_service

# Update sharing blob
data_sharing_service.update_sharing_blob_for_connection(
    connection=connection,
    encrypted_blob=encrypted_blob,
    salt=salt
)

# Mark for update
data_sharing_service.mark_blob_for_update(user, connection_id)
```

### ConnectionRegistry (`connection_registry.py`)

Registry for managing app metadata and connection information.

**Key Features:**
- App metadata caching
- Connection statistics
- App discovery
- Metadata synchronization

**Usage:**
```python
from svasetting.connection_registry import connection_registry

# Get app metadata
metadata = connection_registry.get_app_metadata('app_123')

# Get connection stats
stats = connection_registry.get_connection_stats(user=user)

# Update app metadata
connection_registry.update_app_metadata(
    client_id='app_123',
    name='New App Name',
    logo='https://example.com/logo.png'
)
```

### Connection Utilities (`connection_utils.py`)

Helper functions for connection management.

**Key Features:**
- Scope normalization and validation
- Bulk operations
- Connection health checks
- Utility functions

**Usage:**
```python
from svasetting.connection_utils import (
    normalize_scopes,
    validate_scopes,
    check_connection_health,
    get_connection_summary
)

# Normalize scopes
scopes = normalize_scopes(['email', 'profile', 'email'])  # ['email', 'profile']

# Validate scopes
is_valid, valid, invalid = validate_scopes(
    requested_scopes=['email', 'profile', 'invalid'],
    available_scopes=['email', 'profile']
)

# Check connection health
health = check_connection_health(connection)
```

## API Endpoints

### Connection Management

- `GET /zk/settings/app-connections/` - List connections
- `GET /zk/settings/app-connections/<id>/` - Get connection
- `PATCH /zk/settings/app-connections/<id>/scopes/` - Update scopes
- `POST /zk/settings/app-connections/<id>/sharing-blob/` - Update sharing blob
- `POST /zk/settings/app-connections/<id>/revoke/` - Revoke connection
- `POST /zk/settings/app-connections/<id>/restore/` - Restore connection

### Registry & Utilities

- `GET /zk/settings/app-connections/stats/` - Get connection statistics
- `GET /zk/settings/app-connections/health/` - Check all connections health
- `GET /zk/settings/app-connections/<id>/health/` - Check specific connection health
- `GET /zk/settings/app-metadata/?client_id=X` - Get app metadata

### Internal APIs

- `GET /api/internal/app-connections/userinfo/?client_id=X&user_id=Y` - Get sharing data (OAuth server)

## Management Commands

### Sync Connection Metadata

Sync app metadata from OAuth server:

```bash
python manage.py sync_connection_metadata --client-id app_123
python manage.py sync_connection_metadata --all
```

### Check Connection Health

Check health of connections:

```bash
python manage.py check_connection_health
python manage.py check_connection_health --user-id user-uuid
python manage.py check_connection_health --client-id app_123
python manage.py check_connection_health --fix  # Attempt to fix issues
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
```

## Architecture

See `ARCHITECTURE.md` for detailed architecture documentation.

## Migration

See `MIGRATION_GUIDE.md` for migration guide and examples.

