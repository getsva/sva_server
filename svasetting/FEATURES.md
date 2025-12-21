# Connection Management Features

## Complete Feature List

### Core Services

1. **ConnectionService** - Centralized connection management
   - Create/update connections
   - Get connections by ID or client_id
   - List connections with filtering
   - Revoke and restore connections
   - Update scopes with manual override protection
   - Get sharing data for OAuth server
   - Automatic security logging
   - Transaction safety

2. **DataSharingService** - Encrypted sharing blob management
   - Update sharing blobs for connections
   - Validate blob format
   - Mark blobs for update when user data changes
   - Event signals for automatic updates
   - Get connections needing updates

3. **ConnectionRegistry** - App metadata registry
   - App metadata caching
   - Connection statistics
   - App discovery
   - Metadata synchronization
   - Cache invalidation

4. **Connection Utilities** - Helper functions
   - Scope normalization and validation
   - Bulk blob updates
   - Connection health checks
   - Connection summaries
   - App metadata helpers

### Batch Operations

5. **BatchConnectionOperations** - Efficient bulk operations
   - Bulk revoke connections
   - Bulk update metadata
   - Bulk mark for blob update
   - Bulk health check
   - Bulk update scopes

### Webhooks

6. **WebhookService** - Event notifications
   - Connection created notifications
   - Connection revoked notifications
   - Scope updated notifications
   - Sharing blob updated notifications
   - HMAC signature support

### Signal Handlers

7. **Automatic Signal Handlers**
   - User data changed → Mark connections for blob update
   - Connection scopes changed → Mark for blob update
   - Sharing blob updated → Trigger webhooks
   - Connection saved → Invalidate cache
   - Connection deleted → Invalidate cache

### Admin Interface

8. **Enhanced Admin Interface**
   - Connection list with status badges
   - Scope count display
   - Sharing blob status
   - Health indicators
   - Bulk actions:
     - Mark as active
     - Mark as revoked
     - Refresh sharing blobs
     - Check health

### Management Commands

9. **Management Commands**
   - `sync_connection_metadata` - Sync app metadata from OAuth server
   - `check_connection_health` - Monitor connection health

### API Endpoints

10. **REST API Endpoints**

    **Connection Management:**
    - `GET /zk/settings/app-connections/` - List connections
    - `GET /zk/settings/app-connections/<id>/` - Get connection
    - `PATCH /zk/settings/app-connections/<id>/scopes/` - Update scopes
    - `POST /zk/settings/app-connections/<id>/sharing-blob/` - Update sharing blob
    - `POST /zk/settings/app-connections/<id>/revoke/` - Revoke connection
    - `POST /zk/settings/app-connections/<id>/restore/` - Restore connection

    **Registry & Utilities:**
    - `GET /zk/settings/app-connections/stats/` - Get statistics
    - `GET /zk/settings/app-connections/health/` - Check all connections health
    - `GET /zk/settings/app-connections/<id>/health/` - Check specific connection
    - `GET /zk/settings/app-metadata/?client_id=X` - Get app metadata

    **Batch Operations:**
    - `POST /zk/settings/app-connections/batch/revoke/` - Bulk revoke
    - `POST /zk/settings/app-connections/batch/update-metadata/` - Bulk update metadata
    - `POST /zk/settings/app-connections/batch/mark-blob-update/` - Bulk mark for update
    - `GET /zk/settings/app-connections/batch/health-check/` - Bulk health check
    - `POST /zk/settings/app-connections/batch/update-scopes/` - Bulk update scopes

    **Internal APIs:**
    - `GET /api/internal/app-connections/userinfo/?client_id=X&user_id=Y` - Get sharing data

## Key Features

### 1. Manual Scope Protection
- Automatically detects manually managed scopes
- Preserves user's manual permission settings
- Only allows reducing scopes (not adding) when manually managed

### 2. Transaction Safety
- All operations use `@transaction.atomic`
- `select_for_update()` prevents race conditions
- Consistent error handling

### 3. Event-Driven Updates
- Signals for blob updates
- Signals for user data changes
- Signals for scope changes
- Automatic webhook notifications

### 4. Metadata Caching
- App metadata cached for performance
- Automatic cache invalidation
- Fallback to database and OAuth server

### 5. Health Monitoring
- Connection health checks
- Identifies issues (old blobs, missing blobs)
- Bulk health checks
- Optional automatic fixes

### 6. Statistics & Analytics
- Connection statistics
- App popularity tracking
- User connection summaries
- Health metrics

### 7. Batch Operations
- Efficient bulk operations
- Transaction safety
- Error handling and reporting

### 8. Webhook Support
- Event notifications
- HMAC signature support
- Configurable webhook URLs
- Automatic retries (via signal handlers)

## Configuration

### Webhook Configuration

Add to `settings.py`:

```python
# Webhook configuration
CONNECTION_WEBHOOK_URL = 'https://your-webhook-endpoint.com/webhooks'
CONNECTION_WEBHOOK_SECRET = 'your-webhook-secret'  # Optional, for HMAC signing
```

### Cache Configuration

The registry uses Django's cache framework. Configure in `settings.py`:

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

## Usage Examples

### Batch Operations

```python
from svasetting.batch_operations import batch_operations

# Bulk revoke connections
results = batch_operations.bulk_revoke_connections(
    user=user,
    connection_ids=['id1', 'id2', 'id3'],
    reason='User requested'
)

# Bulk update metadata
results = batch_operations.bulk_update_metadata(
    client_id='app_123',
    name='New App Name',
    logo='https://example.com/new-logo.png'
)

# Bulk mark for blob update
results = batch_operations.bulk_mark_for_blob_update(
    user=user,
    connection_ids=['id1', 'id2']
)
```

### Webhooks

Webhooks are automatically sent when:
- Connection is created
- Connection is revoked
- Scopes are updated
- Sharing blob is updated

Configure webhook URL in settings to enable.

### Health Checks

```python
from svasetting.connection_utils import check_connection_health

health = check_connection_health(connection)
if not health['is_healthy']:
    print(f"Issues: {health['issues']}")
```

## Performance

- **Caching**: App metadata cached for 1 hour
- **Batch Operations**: Efficient bulk operations with transactions
- **Select Related**: Optimized database queries
- **Connection Pooling**: Uses Django's database connection pooling

## Security

- **Service Token Auth**: Internal APIs require service token
- **HMAC Signatures**: Webhooks can be signed with HMAC
- **Transaction Safety**: All operations use transactions
- **Scope Validation**: Only approved scopes are returned
- **Connection Validation**: Active connections only for data access

## Monitoring

- **Health Checks**: Monitor connection health
- **Statistics**: Track connection usage
- **Logging**: Comprehensive logging for all operations
- **Webhooks**: Event notifications for external systems

## Future Enhancements

1. **Rate Limiting**: Per-connection rate limits
2. **Connection Templates**: Pre-configured connection types
3. **Analytics Dashboard**: Visual connection analytics
4. **Webhook Retries**: Automatic retry for failed webhooks
5. **Connection Groups**: Group connections for bulk operations
6. **Audit Trail**: Detailed audit log for all operations

