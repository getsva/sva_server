# backend/middleware.py

from django.middleware.common import CommonMiddleware


class HealthCheckCommonMiddleware(CommonMiddleware):
    """
    Custom CommonMiddleware that skips APPEND_SLASH redirect for the root health check endpoint.
    This prevents 301 redirect loops on Azure App Service and other platforms.
    
    Azure App Service can cause redirect loops when:
    - Django's CommonMiddleware tries to append a trailing slash
    - Azure's reverse proxy adds/removes slashes
    - The health check endpoint is at the root path
    
    This middleware prevents the redirect for the root path only.
    """
    
    def process_request(self, request):
        # Skip APPEND_SLASH redirect for root path to prevent redirect loops
        # Handle both '/' and '' (empty string) paths
        path = request.path.rstrip('/')
        if path == '':
            # Let the request pass through without redirect
            # This prevents the 301 redirect loop on Azure App Service
            return None
        # For all other paths, use the default CommonMiddleware behavior
        return super().process_request(request)

