# backend/urls.py

from django.contrib import admin
from django.urls import path, include
from .views import HealthCheckView

urlpatterns = [
    # Health check endpoints
    # Primary: /health (standard practice, avoids root path issues)
    path('health', HealthCheckView.as_view(), name='health_check'),
    path('health/', HealthCheckView.as_view(), name='health_check_slash'),
    # Secondary: root path (for Azure App Service default health checks)
    path('', HealthCheckView.as_view(), name='health_check_root'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls'),name='authentication'),
    path('api/internal/', include('authentication.internal_urls'), name='authentication_internal'),
    path('api/setting/', include('svasetting.urls'),name='svasetting'),
    path('api/canvas/', include('identity_canvas.urls'),name='identity_canvas'),
]