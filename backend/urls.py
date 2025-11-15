# backend/urls.py

from django.contrib import admin
from django.urls import path, include
from .views import HealthCheckView

urlpatterns = [
    # Health check endpoint at root
    # Using path('') handles both / and // to prevent redirect loops on Azure App Service
    path('', HealthCheckView.as_view(), name='health_check'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls'),name='authentication'),
    path('api/internal/', include('authentication.internal_urls'), name='authentication_internal'),
    path('api/setting/', include('svasetting.urls'),name='svasetting'),
    path('api/canvas/', include('identity_canvas.urls'),name='identity_canvas'),
]