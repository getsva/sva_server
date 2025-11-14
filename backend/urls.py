# backend/urls.py

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls'),name='authentication'),
    path('api/internal/', include('authentication.internal_urls'), name='authentication_internal'),
    path('api/setting/', include('svasetting.urls'),name='svasetting'),
    path('api/canvas/', include('identity_canvas.urls'),name='identity_canvas'),
]