from django.urls import path

from .views import (
    AuthRequestConsentProxyView,
    AuthRequestDetailProxyView,
    DataAttestationView,
)


urlpatterns = [
    path('attest-data/', DataAttestationView.as_view(), name='data_attestation'),
    path('oauth/requests/<uuid:auth_request_id>/', AuthRequestDetailProxyView.as_view(), name='oauth_request_detail'),
    path('oauth/requests/<uuid:auth_request_id>/complete/', AuthRequestConsentProxyView.as_view(), name='oauth_request_complete'),
]

