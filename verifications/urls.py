from django.urls import path

from .views import (
    RequestOTPView,
    VerifyOTPView,
    CheckVerificationStatusView,
    VerifiedBlocksView,
    RequestDocumentVerificationView,
    VerifyDocumentView,
    DocumentVerificationStatusView,
    DocumentVerificationListView,
)

urlpatterns = [
    path("otp/request/", RequestOTPView.as_view(), name="request_otp"),
    path("otp/verify/", VerifyOTPView.as_view(), name="verify_otp"),
    path("otp/check-status/", CheckVerificationStatusView.as_view(), name="check_verification_status"),
    path("verified-blocks/", VerifiedBlocksView.as_view(), name="verified_blocks"),
    path("document/request/", RequestDocumentVerificationView.as_view(), name="request_document_verification"),
    path("document/verify/", VerifyDocumentView.as_view(), name="verify_document"),
    path("document/all/", DocumentVerificationListView.as_view(), name="document_verification_list"),
    path("document/<uuid:verification_id>/", DocumentVerificationStatusView.as_view(), name="document_verification_status"),
]

