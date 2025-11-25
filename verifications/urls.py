from django.urls import path

from verifications import views

urlpatterns = [
    # OTP verification
    path("otp/request/", views.RequestOTPView.as_view(), name="request_otp"),
    path("otp/verify/", views.VerifyOTPView.as_view(), name="verify_otp"),
    path("otp/check-status/", views.CheckVerificationStatusView.as_view(), name="check_verification_status"),
    path("verified-blocks/", views.GetVerifiedBlocksView.as_view(), name="get_verified_blocks"),

    # Document verification
    path("document/request/", views.RequestDocumentVerificationView.as_view(), name="request_document_verification"),
    path("document/verify/", views.VerifyDocumentView.as_view(), name="verify_document"),
    path("document/<uuid:verification_id>/", views.GetDocumentVerificationStatusView.as_view(), name="get_document_verification_status"),
    path("document/all/", views.GetDocumentVerificationsView.as_view(), name="get_document_verifications"),
]

