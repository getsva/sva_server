from django.urls import path
from .views import (
    GetCanvasView,
    CreateCanvasView,
    UpdateCanvasView,
    DeleteCanvasView,
    GetCanvasHistoryView,
    RestoreCanvasVersionView,
    RequestOTPView,
    VerifyOTPView,
    CheckVerificationStatusView,
    GetVerifiedBlocksView,
    RequestDocumentVerificationView,
    VerifyDocumentView,
    GetDocumentVerificationStatusView,
    GetDocumentVerificationsView,
    CheckUsernamePrefixView,
    RegisterUsernameView,
    UpdateUsernameView,
    DeleteUsernameView
)

urlpatterns = [
    # Get canvas
    path('canvas/', GetCanvasView.as_view(), name='get_canvas'),
    
    # Create canvas
    path('canvas/create/', CreateCanvasView.as_view(), name='create_canvas'),
    
    # Update canvas
    path('canvas/update/', UpdateCanvasView.as_view(), name='update_canvas'),
    
    # Delete canvas
    path('canvas/delete/', DeleteCanvasView.as_view(), name='delete_canvas'),
    
    # History
    path('canvas/history/', GetCanvasHistoryView.as_view(), name='get_history'),
    path('canvas/restore/', RestoreCanvasVersionView.as_view(), name='restore_version'),
    
    # Verification (Zero-Knowledge OTP)
    path('verification/request-otp/', RequestOTPView.as_view(), name='request_otp'),
    path('verification/verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('verification/check-status/', CheckVerificationStatusView.as_view(), name='check_verification_status'),
    path('verification/verified-blocks/', GetVerifiedBlocksView.as_view(), name='get_verified_blocks'),
    
    # Document Verification
    path('verification/document/request/', RequestDocumentVerificationView.as_view(), name='request_document_verification'),
    path('verification/document/verify/', VerifyDocumentView.as_view(), name='verify_document'),
    path('verification/document/<uuid:verification_id>/', GetDocumentVerificationStatusView.as_view(), name='get_document_verification_status'),
    path('verification/document/all/', GetDocumentVerificationsView.as_view(), name='get_document_verifications'),
    
    # Username Uniqueness (Zero-Knowledge)
    path('username/check-prefix/', CheckUsernamePrefixView.as_view(), name='check_username_prefix'),
    path('username/register/', RegisterUsernameView.as_view(), name='register_username'),
    path('username/update/', UpdateUsernameView.as_view(), name='update_username'),
    path('username/delete/', DeleteUsernameView.as_view(), name='delete_username'),
]

