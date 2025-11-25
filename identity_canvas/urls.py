from django.urls import path
from .views import (
    GetCanvasView,
    CreateCanvasView,
    UpdateCanvasView,
    DeleteCanvasView,
    GetCanvasHistoryView,
    RestoreCanvasVersionView,
    CheckUsernamePrefixView,
    RegisterUsernameView,
    UpdateUsernameView,
    DeleteUsernameView,
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
    
    # Username Uniqueness (Zero-Knowledge)
    path('username/check-prefix/', CheckUsernamePrefixView.as_view(), name='check_username_prefix'),
    path('username/register/', RegisterUsernameView.as_view(), name='register_username'),
    path('username/update/', UpdateUsernameView.as_view(), name='update_username'),
    path('username/delete/', DeleteUsernameView.as_view(), name='delete_username'),
]

