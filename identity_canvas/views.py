from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction

from .models import (
    IdentityCanvas,
    CanvasHistory,
    UsernameProof,
)
from .serializers import (
    IdentityCanvasSerializer,
    CreateCanvasSerializer,
    UpdateCanvasSerializer,
    CanvasHistorySerializer,
    CheckUsernamePrefixSerializer,
    RegisterUsernameSerializer,
)


class GetCanvasView(APIView):
    """
    Get user's identity canvas
    Returns encrypted blocks data
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        try:
            canvas = IdentityCanvas.objects.get(user=user)
            serializer = IdentityCanvasSerializer(canvas)
            return Response(serializer.data)
        except IdentityCanvas.DoesNotExist:
            # Return empty canvas if not exists
            return Response({
                'id': None,
                'encrypted_blocks': '',  # Empty string - no canvas exists yet
                'created_at': None,
                'updated_at': None,
                'version': 0
            })


class CreateCanvasView(APIView):
    """
    Create identity canvas for user
    Client sends encrypted blocks data
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request):
        serializer = CreateCanvasSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        
        # Check if canvas already exists
        if IdentityCanvas.objects.filter(user=user).exists():
            return Response(
                {'error': 'Identity canvas already exists. Use update endpoint.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create new canvas
        canvas = IdentityCanvas.objects.create(
            user=user,
            encrypted_blocks=serializer.validated_data['encrypted_blocks']
        )
        
        # Create initial history entry if needed
        CanvasHistory.objects.create(
            canvas=canvas,
            encrypted_blocks_snapshot=canvas.encrypted_blocks,
            version=1,
            action='create'
        )
        
        serializer = IdentityCanvasSerializer(canvas)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UpdateCanvasView(APIView):
    """
    Update identity canvas
    Client sends encrypted blocks data
    Supports optimistic locking with version field
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def patch(self, request):
        serializer = UpdateCanvasSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        
        try:
            canvas = IdentityCanvas.objects.get(user=user)
        except IdentityCanvas.DoesNotExist:
            # Create if doesn't exist
            canvas = IdentityCanvas.objects.create(
                user=user,
                encrypted_blocks=serializer.validated_data['encrypted_blocks']
            )
            CanvasHistory.objects.create(
                canvas=canvas,
                encrypted_blocks_snapshot=canvas.encrypted_blocks,
                version=1,
                action='create'
            )
            serializer_response = IdentityCanvasSerializer(canvas)
            return Response(serializer_response.data)
        
        # Optimistic locking check
        requested_version = serializer.validated_data.get('version')
        if requested_version is not None:
            if canvas.version != requested_version:
                return Response(
                    {
                        'error': 'Version conflict. Canvas was modified by another request.',
                        'current_version': canvas.version
                    },
                    status=status.HTTP_409_CONFLICT
                )
        
        # Store old data for history
        old_encrypted_blocks = canvas.encrypted_blocks
        old_version = canvas.version
        
        # Update canvas
        canvas.encrypted_blocks = serializer.validated_data['encrypted_blocks']
        canvas.version += 1
        canvas.save()
        
        # Create history entry if requested
        create_history = serializer.validated_data.get('create_history', False)
        if create_history:
            CanvasHistory.objects.create(
                canvas=canvas,
                encrypted_blocks_snapshot=old_encrypted_blocks,
                version=old_version,
                action='update'
            )
        
        serializer_response = IdentityCanvasSerializer(canvas)
        return Response(serializer_response.data)


class DeleteCanvasView(APIView):
    """
    Delete identity canvas
    Permanently removes all canvas data, history, and associated username proof
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def delete(self, request):
        user = request.user
        
        try:
            canvas = IdentityCanvas.objects.get(user=user)
            canvas_id = canvas.id
            
            # Delete history first (foreign key constraint)
            CanvasHistory.objects.filter(canvas=canvas).delete()
            
            # Delete username proof if it exists (username is part of canvas)
            # When canvas is deleted, username should also be deleted
            UsernameProof.objects.filter(user=user).delete()
            
            # Delete canvas
            canvas.delete()
            
            return Response({
                'message': 'Identity canvas deleted successfully',
                'deleted_id': str(canvas_id)
            })
        except IdentityCanvas.DoesNotExist:
            return Response(
                {'error': 'Identity canvas not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class GetCanvasHistoryView(APIView):
    """
    Get history of canvas changes
    Returns encrypted snapshots for audit purposes
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        try:
            canvas = IdentityCanvas.objects.get(user=user)
        except IdentityCanvas.DoesNotExist:
            return Response(
                {'error': 'Identity canvas not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get pagination parameters
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get history entries
        history = CanvasHistory.objects.filter(canvas=canvas)[offset:offset + limit]
        total_count = CanvasHistory.objects.filter(canvas=canvas).count()
        
        serializer = CanvasHistorySerializer(history, many=True)
        
        return Response({
            'history': serializer.data,
            'total': total_count,
            'limit': limit,
            'offset': offset
        })


class RestoreCanvasVersionView(APIView):
    """
    Restore canvas to a specific version from history
    Creates a new version with restored data
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request):
        user = request.user
        version_id = request.data.get('version_id')
        
        if not version_id:
            return Response(
                {'error': 'version_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            canvas = IdentityCanvas.objects.get(user=user)
        except IdentityCanvas.DoesNotExist:
            return Response(
                {'error': 'Identity canvas not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            history_entry = CanvasHistory.objects.get(
                id=version_id,
                canvas=canvas
            )
        except CanvasHistory.DoesNotExist:
            return Response(
                {'error': 'History version not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Store old data for history
        old_encrypted_blocks = canvas.encrypted_blocks
        old_version = canvas.version
        
        # Restore from history
        canvas.encrypted_blocks = history_entry.encrypted_blocks_snapshot
        canvas.version += 1
        canvas.save()
        
        # Create history entry for restore action
        CanvasHistory.objects.create(
            canvas=canvas,
            encrypted_blocks_snapshot=old_encrypted_blocks,
            version=old_version,
            action=f'restore_from_v{history_entry.version}'
        )
        
        serializer = IdentityCanvasSerializer(canvas)
        return Response({
            'message': f'Canvas restored to version {history_entry.version}',
            'canvas': serializer.data
        })


# ==================== USERNAME UNIQUENESS VIEWS (Zero-Knowledge) ====================

class CheckUsernamePrefixView(APIView):
    """
    Check username uniqueness using k-anonymity prefix matching
    
    Zero-Knowledge Design:
    - Client sends prefix (first 8 chars) of hashed username
    - Server returns list of full hashes matching that prefix
    - Client checks locally if its full hash exists
    - Server never learns the actual username or full hash
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from .serializers import CheckUsernamePrefixSerializer
        from django.conf import settings
        
        serializer = CheckUsernamePrefixSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        prefix = serializer.validated_data['prefix']
        
        # Get all proofs with matching prefix
        # Return username_hashes (not proof_hashes) so client can check locally
        matching_proofs = UsernameProof.objects.filter(prefix=prefix)
        matching_hashes = list(matching_proofs.values_list('username_hash', flat=True))
        
        return Response({
            'prefix': prefix,
            'matching_hashes': matching_hashes,
            'count': len(matching_hashes)
        }, status=status.HTTP_200_OK)


class RegisterUsernameView(APIView):
    """
    Register username uniqueness proof after client confirms uniqueness
    
    Zero-Knowledge Design:
    - Client sends full username_hash (with public pepper)
    - Server computes proof_hash = SHA-256(username_hash + SECRET_PEPPER)
    - Server stores proof_hash (not username_hash directly)
    - Server cannot reverse proof_hash to get username
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from .serializers import RegisterUsernameSerializer
        from django.conf import settings
        from .models import UsernameProof
        
        serializer = RegisterUsernameSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        username_hash = serializer.validated_data['username_hash']
        
        # Check if user already has a username proof
        existing_proof = UsernameProof.objects.filter(user=user).first()
        
        if existing_proof:
            return Response({
                'error': 'Username already registered for this user',
                'message': 'You already have a username. Update it instead.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate proof hash using secret pepper
        secret_pepper = settings.SVA_SECRET_SERVER_PEPPER
        proof_hash = UsernameProof.generate_proof_hash(username_hash, secret_pepper)
        prefix = UsernameProof.get_prefix(username_hash)
        
        # Check if proof_hash already exists (username taken)
        if UsernameProof.objects.filter(proof_hash=proof_hash).exists():
            return Response({
                'error': 'Username already taken',
                'message': 'This username is already in use'
            }, status=status.HTTP_409_CONFLICT)
        
        # Create username proof
        username_proof = UsernameProof.objects.create(
            user=user,
            proof_hash=proof_hash,
            prefix=prefix,
            username_hash=username_hash  # Store for prefix matching (needed for k-anonymity)
        )
        
        return Response({
            'message': 'Username registered successfully',
            'proof_id': str(username_proof.id)
        }, status=status.HTTP_201_CREATED)


class UpdateUsernameView(APIView):
    """
    Update username uniqueness proof
    
    Zero-Knowledge Design:
    - Same as RegisterUsernameView but updates existing proof
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from .serializers import RegisterUsernameSerializer
        from django.conf import settings
        from .models import UsernameProof
        
        serializer = RegisterUsernameSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        username_hash = serializer.validated_data['username_hash']
        
        # Get existing proof
        existing_proof = UsernameProof.objects.filter(user=user).first()
        
        if not existing_proof:
            return Response({
                'error': 'No username registered',
                'message': 'Register a username first'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Generate new proof hash
        secret_pepper = settings.SVA_SECRET_SERVER_PEPPER
        proof_hash = UsernameProof.generate_proof_hash(username_hash, secret_pepper)
        prefix = UsernameProof.get_prefix(username_hash)
        
        # Check if new proof_hash already exists (and not owned by this user)
        if UsernameProof.objects.filter(proof_hash=proof_hash).exclude(user=user).exists():
            return Response({
                'error': 'Username already taken',
                'message': 'This username is already in use by another user'
            }, status=status.HTTP_409_CONFLICT)
        
        # Update existing proof
        existing_proof.proof_hash = proof_hash
        existing_proof.prefix = prefix
        existing_proof.username_hash = username_hash
        existing_proof.save()
        
        return Response({
            'message': 'Username updated successfully',
            'proof_id': str(existing_proof.id)
        }, status=status.HTTP_200_OK)


class DeleteUsernameView(APIView):
    """
    Delete username proof when username block is removed from canvas
    
    Zero-Knowledge Design:
    - Called when user removes username block from their canvas
    - Deletes the username proof to free up the username for others
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def delete(self, request):
        user = request.user
        
        # Delete username proof if it exists
        deleted_count = UsernameProof.objects.filter(user=user).delete()[0]
        
        if deleted_count > 0:
            return Response({
                'message': 'Username proof deleted successfully',
                'deleted': True
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': 'No username proof found to delete',
                'deleted': False
            }, status=status.HTTP_200_OK)

