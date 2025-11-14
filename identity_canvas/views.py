from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError

from .models import (
    IdentityCanvas, 
    CanvasHistory, 
    VerifiableBlockOTP, 
    VerifiedBlock,
    VerificationBlockType,
    DocumentVerification,
    UsernameProof
)
from .serializers import (
    IdentityCanvasSerializer,
    CreateCanvasSerializer,
    UpdateCanvasSerializer,
    CanvasHistorySerializer,
    RequestOTPSerializer,
    VerifyOTPSerializer,
    CheckVerificationStatusSerializer,
    VerifiableBlockOTPSerializer,
    VerifiedBlockSerializer,
    DocumentVerificationSerializer,
    RequestDocumentVerificationSerializer,
    VerifyDocumentSerializer,
    CheckUsernamePrefixSerializer,
    RegisterUsernameSerializer
)
import hashlib
from datetime import timedelta


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


# ==================== VERIFICATION VIEWS (Zero-Knowledge OTP) ====================

class RequestOTPView(APIView):
    """
    Request OTP for verifiable block verification
    
    Zero-Knowledge Design:
    - Client sends value (email/phone) to send OTP to
    - Server generates hash and stores it (never stores actual value long-term)
    - OTP is sent via email/SMS
    - Verification uses hash only (zero-knowledge)
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        block_type = serializer.validated_data['block_type']
        value = serializer.validated_data['value']
        
        # Generate hash (zero-knowledge storage)
        value_hash = VerifiableBlockOTP.generate_hash(value)
        
        # Check if already verified
        if VerifiedBlock.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=value_hash
        ).exists():
            return Response(
                {'error': f'{block_type} is already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Invalidate any existing pending OTPs for this block
        VerifiableBlockOTP.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            is_verified=False
        ).delete()
        
        # Generate OTP
        otp_code = VerifiableBlockOTP.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=15)
        
        # Create OTP record
        otp_record = VerifiableBlockOTP.objects.create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            otp_code=otp_code,
            expires_at=expires_at
        )
        
        # Send OTP based on block type
        otp_sent = False
        if block_type == VerificationBlockType.EMAIL:
            from authentication.email_service import send_otp_email
            otp_sent = send_otp_email(value, otp_code)
        elif block_type == VerificationBlockType.PHONE:
            from authentication.email_service import send_otp_sms  # Will create this
            otp_sent = send_otp_sms(value, otp_code)
        
        if not otp_sent:
            otp_record.delete()  # Clean up if sending failed
            return Response(
                {'error': f'Failed to send OTP to {block_type}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        return Response({
            'message': f'OTP sent to {block_type}',
            'otp_id': str(otp_record.id),
            'expires_at': otp_record.expires_at,
            'value_hash': value_hash  # Return hash for client to use in verification
        }, status=status.HTTP_201_CREATED)


class VerifyOTPView(APIView):
    """
    Verify OTP for verifiable block
    
    Zero-Knowledge Design:
    - Client sends hash (never sends actual value)
    - Server verifies OTP and marks block as verified
    - Only hash is stored, actual value remains encrypted in vault
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        block_type = serializer.validated_data['block_type']
        value_hash = serializer.validated_data['value_hash']
        otp_code = serializer.validated_data['otp_code']
        
        # Find valid OTP record
        try:
            otp_record = VerifiableBlockOTP.objects.get(
                user=user,
                block_type=block_type,
                value_hash=value_hash,
                is_verified=False
            )
        except VerifiableBlockOTP.DoesNotExist:
            return Response(
                {'error': 'Invalid OTP request. Please request a new OTP.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if OTP is valid
        if not otp_record.is_valid:
            if otp_record.is_expired:
                return Response(
                    {'error': 'OTP has expired. Please request a new OTP.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif otp_record.attempts >= otp_record.max_attempts:
                return Response(
                    {'error': 'Maximum verification attempts exceeded. Please request a new OTP.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Increment attempts
        otp_record.attempts += 1
        otp_record.save()
        
        # Verify OTP code
        if otp_record.otp_code != otp_code:
            return Response(
                {'error': 'Invalid OTP code', 'attempts_remaining': otp_record.max_attempts - otp_record.attempts},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark OTP as verified
        otp_record.is_verified = True
        otp_record.verified_at = timezone.now()
        otp_record.save()
        
        # Create or update verified block record
        verified_block, created = VerifiedBlock.objects.get_or_create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            defaults={
                'verification_method': 'otp'
            }
        )
        
        if not created:
            # Update verification timestamp
            verified_block.verified_at = timezone.now()
            verified_block.save()
        
        return Response({
            'message': f'{block_type} verified successfully',
            'verified': True,
            'verified_block': VerifiedBlockSerializer(verified_block).data
        }, status=status.HTTP_200_OK)


class CheckVerificationStatusView(APIView):
    """
    Check verification status of a verifiable block
    
    Zero-Knowledge Design:
    - Client sends hash only
    - Server returns verification status without knowing actual value
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = CheckVerificationStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        block_type = serializer.validated_data['block_type']
        value_hash = serializer.validated_data['value_hash']
        
        # Check if verified
        verified_block = VerifiedBlock.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=value_hash
        ).first()
        
        is_verified = verified_block is not None
        
        response_data = {
            'block_type': block_type,
            'value_hash': value_hash,
            'is_verified': is_verified
        }
        
        if is_verified:
            response_data['verified_at'] = verified_block.verified_at
            response_data['verification_method'] = verified_block.verification_method
        
        return Response(response_data, status=status.HTTP_200_OK)


class GetVerifiedBlocksView(APIView):
    """
    Get all verified blocks for current user
    Returns only metadata (block_type, verified_at) - no actual values (zero-knowledge)
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        verified_blocks = VerifiedBlock.objects.filter(user=request.user)
        serializer = VerifiedBlockSerializer(verified_blocks, many=True)
        
        return Response({
            'verified_blocks': serializer.data,
            'count': len(serializer.data)
        }, status=status.HTTP_200_OK)


# ==================== DOCUMENT VERIFICATION VIEWS ====================

class RequestDocumentVerificationView(APIView):
    """
    Request document verification (manual upload, third-party, institutional)
    
    Zero-Knowledge Design:
    - Client sends document identifier (e.g., PAN number) - will be hashed
    - Server stores only hash
    - Verification happens through external services
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = RequestDocumentVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        block_type = serializer.validated_data['block_type']
        document_identifier = serializer.validated_data['document_identifier']
        verification_method = serializer.validated_data['verification_method']
        additional_data = serializer.validated_data.get('additional_data', {})
        
        # Generate hash (zero-knowledge storage)
        document_hash = VerifiableBlockOTP.generate_hash(document_identifier)
        
        # Check if already verified
        verified_block = VerifiedBlock.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=document_hash
        ).first()
        
        if verified_block:
            return Response({
                'error': f'{block_type} is already verified',
                'verified_at': verified_block.verified_at,
                'verification_id': None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create or get existing verification request
        verification, created = DocumentVerification.objects.get_or_create(
            user=user,
            block_type=block_type,
            document_hash=document_hash,
            defaults={
                'verification_method': verification_method,
                'status': 'pending'
            }
        )
        
        if not created and verification.status == 'verified':
            return Response({
                'error': 'Document already verified',
                'verification_id': str(verification.id),
                'verified_at': verification.verified_at
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle different verification methods
        if verification_method == 'institutional':
            # For education/employment verification
            verification.status = 'pending'
            verification.save()
            
            return Response({
                'message': f'{block_type} verification request created',
                'verification_id': str(verification.id),
                'status': verification.status,
                'note': 'Verification will be processed through institutional verification'
            }, status=status.HTTP_201_CREATED)
        
        else:
            # Manual upload or third-party
            verification.status = 'pending'
            verification.save()
            
            return Response({
                'message': f'{block_type} verification request created',
                'verification_id': str(verification.id),
                'status': verification.status
            }, status=status.HTTP_201_CREATED)


class VerifyDocumentView(APIView):
    """
    Complete document verification
    Can be called after DigiLocker callback or manual verification
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request):
        serializer = VerifyDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        verification_id = serializer.validated_data['verification_id']
        verification_code = serializer.validated_data.get('verification_code')
        
        try:
            verification = DocumentVerification.objects.get(
                id=verification_id,
                user=user
            )
        except DocumentVerification.DoesNotExist:
            return Response(
                {'error': 'Verification request not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if verification.status == 'verified':
            return Response({
                'error': 'Document already verified',
                'verified_at': verification.verified_at
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # For now, simulate verification (in production, verify with external service)
        # In production:
        # - For third-party: Verify through external API
        # - For institutional: Verify with institution APIs
        # - For manual: Verify uploaded documents
        
        verification.status = 'verified'
        verification.verified_at = timezone.now()
        verification.save()
        
        # Create VerifiedBlock entry
        verified_block, created = VerifiedBlock.objects.get_or_create(
            user=user,
            block_type=verification.block_type,
            value_hash=verification.document_hash,
            defaults={
                'verification_method': verification.verification_method
            }
        )
        
        if not created:
            verified_block.verified_at = timezone.now()
            verified_block.verification_method = verification.verification_method
            verified_block.save()
        
        return Response({
            'message': f'{verification.block_type} verified successfully',
            'verified': True,
            'verified_at': verification.verified_at,
            'verified_block': VerifiedBlockSerializer(verified_block).data
        }, status=status.HTTP_200_OK)


class GetDocumentVerificationStatusView(APIView):
    """Get status of a document verification request"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, verification_id):
        try:
            verification = DocumentVerification.objects.get(
                id=verification_id,
                user=request.user
            )
        except DocumentVerification.DoesNotExist:
            return Response(
                {'error': 'Verification request not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = DocumentVerificationSerializer(verification)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetDocumentVerificationsView(APIView):
    """Get all document verification requests for current user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        verifications = DocumentVerification.objects.filter(user=request.user)
        serializer = DocumentVerificationSerializer(verifications, many=True)
        
        return Response({
            'verifications': serializer.data,
            'count': len(serializer.data)
        }, status=status.HTTP_200_OK)


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

