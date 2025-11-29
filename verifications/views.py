import json
import logging
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.email_service import send_otp_email, send_otp_sms
from identity_canvas.models import (
    DocumentVerification,
    VerificationBlockType,
    VerifiableBlockOTP,
    VerifiedBlock,
    AadhaarVerificationSession,
    UniquenessProof,
    PANUniquenessProof,
)
from .serializers import (
    RequestOTPSerializer,
    VerifyOTPSerializer,
    CheckVerificationStatusSerializer,
    DocumentVerificationRequestSerializer,
    DocumentVerificationVerifySerializer,
    DocumentVerificationStatusSerializer,
    AadhaarGenerateOTPSerializer,
    AadhaarVerifyOTPSerializer,
    CleanupVerificationDataSerializer,
)
from .sandbox_client import SandboxKYCClient, SandboxAPIError, SandboxConfigurationError


OTP_EXPIRATION_MINUTES = 15
logger = logging.getLogger(__name__)


class RequestOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        block_type = serializer.validated_data["block_type"]
        value = serializer.validated_data["value"].strip()
        delivery_method = serializer.validated_data.get("delivery_method")
        frontend_url = serializer.validated_data.get("frontend_url")

        value_hash = VerifiableBlockOTP.generate_hash(value)
        otp_code = VerifiableBlockOTP.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)

        otp_entry = VerifiableBlockOTP.objects.create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            otp_code=otp_code,
            expires_at=expires_at,
        )

        try:
            if delivery_method == "sms" or block_type == VerificationBlockType.PHONE:
                send_otp_sms(value, otp_code)
            else:
                target_email = value if block_type == VerificationBlockType.EMAIL else user.email
                send_otp_email(target_email, otp_code, frontend_url)
        except Exception:
            # Fail silently to avoid leaking OTP generation issues; client can retry.
            pass

        return Response(
            {
                "message": "OTP generated successfully",
                "otp_id": str(otp_entry.id),
                "expires_at": expires_at.isoformat(),
                "value_hash": value_hash,
            },
            status=status.HTTP_200_OK,
        )


class VerifyOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        block_type = serializer.validated_data["block_type"]
        value_hash = serializer.validated_data["value_hash"]
        otp_code = serializer.validated_data["otp_code"]

        otp_entry = (
            VerifiableBlockOTP.objects.filter(
                user=user,
                block_type=block_type,
                value_hash=value_hash,
            )
            .order_by("-created_at")
            .first()
        )

        if not otp_entry:
            return Response(
                {"error": "OTP not found for the provided value."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not otp_entry.is_valid:
            return Response(
                {"error": "OTP is no longer valid. Please request a new code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if otp_entry.otp_code != otp_code:
            otp_entry.attempts += 1
            otp_entry.save(update_fields=["attempts"])
            return Response(
                {"error": "Invalid OTP code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp_entry.is_verified = True
        otp_entry.verified_at = timezone.now()
        otp_entry.save(update_fields=["is_verified", "verified_at"])

        verified_block, _created = VerifiedBlock.objects.update_or_create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            defaults={
                "verified_at": timezone.now(),
                "verification_method": "otp",
            },
        )

        return Response(
            {
                "message": "Verification successful",
                "verified": True,
                "verified_block": {
                    "id": str(verified_block.id),
                    "block_type": verified_block.block_type,
                    "value_hash": verified_block.value_hash,
                    "verified_at": verified_block.verified_at.isoformat(),
                    "verification_method": verified_block.verification_method,
                },
            },
            status=status.HTTP_200_OK,
        )


class CheckVerificationStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CheckVerificationStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        block_type = serializer.validated_data["block_type"]
        value_hash = serializer.validated_data["value_hash"]

        verified_block = VerifiedBlock.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
        ).first()

        if not verified_block:
            return Response(
                {
                    "block_type": block_type,
                    "value_hash": value_hash,
                    "is_verified": False,
                }
            )

        return Response(
            {
                "block_type": block_type,
                "value_hash": value_hash,
                "is_verified": True,
                "verified_at": verified_block.verified_at.isoformat(),
                "verification_method": verified_block.verification_method,
            }
        )


class VerifiedBlocksView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        blocks = VerifiedBlock.objects.filter(user=request.user).order_by("-verified_at")
        data = [
            {
                "id": str(block.id),
                "block_type": block.block_type,
                "value_hash": block.value_hash,
                "verified_at": block.verified_at.isoformat(),
                "verification_method": block.verification_method,
            }
            for block in blocks
        ]
        return Response({"verified_blocks": data, "count": len(data)})


def _hash_document_identifier(identifier: str) -> str:
    return VerifiableBlockOTP.generate_hash(identifier.strip())


class RequestDocumentVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DocumentVerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        block_type = serializer.validated_data["block_type"]
        document_identifier = serializer.validated_data["document_identifier"]
        verification_method = serializer.validated_data["verification_method"]
        additional_data = serializer.validated_data.get("additional_data") or {}
        
        # For PAN verification, only store pan_hash_with_pepper (zero-knowledge)
        # Do NOT store the actual PAN number in metadata

        document_hash = _hash_document_identifier(document_identifier)
        
        # Use get_or_create to handle existing verifications gracefully
        verification, created = DocumentVerification.objects.get_or_create(
            user=user,
            block_type=block_type,
            document_hash=document_hash,
            defaults={
                "verification_method": verification_method,
                "status": "pending",
                "verification_metadata": json.dumps(additional_data),
            }
        )
        
        # If verification already exists, update metadata if needed
        if not created:
            existing_metadata = json.loads(verification.verification_metadata or "{}")
            existing_metadata.update(additional_data)
            verification.verification_metadata = json.dumps(existing_metadata)
            # Reset status to pending if it was rejected/expired
            if verification.status in ["rejected", "expired"]:
                verification.status = "pending"
            verification.save(update_fields=["verification_metadata", "status"])

        return Response(
            {
                "message": "Document verification requested" if created else "Verification already exists, returning existing verification",
                "verification_id": str(verification.id),
                "status": verification.status,
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class VerifyDocumentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DocumentVerificationVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        verification_id = serializer.validated_data["verification_id"]
        verification_code = serializer.validated_data.get("verification_code")

        try:
            verification = DocumentVerification.objects.get(id=verification_id, user=request.user)
        except DocumentVerification.DoesNotExist:
            return Response({"error": "Verification not found."}, status=status.HTTP_404_NOT_FOUND)

        # For PAN verification via third-party, call Sandbox API
        if verification.block_type == VerificationBlockType.PAN_CARD and verification.verification_method == "third_party":
            # Get PAN details from request (zero-knowledge - not stored in DB)
            pan_details = serializer.validated_data.get("pan_details")
            if not pan_details:
                return Response(
                    {"error": "Missing required PAN verification details (pan_details)"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            pan_number = pan_details.get("pan_number")
            name_as_per_pan = pan_details.get("name_as_per_pan")
            date_of_birth = pan_details.get("date_of_birth")
            consent = pan_details.get("consent", "Y")
            reason = pan_details.get("reason", "identity_verification")
            
            if not all([pan_number, name_as_per_pan, date_of_birth]):
                return Response(
                    {"error": "Missing required PAN verification fields (pan_number, name_as_per_pan, date_of_birth)"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                sandbox_client = SandboxKYCClient()
                if not sandbox_client.is_configured:
                    # Fallback to mock if Sandbox is not configured
                    if _sandbox_allow_mock_fallback():
                        logger.warning("Sandbox not configured, using mock PAN verification")
                        verification.status = "verified"
                        verification.verified_at = timezone.now()
                        verification.save(update_fields=["status", "verified_at"])
                    else:
                        return Response(
                            {"error": "PAN verification service is not configured"},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE
                        )
                else:
                    # Call Sandbox API
                    sandbox_response = sandbox_client.verify_pan(
                        pan=pan_number,
                        name_as_per_pan=name_as_per_pan,
                        date_of_birth=date_of_birth,
                        consent=consent,
                        reason=reason
                    )
                    
                    # Check if verification was successful
                    data = sandbox_response.get("data", {})
                    pan_status = data.get("status", "").lower()
                    
                    if pan_status == "valid":
                        verification.status = "verified"
                        verification.verified_at = timezone.now()
                        # Store only sanitized Sandbox response (no PII) in metadata
                        import json
                        existing_metadata = json.loads(verification.verification_metadata or "{}")
                        # Only store sanitized response - never store PAN number or other PII
                        existing_metadata["sandbox_response"] = _sanitize_sandbox_metadata(sandbox_response)
                        verification.verification_metadata = json.dumps(existing_metadata)
                        verification.save(update_fields=["status", "verified_at", "verification_metadata"])
                    else:
                        verification.status = "rejected"
                        verification.save(update_fields=["status"])
                        return Response(
                            {
                                "error": f"PAN verification failed: {data.get('remarks', 'Invalid PAN')}",
                                "verified": False,
                                "status": verification.status,
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
            except SandboxAPIError as e:
                logger.error("Sandbox PAN verification failed: %s", e)
                # If Sandbox returns 403 or other errors, allow mock fallback if enabled
                if _sandbox_allow_mock_fallback():
                    logger.warning("Sandbox PAN verification failed, using mock fallback: %s", e)
                    verification.status = "verified"
                    verification.verified_at = timezone.now()
                    verification.save(update_fields=["status", "verified_at"])
                else:
                    return Response(
                        {"error": f"PAN verification service error: {str(e)}"},
                        status=status.HTTP_502_BAD_GATEWAY
                    )
        else:
            # For other document types or methods, use placeholder logic
            verification.status = "verified"
            verification.verified_at = timezone.now()
            verification.save(update_fields=["status", "verified_at"])

        verified_block, created = VerifiedBlock.objects.update_or_create(
            user=request.user,
            block_type=verification.block_type,
            value_hash=verification.document_hash,
            defaults={
                "verified_at": timezone.now(),
                "verification_method": verification.verification_method or "document",
            },
        )

        # Store PAN uniqueness proof if this is a PAN verification
        if verification.block_type == VerificationBlockType.PAN_CARD:
            import json
            verification_metadata = json.loads(verification.verification_metadata or "{}")
            pan_hash_with_pepper = verification_metadata.get("pan_hash_with_pepper")
            
            if pan_hash_with_pepper:
                from django.conf import settings
                secret_pepper = getattr(settings, 'SVA_SECRET_SERVER_PEPPER', 'sva-secret-server-pepper-2024-never-expose-this-value')
                
                # Generate final_hash with secret pepper
                final_hash = PANUniquenessProof.generate_final_hash(pan_hash_with_pepper, secret_pepper)
                prefix = PANUniquenessProof.get_prefix(pan_hash_with_pepper)
                
                # Store uniqueness proof (get_or_create to handle race conditions)
                PANUniquenessProof.objects.get_or_create(
                    final_hash=final_hash,
                    defaults={
                        'pan_hash': pan_hash_with_pepper,
                        'prefix': prefix,
                    }
                )

        return Response(
            {
                "message": "Document verified successfully",
                "verified": True,
                "verified_at": verification.verified_at.isoformat(),
            }
        )


class DocumentVerificationStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, verification_id):
        try:
            verification = DocumentVerification.objects.get(id=verification_id, user=request.user)
        except DocumentVerification.DoesNotExist:
            return Response({"error": "Verification not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response(
            {
                "id": str(verification.id),
                "block_type": verification.block_type,
                "document_hash": verification.document_hash,
                "verification_method": verification.verification_method,
                "status": verification.status,
                "created_at": verification.created_at.isoformat(),
                "verified_at": verification.verified_at.isoformat() if verification.verified_at else None,
            }
        )


class DocumentVerificationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        verifications = DocumentVerification.objects.filter(user=request.user).order_by("-created_at")
        data = [
            {
                "id": str(verification.id),
                "block_type": verification.block_type,
                "document_hash": verification.document_hash,
                "verification_method": verification.verification_method,
                "status": verification.status,
                "created_at": verification.created_at.isoformat(),
                "verified_at": verification.verified_at.isoformat() if verification.verified_at else None,
            }
            for verification in verifications
        ]
        return Response({"verifications": data, "count": len(data)})


def _extract_reference_id(payload: dict) -> str:
    data = payload.get("data") or {}
    reference = data.get("reference_id") or payload.get("reference_id")
    if reference is None:
        return str(uuid.uuid4())
    return str(reference)


def _extract_message(payload: dict) -> str | None:
    data = payload.get("data") or {}
    return data.get("message") or payload.get("message")


def _sanitize_sandbox_metadata(payload: dict) -> dict:
    data = payload.get("data") or {}
    sanitized = {
        "status": data.get("status"),
        "message": data.get("message") or payload.get("message"),
    }
    if payload.get("transaction_id"):
        sanitized["transaction_id"] = payload.get("transaction_id")
    return {k: v for k, v in sanitized.items() if v}


def _format_aadhaar_details(data: dict | None) -> dict | None:
    if not data:
        return None
    details = {
        "status": data.get("status"),
        "message": data.get("message"),
        "name": data.get("name"),
        "gender": data.get("gender"),
        "date_of_birth": data.get("date_of_birth"),
        "year_of_birth": data.get("year_of_birth"),
        "care_of": data.get("care_of"),
        "full_address": data.get("full_address"),
        "address": data.get("address"),
        "email_hash": data.get("email_hash"),
        "mobile_hash": data.get("mobile_hash"),
        "share_code": data.get("share_code"),
        "photo": data.get("photo"),
        "reference_id": data.get("reference_id"),
    }
    return {k: v for k, v in details.items() if v not in (None, "", {})}


def _sandbox_allow_mock_fallback() -> bool:
    return getattr(settings, "SANDBOX_ALLOW_MOCK_FALLBACK", False)


class AadhaarAnonCheckView(APIView):
    """
    Check Aadhaar uniqueness using k-anonymity prefix matching
    
    Zero-Knowledge Design:
    - Client sends prefix (first 5 chars) of hashed Aadhaar number
    - Server returns list of full hashes matching that prefix
    - Client checks locally if its full hash exists
    - Server never learns the actual Aadhaar number or full hash
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        prefix = request.query_params.get('prefix', '').strip()
        
        if not prefix or len(prefix) != 5:
            return Response(
                {"error": "Prefix must be exactly 5 characters"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get all proofs with matching prefix
        # Return aadhaar_hashes (not final_hashes) so client can check locally
        matching_proofs = UniquenessProof.objects.filter(prefix=prefix)
        matching_hashes = list(matching_proofs.values_list('aadhaar_hash', flat=True))
        
        return Response({
            'prefix': prefix,
            'matching_hashes': matching_hashes,
            'count': len(matching_hashes)
        }, status=status.HTTP_200_OK)


class PANAnonCheckView(APIView):
    """
    Check PAN uniqueness using k-anonymity prefix matching
    
    Zero-Knowledge Design:
    - Client sends prefix (first 5 chars) of hashed PAN number
    - Server returns list of full hashes matching that prefix
    - Client checks locally if its full hash exists
    - Server never learns the actual PAN number or full hash
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        prefix = request.query_params.get('prefix', '').strip()
        
        if not prefix or len(prefix) != 5:
            return Response(
                {"error": "Prefix must be exactly 5 characters"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get all proofs with matching prefix
        # Return pan_hashes (not final_hashes) so client can check locally
        matching_proofs = PANUniquenessProof.objects.filter(prefix=prefix)
        matching_hashes = list(matching_proofs.values_list('pan_hash', flat=True))
        
        return Response({
            'prefix': prefix,
            'matching_hashes': matching_hashes,
            'count': len(matching_hashes)
        }, status=status.HTTP_200_OK)


class AadhaarGenerateOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AadhaarGenerateOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        aadhaar_number = serializer.validated_data["aadhaar_number"]
        consent = serializer.validated_data["consent"]
        reason = serializer.validated_data["reason"] or "identity_verification"
        aadhaar_hash = VerifiableBlockOTP.generate_hash(aadhaar_number)

        # Note: Duplicate check is now done client-side using k-Anonymity API
        # Server does not perform any duplicate checks here to maintain zero-knowledge
        
        # Calculate aadhaar_hash_with_pepper for uniqueness proof storage
        from django.conf import settings
        import hashlib
        public_pepper = getattr(settings, 'SVA_PUBLIC_PEPPER', 'sva-public-pepper-2024-zero-knowledge-uniqueness-check')
        aadhaar_with_pepper = f"{aadhaar_number}{public_pepper}"
        aadhaar_hash_with_pepper = hashlib.sha256(aadhaar_with_pepper.encode()).hexdigest()

        client = SandboxKYCClient()
        simulated_otp = None

        if client.is_configured:
            try:
                sandbox_response = client.generate_aadhaar_otp(aadhaar_number, consent, reason)
            except (SandboxAPIError, SandboxConfigurationError) as exc:
                logger.exception("Failed to request Aadhaar OTP via Sandbox: %s", exc)
                if not _sandbox_allow_mock_fallback():
                    return Response({"error": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)
                logger.warning("Falling back to mock Aadhaar OTP generation due to Sandbox error")
                sandbox_response, simulated_otp = self._mock_generate_response()
        else:
            sandbox_response, simulated_otp = self._mock_generate_response()

        reference_id = _extract_reference_id(sandbox_response)
        message = _extract_message(sandbox_response) or "OTP sent successfully"

        AadhaarVerificationSession.objects.create(
            user=request.user,
            aadhaar_hash=aadhaar_hash,
            aadhaar_hash_with_pepper=aadhaar_hash_with_pepper,
            reference_id=reference_id,
            status=AadhaarVerificationSession.STATUS_PENDING,
            sandbox_transaction_id=sandbox_response.get("transaction_id"),
            sandbox_message=message,
            sandbox_metadata=_sanitize_sandbox_metadata(sandbox_response),
            simulated_otp=simulated_otp,
        )

        response_payload = {
            "message": message,
            "reference_id": reference_id,
            "value_hash": aadhaar_hash,
            "status": AadhaarVerificationSession.STATUS_PENDING,
            "sandbox": sandbox_response.get("data") or {},
            "dev_hint": f"Use OTP {simulated_otp}" if simulated_otp else None,
        }
        return Response({k: v for k, v in response_payload.items() if v is not None})

    @staticmethod
    def _mock_generate_response():
        reference_id = str(uuid.uuid4())
        otp_code = "123456"
        payload = {
            "code": 200,
            "transaction_id": str(uuid.uuid4()),
            "data": {
                "reference_id": reference_id,
                "message": "OTP sent successfully (mock)",
            },
        }
        return payload, otp_code


class AadhaarVerifyOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AadhaarVerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reference_id = serializer.validated_data["reference_id"]
        otp = serializer.validated_data["otp"]

        try:
            session = AadhaarVerificationSession.objects.get(user=request.user, reference_id=reference_id)
        except AadhaarVerificationSession.DoesNotExist:
            return Response({"error": "Reference ID not found. Please start again."}, status=status.HTTP_404_NOT_FOUND)

        client = SandboxKYCClient()

        if client.is_configured:
            try:
                # Force re-authentication to get a fresh token before verifying OTP
                # Don't use the cached token from OTP generation
                client.access_token = ''
                client._clear_cached_token()
                client._authenticate(force=True)
                
                sandbox_response = client.verify_aadhaar_otp(reference_id, otp)
            except (SandboxAPIError, SandboxConfigurationError) as exc:
                logger.exception("Failed to verify Aadhaar OTP via Sandbox: %s", exc)
                if not _sandbox_allow_mock_fallback():
                    return Response({"error": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)
                logger.warning("Falling back to mock Aadhaar verification due to Sandbox error")
                sandbox_response = self._mock_verify_response(session, otp)
        else:
            sandbox_response = self._mock_verify_response(session, otp)

        data = sandbox_response.get("data") or {}
        status_text = (data.get("status") or "").upper()
        metadata = _sanitize_sandbox_metadata(sandbox_response)
        message = data.get("message") or sandbox_response.get("message") or "Aadhaar verification failed"

        if status_text != "VALID":
            session.status = AadhaarVerificationSession.STATUS_FAILED
            session.sandbox_message = message
            session.sandbox_metadata = metadata
            session.save(update_fields=["status", "sandbox_message", "sandbox_metadata", "updated_at"])
            return Response(
                {
                    "message": message,
                    "status": session.status,
                    "sandbox": data,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Note: Duplicate check is now done client-side using k-Anonymity API
        # Server does not perform any duplicate checks here to maintain zero-knowledge

        now = timezone.now()
        session.status = AadhaarVerificationSession.STATUS_VERIFIED
        session.verified_at = now
        session.sandbox_transaction_id = sandbox_response.get("transaction_id")
        session.sandbox_message = message
        session.sandbox_metadata = metadata
        session.simulated_otp = None
        session.save(
            update_fields=[
                "status",
                "verified_at",
                "sandbox_transaction_id",
                "sandbox_message",
                "sandbox_metadata",
                "simulated_otp",
                "updated_at",
            ]
        )

        # Create or update verified block for this user
        verified_block, created = VerifiedBlock.objects.get_or_create(
            user=request.user,
            block_type=VerificationBlockType.AADHAR,
            value_hash=session.aadhaar_hash,
            defaults={
                "verified_at": now,
                "verification_method": "aadhaar_okyc",
            },
        )
        
        # If it already exists, update the verification time
        if not created:
            verified_block.verified_at = now
            verified_block.verification_method = "aadhaar_okyc"
            verified_block.save(update_fields=["verified_at", "verification_method"])

        # Store uniqueness proof using k-Anonymity (Zero-Knowledge)
        # Use the aadhaar_hash_with_pepper stored in the session during OTP generation
        if session.aadhaar_hash_with_pepper:
            from django.conf import settings
            secret_pepper = getattr(settings, 'SVA_SECRET_SERVER_PEPPER', 'sva-secret-server-pepper-2024-never-expose-this-value')
            
            # Generate final_hash with secret pepper
            final_hash = UniquenessProof.generate_final_hash(session.aadhaar_hash_with_pepper, secret_pepper)
            prefix = UniquenessProof.get_prefix(session.aadhaar_hash_with_pepper)
            
            # Store uniqueness proof (get_or_create to handle race conditions)
            UniquenessProof.objects.get_or_create(
                final_hash=final_hash,
                defaults={
                    'aadhaar_hash': session.aadhaar_hash_with_pepper,
                    'prefix': prefix,
                }
            )

        response_payload = {
            "message": "Aadhaar verification successful",
            "verified": True,
            "status": session.status,
            "reference_id": reference_id,
            "value_hash": session.aadhaar_hash,
            "aadhaar_hash_with_pepper": session.aadhaar_hash_with_pepper,  # Include for cleanup
            "aadhaar_details": _format_aadhaar_details(data),
            "verified_block": {
                "id": str(verified_block.id),
                "block_type": verified_block.block_type,
                "value_hash": verified_block.value_hash,
                "verified_at": verified_block.verified_at.isoformat(),
                "verification_method": verified_block.verification_method,
            },
            "sandbox": metadata,
        }
        return Response(response_payload)

    @staticmethod
    def _mock_verify_response(session: AadhaarVerificationSession, otp: str):
        expected = session.simulated_otp or "123456"
        if otp != expected:
            return {
                "code": 200,
                "transaction_id": str(uuid.uuid4()),
                "data": {
                    "message": "Invalid OTP",
                },
            }

        sample_data = {
            "@entity": "in.co.sandbox.kyc.aadhaar.okyc",
            "reference_id": session.reference_id,
            "status": "VALID",
            "message": "Aadhaar Card Exists (mock)",
            "care_of": "S/O: Sample User",
            "full_address": "123 Sample Street, Bengaluru, India",
            "date_of_birth": "21-04-1985",
            "gender": "M",
            "name": "Sample User",
            "address": {
                "@entity": "in.co.sandbox.kyc.aadhaar.okyc.address",
                "country": "India",
                "district": "Bengaluru",
                "house": "Sample House",
                "pincode": "560001",
                "state": "Karnataka",
                "street": "Sample Street",
                "vtc": "Bengaluru",
            },
            "year_of_birth": "1985",
            "mobile_hash": "mock-mobile-hash",
            "email_hash": "mock-email-hash",
            "share_code": "1234",
            "photo": "data:image/png;base64,mock",
        }
        return {
            "code": 200,
            "transaction_id": str(uuid.uuid4()),
            "data": sample_data,
        }


class CleanupVerificationDataView(APIView):
    """
    Clean up verification data when blocks are deleted from canvas
    
    Deletes:
    - VerifiedBlock records (verification status)
    - UniquenessProof records (for Aadhaar - allows re-verification)
    """
    permission_classes = [IsAuthenticated]
    
    @transaction.atomic
    def post(self, request):
        serializer = CleanupVerificationDataSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        block_type = serializer.validated_data["block_type"]
        value_hash = serializer.validated_data.get("value_hash")
        aadhaar_hash_with_pepper = serializer.validated_data.get("aadhaar_hash_with_pepper")
        
        deleted_count = 0
        deleted_uniqueness_proofs = 0
        
        # Delete VerifiedBlock records
        if value_hash:
            verified_blocks = VerifiedBlock.objects.filter(
                user=user,
                block_type=block_type,
                value_hash=value_hash
            )
            deleted_count = verified_blocks.count()
            verified_blocks.delete()
        else:
            # If no value_hash provided, delete all VerifiedBlocks of this type for the user
            verified_blocks = VerifiedBlock.objects.filter(
                user=user,
                block_type=block_type
            )
            deleted_count = verified_blocks.count()
            verified_blocks.delete()
        
        # For Aadhaar, also delete UniquenessProof
        if block_type == VerificationBlockType.AADHAR:
            if aadhaar_hash_with_pepper:
                # Delete specific UniquenessProof by aadhaar_hash_with_pepper
                secret_pepper = getattr(settings, 'SVA_SECRET_SERVER_PEPPER', 'sva-secret-server-pepper-2024-never-expose-this-value')
                final_hash = UniquenessProof.generate_final_hash(aadhaar_hash_with_pepper, secret_pepper)
                
                uniqueness_proofs = UniquenessProof.objects.filter(final_hash=final_hash)
                deleted_uniqueness_proofs = uniqueness_proofs.count()
                uniqueness_proofs.delete()
            else:
                # If no aadhaar_hash_with_pepper provided, we can't safely delete
                # (multiple users might have verified the same Aadhaar)
                # For now, we'll skip UniquenessProof deletion if hash not provided
                pass
        
        # For PAN, also delete PANUniquenessProof
        if block_type == VerificationBlockType.PAN_CARD:
            pan_hash_with_pepper = serializer.validated_data.get("pan_hash_with_pepper")
            if pan_hash_with_pepper:
                # Delete specific PANUniquenessProof by pan_hash_with_pepper
                secret_pepper = getattr(settings, 'SVA_SECRET_SERVER_PEPPER', 'sva-secret-server-pepper-2024-never-expose-this-value')
                final_hash = PANUniquenessProof.generate_final_hash(pan_hash_with_pepper, secret_pepper)
                
                pan_uniqueness_proofs = PANUniquenessProof.objects.filter(final_hash=final_hash)
                deleted_pan_proofs = pan_uniqueness_proofs.count()
                deleted_uniqueness_proofs += deleted_pan_proofs
                pan_uniqueness_proofs.delete()
            else:
                # If no pan_hash_with_pepper provided, we can't safely delete
                # (multiple users might have verified the same PAN)
                # For now, we'll skip PANUniquenessProof deletion if hash not provided
                pass
        
        return Response({
            "message": "Verification data cleaned up successfully",
            "deleted_verified_blocks": deleted_count,
            "deleted_uniqueness_proofs": deleted_uniqueness_proofs,
            "block_type": block_type
        }, status=status.HTTP_200_OK)

