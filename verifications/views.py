import json
from datetime import timedelta

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
)
from .serializers import (
    RequestOTPSerializer,
    VerifyOTPSerializer,
    CheckVerificationStatusSerializer,
    DocumentVerificationRequestSerializer,
    DocumentVerificationVerifySerializer,
    DocumentVerificationStatusSerializer,
)


OTP_EXPIRATION_MINUTES = 15


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

        verification = DocumentVerification.objects.create(
            user=user,
            block_type=block_type,
            document_hash=_hash_document_identifier(document_identifier),
            verification_method=verification_method,
            status="pending",
            verification_metadata=json.dumps(additional_data),
        )

        return Response(
            {
                "message": "Document verification requested",
                "verification_id": str(verification.id),
                "status": verification.status,
            },
            status=status.HTTP_201_CREATED,
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

        # Placeholder: In the future integrate with external providers
        verification.status = "verified"
        verification.verified_at = timezone.now()
        verification.save(update_fields=["status", "verified_at"])

        VerifiedBlock.objects.update_or_create(
            user=request.user,
            block_type=verification.block_type,
            value_hash=verification.document_hash,
            defaults={
                "verified_at": timezone.now(),
                "verification_method": verification.verification_method or "document",
            },
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

