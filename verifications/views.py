import json
from datetime import timedelta

from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from identity_canvas.models import (
    DocumentVerification,
    VerifiableBlockOTP,
    VerifiedBlock,
    VerificationBlockType,
)
from verifications.serializers import (
    CheckVerificationStatusSerializer,
    DocumentVerificationSerializer,
    RequestDocumentVerificationSerializer,
    RequestOTPSerializer,
    VerifyDocumentSerializer,
    VerifiedBlockSerializer,
    VerifyOTPSerializer,
)
from verifications.services import SandboxVerificationService


sandbox_service = SandboxVerificationService()


class RequestOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        block_type = serializer.validated_data["block_type"]
        value = serializer.validated_data["value"]

        value_hash = VerifiableBlockOTP.generate_hash(value)

        if VerifiedBlock.objects.filter(
            user=user, block_type=block_type, value_hash=value_hash
        ).exists():
            return Response(
                {"error": f"{block_type} is already verified"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        VerifiableBlockOTP.objects.filter(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            is_verified=False,
        ).delete()

        otp_code = VerifiableBlockOTP.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=15)

        otp_record = VerifiableBlockOTP.objects.create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            otp_code=otp_code,
            expires_at=expires_at,
        )

        otp_sent = False
        if block_type == VerificationBlockType.EMAIL:
            from authentication.email_service import send_otp_email

            otp_sent = send_otp_email(value, otp_code)
        elif block_type == VerificationBlockType.PHONE:
            from authentication.email_service import send_otp_sms

            otp_sent = send_otp_sms(value, otp_code)

        if not otp_sent:
            otp_record.delete()
            return Response(
                {"error": f"Failed to send OTP to {block_type}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "message": f"OTP sent to {block_type}",
                "otp_id": str(otp_record.id),
                "expires_at": otp_record.expires_at,
                "value_hash": value_hash,
            },
            status=status.HTTP_201_CREATED,
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

        try:
            otp_record = VerifiableBlockOTP.objects.get(
                user=user,
                block_type=block_type,
                value_hash=value_hash,
                is_verified=False,
            )
        except VerifiableBlockOTP.DoesNotExist:
            return Response(
                {"error": "Invalid OTP request. Please request a new OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not otp_record.is_valid:
            if otp_record.is_expired:
                return Response(
                    {"error": "OTP has expired. Please request a new OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if otp_record.attempts >= otp_record.max_attempts:
                return Response(
                    {"error": "Maximum verification attempts exceeded. Please request a new OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        otp_record.attempts += 1
        otp_record.save()

        if otp_record.otp_code != otp_code:
            return Response(
                {
                    "error": "Invalid OTP code",
                    "attempts_remaining": otp_record.max_attempts - otp_record.attempts,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp_record.is_verified = True
        otp_record.verified_at = timezone.now()
        otp_record.save()

        verified_block, created = VerifiedBlock.objects.get_or_create(
            user=user,
            block_type=block_type,
            value_hash=value_hash,
            defaults={"verification_method": "otp"},
        )

        if not created:
            verified_block.verified_at = timezone.now()
            verified_block.save()

        return Response(
            {
                "message": f"{block_type} verified successfully",
                "verified": True,
                "verified_block": VerifiedBlockSerializer(verified_block).data,
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
            user=user, block_type=block_type, value_hash=value_hash
        ).first()

        is_verified = verified_block is not None
        response_data = {
            "block_type": block_type,
            "value_hash": value_hash,
            "is_verified": is_verified,
        }

        if is_verified:
            response_data["verified_at"] = verified_block.verified_at
            response_data["verification_method"] = verified_block.verification_method

        return Response(response_data, status=status.HTTP_200_OK)


class GetVerifiedBlocksView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        verified_blocks = VerifiedBlock.objects.filter(user=request.user)
        serializer = VerifiedBlockSerializer(verified_blocks, many=True)
        return Response(
            {"verified_blocks": serializer.data, "count": len(serializer.data)},
            status=status.HTTP_200_OK,
        )


class RequestDocumentVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        serializer = RequestDocumentVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        block_type = serializer.validated_data["block_type"]
        document_identifier = serializer.validated_data["document_identifier"]
        verification_method = serializer.validated_data["verification_method"]
        additional_data = serializer.validated_data.get("additional_data", {})

        document_hash = VerifiableBlockOTP.generate_hash(document_identifier)

        if VerifiedBlock.objects.filter(
            user=user, block_type=block_type, value_hash=document_hash
        ).exists():
            return Response(
                {
                    "error": f"{block_type} is already verified",
                    "verification_id": None,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        verification, _ = DocumentVerification.objects.get_or_create(
            user=user,
            block_type=block_type,
            document_hash=document_hash,
            defaults={
                "verification_method": verification_method,
                "status": "pending",
            },
        )

        verification.verification_metadata = json.dumps(additional_data or {})
        verification.status = "pending"
        verification.save()

        # Handle Sandbox integration for third-party verifications
        if verification_method == "third_party":
            result = sandbox_service.verify_document(
                document_type=block_type,
                document_identifier=document_identifier,
                metadata=additional_data,
            )

            verification.verification_metadata = json.dumps(result.raw_response)

            if sandbox_service.is_verified(result):
                verification.status = "verified"
                verification.verified_at = timezone.now()
                verification.save()

                verified_block, created = VerifiedBlock.objects.get_or_create(
                    user=user,
                    block_type=block_type,
                    value_hash=document_hash,
                    defaults={"verification_method": "third_party"},
                )

                if not created:
                    verified_block.verified_at = timezone.now()
                    verified_block.verification_method = "third_party"
                    verified_block.save()

                return Response(
                    {
                        "message": f"{block_type} verified successfully",
                        "verification_id": str(verification.id),
                        "status": verification.status,
                        "provider_reference": result.reference_id,
                    },
                    status=status.HTTP_201_CREATED,
                )

            if sandbox_service.is_pending(result):
                verification.status = "pending"
                verification.save()
                return Response(
                    {
                        "message": f"{block_type} verification pending",
                        "verification_id": str(verification.id),
                        "status": verification.status,
                        "provider_reference": result.reference_id,
                        "note": result.message
                        or "Sandbox is processing this verification. Check back later.",
                    },
                    status=status.HTTP_202_ACCEPTED,
                )

            verification.status = "rejected"
            verification.save()
            return Response(
                {
                    "error": f"{block_type} verification rejected",
                    "verification_id": str(verification.id),
                    "status": verification.status,
                    "provider_reference": result.reference_id,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Manual upload / institutional flows
        if verification_method == "institutional":
            message = "Verification will be processed through institutional verification"
        else:
            message = "Document verification request created. Awaiting manual review."

        return Response(
            {
                "message": message,
                "verification_id": str(verification.id),
                "status": verification.status,
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyDocumentView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        serializer = VerifyDocumentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        verification_id = serializer.validated_data["verification_id"]

        try:
            verification = DocumentVerification.objects.get(
                id=verification_id,
                user=user,
            )
        except DocumentVerification.DoesNotExist:
            return Response(
                {"error": "Verification request not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if verification.status == "verified":
            return Response(
                {
                    "error": "Document already verified",
                    "verified_at": verification.verified_at,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        verification.status = "verified"
        verification.verified_at = timezone.now()
        verification.save()

        verified_block, created = VerifiedBlock.objects.get_or_create(
            user=user,
            block_type=verification.block_type,
            value_hash=verification.document_hash,
            defaults={"verification_method": verification.verification_method},
        )

        if not created:
            verified_block.verified_at = timezone.now()
            verified_block.verification_method = verification.verification_method
            verified_block.save()

        return Response(
            {
                "message": f"{verification.block_type} verified successfully",
                "verified": True,
                "verified_at": verification.verified_at,
                "verified_block": VerifiedBlockSerializer(verified_block).data,
            },
            status=status.HTTP_200_OK,
        )


class GetDocumentVerificationStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, verification_id):
        try:
            verification = DocumentVerification.objects.get(
                id=verification_id,
                user=request.user,
            )
        except DocumentVerification.DoesNotExist:
            return Response(
                {"error": "Verification request not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = DocumentVerificationSerializer(verification)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetDocumentVerificationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        verifications = DocumentVerification.objects.filter(user=request.user)
        serializer = DocumentVerificationSerializer(verifications, many=True)
        return Response(
            {"verifications": serializer.data, "count": len(serializer.data)},
            status=status.HTTP_200_OK,
        )

