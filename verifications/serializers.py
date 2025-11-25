from rest_framework import serializers

from identity_canvas.models import (
    DocumentVerification,
    VerifiableBlockOTP,
    VerifiedBlock,
    VerificationBlockType,
)


class RequestOTPSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True,
        help_text="Type of block to verify (email, phone, etc.)",
    )
    value = serializers.CharField(
        required=True,
        help_text="Value to verify (email, phone, etc.) - will be hashed client-side ideally, but we receive it to send OTP",
    )

    def validate_block_type(self, value):
        if value not in [choice[0] for choice in VerificationBlockType.choices]:
            raise serializers.ValidationError(f"Unsupported block type: {value}")
        return value

    def validate_value(self, value):
        if not value or len(value.strip()) == 0:
            raise serializers.ValidationError("Value cannot be empty")
        return value.strip()


class VerifyOTPSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True,
        help_text="Type of block being verified",
    )
    value_hash = serializers.CharField(
        required=True,
        max_length=64,
        help_text="SHA-256 hash of the value being verified (zero-knowledge)",
    )
    otp_code = serializers.CharField(
        required=True,
        max_length=6,
        min_length=6,
        help_text="6-digit OTP code",
    )

    def validate_otp_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP code must be numeric")
        if len(value) != 6:
            raise serializers.ValidationError("OTP code must be 6 digits")
        return value

    def validate_value_hash(self, value):
        if len(value) != 64:
            raise serializers.ValidationError("Hash must be 64 characters (SHA-256)")
        return value


class CheckVerificationStatusSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices, required=True)
    value_hash = serializers.CharField(required=True, max_length=64)

    def validate_value_hash(self, value):
        if len(value) != 64:
            raise serializers.ValidationError("Hash must be 64 characters (SHA-256)")
        return value


class VerifiableBlockOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerifiableBlockOTP
        fields = [
            "id",
            "block_type",
            "expires_at",
            "is_verified",
            "attempts",
            "max_attempts",
            "created_at",
        ]
        read_only_fields = fields


class VerifiedBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerifiedBlock
        fields = [
            "id",
            "block_type",
            "value_hash",
            "verified_at",
            "verification_method",
        ]
        read_only_fields = fields


class DocumentVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentVerification
        fields = [
            "id",
            "block_type",
            "document_hash",
            "verification_method",
            "status",
            "created_at",
            "verified_at",
        ]
        read_only_fields = ["id", "created_at", "verified_at"]


class RequestDocumentVerificationSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(
        choices=VerificationBlockType.choices,
        required=True,
    )
    document_identifier = serializers.CharField(
        required=True,
        help_text="Document identifier (e.g., PAN number, license number) - will be hashed",
    )
    verification_method = serializers.ChoiceField(
        choices=DocumentVerification.VERIFICATION_METHOD_CHOICES,
        required=True,
    )
    additional_data = serializers.DictField(
        required=False,
        help_text="Additional data for verification",
    )

    def validate_block_type(self, value):
        otp_only_types = ["email", "phone"]
        if value in otp_only_types:
            raise serializers.ValidationError(
                f"{value} verification uses OTP method, not document verification"
            )
        return value


class VerifyDocumentSerializer(serializers.Serializer):
    verification_id = serializers.UUIDField(required=True)
    verification_code = serializers.CharField(
        required=False,
        help_text="Verification code if needed (e.g., from third-party callback)",
    )

