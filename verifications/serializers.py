from rest_framework import serializers

from identity_canvas.models import VerificationBlockType, DocumentVerification


class RequestOTPSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices)
    value = serializers.CharField(max_length=512)
    delivery_method = serializers.ChoiceField(
        choices=[("email", "Email"), ("sms", "SMS")],
        required=False,
        allow_null=True,
        allow_blank=True,
    )
    frontend_url = serializers.CharField(required=False, allow_blank=True, allow_null=True)


class VerifyOTPSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices)
    value_hash = serializers.CharField(max_length=64)
    otp_code = serializers.CharField(min_length=4, max_length=6)

    def validate_value_hash(self, value):
        if len(value) != 64:
            raise serializers.ValidationError("value_hash must be a SHA-256 hex string.")
        return value.lower()


class CheckVerificationStatusSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices)
    value_hash = serializers.CharField(max_length=64)

    def validate_value_hash(self, value):
        if len(value) != 64:
            raise serializers.ValidationError("value_hash must be a SHA-256 hex string.")
        return value.lower()


class DocumentVerificationRequestSerializer(serializers.Serializer):
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices)
    document_identifier = serializers.CharField(max_length=512)
    verification_method = serializers.ChoiceField(
        choices=[
            ("manual_upload", "Manual Upload"),
            ("third_party", "Third Party API"),
            ("institutional", "Institutional Verification"),
        ]
    )
    additional_data = serializers.JSONField(required=False)


class PANDetailsSerializer(serializers.Serializer):
    """PAN details for verification - sent in request but NOT stored (zero-knowledge)"""
    pan_number = serializers.CharField(max_length=10)
    name_as_per_pan = serializers.CharField(max_length=255)
    date_of_birth = serializers.CharField(max_length=10)
    consent = serializers.CharField(max_length=1, default="Y")
    reason = serializers.CharField(max_length=255, required=False, default="identity_verification")


class DocumentVerificationVerifySerializer(serializers.Serializer):
    verification_id = serializers.UUIDField()
    verification_code = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    pan_details = PANDetailsSerializer(required=False, allow_null=True)


class DocumentVerificationStatusSerializer(serializers.Serializer):
    verification_id = serializers.UUIDField()


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
            "verification_metadata",
        ]
        read_only_fields = fields


class AadhaarGenerateOTPSerializer(serializers.Serializer):
    aadhaar_number = serializers.CharField(min_length=12, max_length=14)
    consent = serializers.ChoiceField(
        choices=[("Y", "Yes")],
        default="Y",
    )
    reason = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        default="identity_verification",
    )

    def validate_aadhaar_number(self, value):
        normalized = "".join(filter(str.isdigit, value or ""))
        if len(normalized) != 12:
            raise serializers.ValidationError("Aadhaar number must be a 12-digit value.")
        return normalized


class AadhaarVerifyOTPSerializer(serializers.Serializer):
    reference_id = serializers.CharField(max_length=128)
    otp = serializers.CharField(min_length=6, max_length=6)


class CleanupVerificationDataSerializer(serializers.Serializer):
    """
    Serializer for cleaning up verification data when blocks are deleted
    """
    block_type = serializers.ChoiceField(choices=VerificationBlockType.choices)
    value_hash = serializers.CharField(
        max_length=64,
        required=False,
        allow_null=True,
        help_text="SHA-256 hash of the value (for VerifiedBlock cleanup)"
    )
    aadhaar_hash_with_pepper = serializers.CharField(
        max_length=64,
        required=False,
        allow_null=True,
        help_text="SHA-256 hash of (Aadhaar + PUBLIC_PEPPER) for UniquenessProof cleanup"
    )
    pan_hash_with_pepper = serializers.CharField(
        max_length=64,
        required=False,
        allow_null=True,
        help_text="SHA-256 hash of (PAN + PUBLIC_PEPPER) for PANUniquenessProof cleanup"
    )

