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


class DocumentVerificationVerifySerializer(serializers.Serializer):
    verification_id = serializers.UUIDField()
    verification_code = serializers.CharField(required=False, allow_blank=True, allow_null=True)


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

