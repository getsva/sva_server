import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class SandboxVerificationError(Exception):
    """Raised when Sandbox verification fails."""


@dataclass
class SandboxVerificationResult:
    status: str
    reference_id: Optional[str]
    raw_response: Dict[str, Any]
    message: Optional[str] = None


class SandboxVerificationClient:
    """
    Lightweight client for interacting with Sandbox KYC APIs.

    The real Sandbox API endpoints vary per product. Instead of locking ourselves
    to a specific contract, we allow the base endpoint to be configured via
    environment variables so we can plug in PAN, Aadhaar, GST, etc.
    """

    def __init__(self) -> None:
        self.base_url = getattr(settings, "SANDBOX_API_BASE_URL", "").rstrip("/")
        self.api_key = getattr(settings, "SANDBOX_API_KEY", "")
        self.timeout = getattr(settings, "SANDBOX_API_TIMEOUT", 30)

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _build_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def verify_document(
        self,
        document_type: str,
        document_identifier: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SandboxVerificationResult:
        """
        Submit a document verification request to Sandbox.

        Since Sandbox exposes multiple endpoints, we allow the path to be configured
        via SANDBOX_VERIFICATION_ENDPOINT. When the configuration is missing, we
        simulate a successful verification so development can continue without
        production credentials.
        """
        if not self.is_configured:
            logger.warning(
                "Sandbox API not configured; returning simulated verification result"
            )
            return SandboxVerificationResult(
                status="verified",
                reference_id=str(uuid.uuid4()),
                raw_response={
                    "simulated": True,
                    "document_type": document_type,
                    "document_identifier": document_identifier[-4:],
                },
                message="Sandbox API not configured. Verification auto-approved in development.",
            )

        endpoint = getattr(settings, "SANDBOX_VERIFICATION_ENDPOINT", "/kyc/verify")
        url = f"{self.base_url}{endpoint}"
        payload = {
            "document_type": document_type,
            "document_identifier": document_identifier,
            "metadata": metadata or {},
        }

        try:
            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.exception("Sandbox verification request failed")
            raise SandboxVerificationError("Failed to reach Sandbox API") from exc

        data = response.json()
        status = (data.get("status") or data.get("result") or "pending").lower()
        reference_id = (
            data.get("request_id")
            or data.get("reference_id")
            or data.get("transaction_id")
        )

        return SandboxVerificationResult(
            status=status,
            reference_id=reference_id,
            raw_response=data,
            message=data.get("message"),
        )


class SandboxVerificationService:
    """
    Thin service layer that orchestrates Sandbox verification calls.
    """

    SUCCESS_STATUSES = {"success", "verified", "completed"}
    PENDING_STATUSES = {"pending", "in_progress", "processing"}

    def __init__(self) -> None:
        self.client = SandboxVerificationClient()

    def verify_document(
        self,
        document_type: str,
        document_identifier: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SandboxVerificationResult:
        return self.client.verify_document(document_type, document_identifier, metadata)

    def is_verified(self, result: SandboxVerificationResult) -> bool:
        return result.status in self.SUCCESS_STATUSES

    def is_pending(self, result: SandboxVerificationResult) -> bool:
        return result.status in self.PENDING_STATUSES

