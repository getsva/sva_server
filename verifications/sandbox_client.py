import logging
from typing import Any, Dict, Optional

import requests
from django.conf import settings
from requests import RequestException, Response

logger = logging.getLogger(__name__)


class SandboxConfigurationError(Exception):
    """Raised when Sandbox credentials are missing."""


class SandboxAPIError(Exception):
    """Raised when Sandbox responds with an error or cannot be reached."""


class SandboxKYCClient:
    """Lightweight wrapper around Sandbox KYC APIs used for Aadhaar OKYC."""

    _token_cache: Dict[str, str] = {}

    def __init__(self):
        self.base_url = (getattr(settings, 'SANDBOX_API_BASE_URL', '') or '').rstrip('/')
        self.api_key = getattr(settings, 'SANDBOX_API_KEY', '') or ''
        self.api_secret = getattr(settings, 'SANDBOX_API_SECRET', '') or ''
        self.api_version = getattr(settings, 'SANDBOX_API_VERSION', '') or ''
        self.timeout = getattr(settings, 'SANDBOX_API_TIMEOUT', 30)
        self.generate_endpoint = getattr(settings, 'SANDBOX_AADHAAR_GENERATE_ENDPOINT', '/kyc/aadhaar/okyc/otp')
        self.verify_endpoint = getattr(settings, 'SANDBOX_AADHAAR_VERIFY_ENDPOINT', '/kyc/aadhaar/okyc/otp/verify')
        self.auth_endpoint = getattr(settings, 'SANDBOX_AUTH_ENDPOINT', '/authenticate')

        # Static override (mainly for tests) or cached token from prior auth
        explicit_token = getattr(settings, 'SANDBOX_ACCESS_TOKEN', '') or ''
        self.access_token = explicit_token or self._get_cached_token()

    @property
    def is_configured(self) -> bool:
        has_token = bool(self.access_token)
        can_authenticate = bool(self.api_secret)
        return bool(self.base_url and self.api_key and (has_token or can_authenticate))

    def _cache_key(self) -> Optional[str]:
        if not (self.api_key and self.api_secret):
            return None
        return f"{self.api_key}:{self.api_secret}"

    def _get_cached_token(self) -> str:
        key = self._cache_key()
        if not key:
            return ''
        return self._token_cache.get(key, '')

    def _cache_token(self, token: str) -> None:
        key = self._cache_key()
        if not key:
            return
        self._token_cache[key] = token

    def _clear_cached_token(self) -> None:
        key = self._cache_key()
        if key and key in self._token_cache:
            self._token_cache.pop(key, None)

    def _build_url(self, endpoint: str) -> str:
        if not self.base_url:
            raise SandboxConfigurationError("Sandbox base URL is not configured")
        endpoint = endpoint or ''
        if endpoint.startswith('http'):
            return endpoint
        endpoint = endpoint if endpoint.startswith('/') else f'/{endpoint}'
        return f"{self.base_url}{endpoint}"

    def _ensure_access_token(self) -> str:
        if self.access_token:
            return self.access_token
        if not self.api_secret:
            raise SandboxConfigurationError(
                "Sandbox access token is not configured and API secret is unavailable for authentication."
            )
        token = self._authenticate(force=True)
        if not token:
            raise SandboxConfigurationError("Sandbox authentication failed to return an access token.")
        return token

    def _headers(self, api_version_override: Optional[str] = None) -> Dict[str, str]:
        if not self.api_key:
            raise SandboxConfigurationError("Sandbox API key is not configured")

        token = self._ensure_access_token()
        headers = {
            "Authorization": token,  # Sandbox API expects token directly, not "Bearer {token}"
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        # Use override version if provided, otherwise use default API version
        version = api_version_override or self.api_version
        if version:
            headers["x-api-version"] = str(version)
        return headers

    def _authenticate(self, force: bool = False) -> str:
        if not self.api_secret:
            return ''
        if self.access_token and not force:
            return self.access_token

        url = self._build_url(self.auth_endpoint)
        headers = {
            "x-api-key": self.api_key,
            "x-api-secret": self.api_secret,
        }
        if self.api_version:
            headers["x-api-version"] = str(self.api_version)

        try:
            response = requests.post(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except RequestException as exc:
            logger.error("Failed to authenticate with Sandbox %s: %s", url, exc)
            raise SandboxAPIError(str(exc)) from exc
        except ValueError as exc:
            logger.error("Sandbox authentication returned invalid JSON: %s", exc)
            raise SandboxAPIError("Invalid JSON response from Sandbox authentication") from exc

        token = (payload.get("data") or {}).get("access_token")
        if not token:
            raise SandboxAPIError("Sandbox authentication response missing access_token")

        self.access_token = token
        self._cache_token(token)
        return token

    def _post(self, endpoint: str, payload: Dict[str, Any], api_version_override: Optional[str] = None) -> Dict[str, Any]:
        url = self._build_url(endpoint)
        attempt = 0
        while attempt < 2:
            headers = self._headers(api_version_override=api_version_override)
            response: Optional[Response] = None
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                return response.json()
            except RequestException as exc:
                status_code = getattr(response, "status_code", None)
                if status_code in (401, 403) and self.api_secret and attempt == 0:
                    logger.warning("Sandbox token rejected (%s). Re-authenticating and retrying...", status_code)
                    self.access_token = ''
                    self._clear_cached_token()
                    self._authenticate(force=True)
                    attempt += 1
                    continue

                logger.error("Failed to call Sandbox API %s: %s", url, exc)
                raise SandboxAPIError(str(exc)) from exc
            except ValueError as exc:
                logger.error("Sandbox API returned a non-JSON response for %s: %s", url, exc)
                raise SandboxAPIError("Invalid JSON response from Sandbox") from exc
        raise SandboxAPIError("Sandbox API request failed after re-authentication attempt")

    def generate_aadhaar_otp(self, aadhaar_number: str, consent: str, reason: str) -> Dict[str, Any]:
        payload = {
            "@entity": "in.co.sandbox.kyc.aadhaar.okyc.otp.request",
            "aadhaar_number": aadhaar_number,
            "consent": consent,
            "reason": reason,
        }
        return self._post(self.generate_endpoint, payload)

    def verify_aadhaar_otp(self, reference_id: str, otp: str) -> Dict[str, Any]:
        payload = {
            "@entity": "in.co.sandbox.kyc.aadhaar.okyc.request",
            "reference_id": reference_id,
            "otp": otp,
        }
        # Verify endpoint requires API version 2.0 according to Sandbox documentation
        return self._post(self.verify_endpoint, payload, api_version_override="2.0")

    def verify_pan(self, pan: str, name_as_per_pan: str, date_of_birth: str, consent: str, reason: str) -> Dict[str, Any]:
        """
        Verify PAN details using Sandbox API.
        
        Args:
            pan: PAN number (10 characters)
            name_as_per_pan: Name as per PAN card
            date_of_birth: Date of birth in DD/MM/YYYY format
            consent: Consent value (typically "Y")
            reason: Reason for verification
        
        Returns:
            Response from Sandbox API
        """
        payload = {
            "@entity": "in.co.sandbox.kyc.pan_verification.request",
            "pan": pan,
            "name_as_per_pan": name_as_per_pan,
            "date_of_birth": date_of_birth,
            "consent": consent,
            "reason": reason,
        }
        pan_verify_endpoint = getattr(settings, 'SANDBOX_PAN_VERIFY_ENDPOINT', '/kyc/pan/verify')
        # PAN verification endpoint - no API version override needed based on Postman collection
        return self._post(pan_verify_endpoint, payload)


__all__ = [
    "SandboxKYCClient",
    "SandboxAPIError",
    "SandboxConfigurationError",
]

