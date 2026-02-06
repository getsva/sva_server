"""
Identity verification eligibility checks.

Determines whether a user is eligible to upgrade to a given identity level
based on VerifiedBlock (and DocumentVerification) and UserIdentityLevel state.
Levels must be completed in order: 0 -> 1 -> 2 -> 3.
"""

from django.utils import timezone

from .models import UserIdentityLevel
from identity_canvas.models import (
    DocumentVerification,
    VerificationBlockType,
    VerifiedBlock,
)

# Block type values (strings) that satisfy each level's requirements
LEVEL_1_BLOCK_TYPES = {VerificationBlockType.EMAIL, VerificationBlockType.PHONE}
GOVT_ID_BLOCK_TYPES = {
    VerificationBlockType.PAN_CARD,
    VerificationBlockType.AADHAR,
    VerificationBlockType.DRIVING_LICENSE,
    VerificationBlockType.VOTER_ID,
    VerificationBlockType.PASSPORT,
}
PROFESSIONAL_BLOCK_TYPES = {
    VerificationBlockType.PROFESSIONAL_LICENSE,
    VerificationBlockType.EDUCATION,
    VerificationBlockType.EMPLOYMENT,
}


def _as_string_set(block_types):
    """Normalize to set of strings for comparison with DB values."""
    return {bt if isinstance(bt, str) else bt.value for bt in block_types}


def _user_verified_block_types(user):
    """Return set of block_type values the user has verified (VerifiedBlock)."""
    return set(
        VerifiedBlock.objects.filter(user=user).values_list("block_type", flat=True)
    )


def _user_verified_document_types(user):
    """Return set of block_type values with verified DocumentVerification (status='verified')."""
    return set(
        DocumentVerification.objects.filter(
            user=user, status="verified"
        ).values_list("block_type", flat=True)
    )


def _has_level_1_requirements(user, identity_level):
    """
    Level 1: Email and phone verified.
    Uses VerifiedBlock first; falls back to identity_level timestamps for legacy.
    """
    verified_types = _user_verified_block_types(user)
    has_email = (VerificationBlockType.EMAIL.value in verified_types or
                 (identity_level and identity_level.email_verified_at))
    has_phone = (VerificationBlockType.PHONE.value in verified_types or
                 (identity_level and identity_level.phone_verified_at))
    return has_email and has_phone


def _has_level_2_requirements(user, identity_level):
    """
    Level 2: At least one government ID verified.
    Uses VerifiedBlock and DocumentVerification (verified status).
    """
    verified_blocks = _user_verified_block_types(user)
    verified_docs = _user_verified_document_types(user)
    combined = verified_blocks | verified_docs
    govt_set = _as_string_set(GOVT_ID_BLOCK_TYPES)
    has_govt_id = bool(combined & govt_set)
    # Legacy: timestamp set from previous verify-identity call
    has_legacy = bool(identity_level and identity_level.govt_id_verified_at)
    return has_govt_id or has_legacy


def _has_level_3_requirements(user, identity_level):
    """
    Level 3: At least one professional credential verified.
    """
    verified_types = _user_verified_block_types(user)
    prof_set = _as_string_set(PROFESSIONAL_BLOCK_TYPES)
    has_prof = bool(verified_types & prof_set)
    has_legacy = bool(identity_level and identity_level.professional_verified_at)
    return has_prof or has_legacy


def get_eligibility(user):
    """
    Compute identity verification eligibility for the user.

    Returns dict:
      - current_level: int (0-3)
      - next_eligible_level: int | None  (only current_level + 1 if requirements met)
      - requirements_met: { "1": bool, "2": bool, "3": bool }
      - requirements_detail: { "1": str, "2": str, "3": str }  (human-readable)
    """
    identity_level, _ = UserIdentityLevel.objects.get_or_create(user=user)
    current = identity_level.current_level

    req_1 = _has_level_1_requirements(user, identity_level)
    req_2 = _has_level_2_requirements(user, identity_level)
    req_3 = _has_level_3_requirements(user, identity_level)

    requirements_met = {"1": req_1, "2": req_2, "3": req_3}
    requirements_detail = {
        "1": "Email and phone verified"
        if req_1
        else "Verify your email and phone to unlock Level 1",
        "2": "Government ID verified"
        if req_2
        else "Verify a government ID (e.g. PAN, Aadhaar, Passport) to unlock Level 2",
        "3": "Professional credential verified"
        if req_3
        else "Verify a professional credential to unlock Level 3",
    }

    next_eligible_level = None
    if current < 3:
        next_level = current + 1
        if next_level == 1 and req_1:
            next_eligible_level = 1
        elif next_level == 2 and current >= 1 and req_2:
            next_eligible_level = 2
        elif next_level == 3 and current >= 2 and req_3:
            next_eligible_level = 3

    return {
        "current_level": current,
        "next_eligible_level": next_eligible_level,
        "requirements_met": requirements_met,
        "requirements_detail": requirements_detail,
    }


def can_upgrade_to_level(user, identity_level, requested_level):
    """
    Return (allowed: bool, error_message: str | None).
    """
    current = identity_level.current_level
    if requested_level <= current:
        return False, "Requested level must be higher than current level."
    if requested_level != current + 1:
        return False, "You can only upgrade to the next level (sequential verification)."
    if requested_level == 1:
        if not _has_level_1_requirements(user, identity_level):
            return False, "Complete email and phone verification first."
    elif requested_level == 2:
        if not _has_level_2_requirements(user, identity_level):
            return False, "Complete a government ID verification first."
    elif requested_level == 3:
        if not _has_level_3_requirements(user, identity_level):
            return False, "Complete a professional credential verification first."
    return True, None


def _compute_effective_level(user, identity_level):
    """
    Compute the highest identity level (0-3) the user currently qualifies for
    based on VerifiedBlock and DocumentVerification only (no manual upgrade).
    """
    if _has_level_1_requirements(user, identity_level):
        if _has_level_2_requirements(user, identity_level):
            if _has_level_3_requirements(user, identity_level):
                return 3
            return 2
        return 1
    return 0


def sync_identity_level_from_verifications(user, request=None):
    """
    Event-driven auto-upgrade (method 1): recompute identity level from
    VerifiedBlock and DocumentVerification and upgrade UserIdentityLevel if
    the user now qualifies for a higher level. Call this after any verification
    completes (OTP verify, document verify).

    Optional request: if provided, used for security log (ip_address, user_agent).
    Returns (upgraded: bool, new_level: int).
    """
    from .models import SecurityLog

    identity_level, _ = UserIdentityLevel.objects.get_or_create(user=user)
    effective = _compute_effective_level(user, identity_level)
    current = identity_level.current_level

    if effective <= current:
        return False, current

    now = timezone.now()
    if effective >= 1 and not identity_level.email_verified_at:
        identity_level.email_verified_at = now
        identity_level.phone_verified_at = now
    if effective >= 2 and not identity_level.govt_id_verified_at:
        identity_level.govt_id_verified_at = now
    if effective >= 3 and not identity_level.professional_verified_at:
        identity_level.professional_verified_at = now
    identity_level.current_level = effective
    identity_level.save()

    SecurityLog.objects.create(
        user=user,
        log_type="identity_upgrade",
        ip_address=request.META.get("REMOTE_ADDR") if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT") if request else None,
    )
    return True, effective
