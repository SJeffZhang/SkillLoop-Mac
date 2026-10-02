"""Consumption-time eligibility after independent API4 chain verification.

The caller authenticates the issuer, resolves the current deployment's frozen
bindings, and passes a trusted clock. This helper neither verifies a full chain
nor issues or renews a qualification.
"""
from datetime import datetime, timedelta, timezone
from skillloop.protocol import validate_envelope

BINDINGS = frozenset(('subject_digest', 'plan_digest', 'suite_digest',
                      'config_digest', 'issuer', 'trust_revision'))

def validate_consumption(attestation, *, verified_attestation_digest,
                         expected_bindings, now):
    validate_envelope(attestation)
    if attestation['kind'] != 'EvaluationAttestation':
        raise ValueError('consumption_attestation_kind')
    if attestation['digest'] != verified_attestation_digest:
        raise ValueError('consumption_unverified_attestation')
    if set(expected_bindings) != BINDINGS:
        raise ValueError('consumption_frozen_bindings_required')
    body = attestation['body']
    if any(body[k] != expected_bindings[k] for k in BINDINGS):
        raise ValueError('consumption_binding_mismatch')
    if body['verdict'] != 'pass':
        raise ValueError('consumption_not_pass')
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('consumption_trusted_clock_required')
    issued = datetime.fromisoformat(body['issued_at'].replace('Z', '+00:00'))
    expiry = datetime.fromisoformat(body['expires_at'].replace('Z', '+00:00'))
    if not timedelta(0) < expiry - issued <= timedelta(hours=24):
        raise ValueError('consumption_ttl_invalid')
    now = now.astimezone(timezone.utc)
    if now < issued:
        raise ValueError('consumption_not_yet_valid')
    if now >= expiry:
        raise ValueError('consumption_expired')
    return attestation
