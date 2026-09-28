from causalforge.observability.logging import redact_log_text


def test_log_redaction_masks_common_credential_shapes() -> None:
    message = "token=abc123 password:super-secret authorization=Bearer.secret"

    redacted = redact_log_text(message)

    assert "abc123" not in redacted
    assert "super-secret" not in redacted
    assert "Bearer.secret" not in redacted
    assert redacted.count("[REDACTED]") == 3
