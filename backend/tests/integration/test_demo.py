from scripts.demo import build_report


def test_offline_demo_is_deterministic_and_preserves_unknown_exfiltration() -> None:
    first = build_report()
    second = build_report()

    assert first == second
    assert "UNKNOWN / NOT ESTABLISHED" in first
    assert "No Kubernetes cluster" in first
    assert "Audit chain valid: **True**" in first
    assert "Detections: **1**" in first
