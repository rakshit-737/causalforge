from causalforge.storage.health import ReadinessRegistry, StaticProbe


class FailingProbe:
    name = "required-dependency"
    required = True
    enabled = True

    def check(self) -> None:
        raise RuntimeError("connection string must not escape the health response")


def test_disabled_optional_probe_is_explicitly_skipped() -> None:
    report = ReadinessRegistry((StaticProbe(name="redis", detail="not_configured"),)).evaluate()

    assert report.status == "ready"
    assert report.checks[0].status == "skipped"


def test_required_probe_failure_makes_readiness_fail_without_raw_error() -> None:
    report = ReadinessRegistry((FailingProbe(),)).evaluate()

    assert report.status == "not_ready"
    assert report.checks[0].status == "error"
    assert report.checks[0].detail == "RuntimeError"
    assert "connection string" not in report.model_dump_json()
