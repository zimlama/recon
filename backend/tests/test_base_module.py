"""Tests for BaseReconModule ABC contract + SSRF defense helpers."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, ModuleInput, ModuleOutput
from app.modules.whois_rdap import WhoisRDAPModule


class ConcreteTestModule(BaseReconModule):
    name = "concrete_test"
    description = "A test module"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 5

    async def run(self, input: ModuleInput) -> ModuleOutput:
        return ModuleOutput(
            module=self.name,
            findings=[Finding(type="ip_address", value="1.2.3.4", source="test")],
        )

    def get_ai_prompt(self) -> str:
        return "Test prompt"


class _AbstractAttempt(BaseReconModule):
    """Intentionally missing run() and get_ai_prompt() to test ABC."""
    name = "abstract"
    description = "Should not be instantiable"


def test_abstract_cannot_instantiate() -> None:
    """BaseReconModule cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseReconModule()  # type: ignore[abstract]


def test_abstract_subclass_cannot_instantiate() -> None:
    """Subclass missing abstract methods cannot be instantiated."""
    with pytest.raises(TypeError):
        _AbstractAttempt()


def test_concrete_module_instantiable() -> None:
    """Subclass with all methods can be instantiated."""
    m = ConcreteTestModule()
    assert m.name == "concrete_test"
    assert m.tier == ModuleTier.TIER_1


def test_module_without_name_raises() -> None:
    """Modules must set `name` class attribute."""

    class NamelessModule(BaseReconModule):
        description = "no name"
        tier = ModuleTier.TIER_1

        async def run(self, input: ModuleInput) -> ModuleOutput:
            return ModuleOutput(module="x")

        def get_ai_prompt(self) -> str:
            return "x"

    with pytest.raises(ValueError, match="must set `name`"):
        NamelessModule()


def test_module_without_description_raises() -> None:
    """Modules must set `description` class attribute."""

    class DescriptionlessModule(BaseReconModule):
        name = "x"
        tier = ModuleTier.TIER_1

        async def run(self, input: ModuleInput) -> ModuleOutput:
            return ModuleOutput(module="x")

        def get_ai_prompt(self) -> str:
            return "x"

    with pytest.raises(ValueError, match="must set `description`"):
        DescriptionlessModule()


def test_whois_rdap_module_is_concrete() -> None:
    """WhoisRDAPModule is properly implemented."""
    m = WhoisRDAPModule()
    assert m.name == "whois_rdap"
    assert m.tier == ModuleTier.TIER_1
    assert "T1596.002" in m.mitre_techniques
    assert m.enabled_by_default is True


def test_target_format_validation() -> None:
    """target validation strips and lowercases."""
    m = WhoisRDAPModule()
    assert m.validate_target_format("EXAMPLE.COM") == "example.com"
    with pytest.raises(ValueError):
        m.validate_target_format("")


def test_module_repr() -> None:
    """Module __repr__ is informative."""
    m = WhoisRDAPModule()
    r = repr(m)
    assert "WhoisRDAPModule" in r
    assert "whois_rdap" in r
    assert "tier_1" in r


# ---- SSRF defense helpers (safe_http_get / safe_http_get_async) ----

class _SSRFProbe(ConcreteTestModule):
    """Concrete subclass exposing the async SSRF helper for tests."""

    async def probe(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        return await self.safe_http_get_async(url, **kwargs)


@pytest.fixture
def ssrf_probe() -> _SSRFProbe:
    return _SSRFProbe()


def test_safe_http_get_returns_response_on_200() -> None:
    """safe_http_get returns the httpx.Response on success."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/safe").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        resp = BaseReconModule.safe_http_get("https://example.com/safe")
    assert resp is not None
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_safe_http_get_returns_response_on_404() -> None:
    """safe_http_get returns the response even on 4xx (not None — caller decides)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/missing").mock(
            return_value=httpx.Response(404)
        )
        resp = BaseReconModule.safe_http_get("https://example.com/missing")
    assert resp is not None
    assert resp.status_code == 404


def test_safe_http_get_returns_none_on_timeout() -> None:
    """safe_http_get swallows timeouts (httpx.TimeoutException is httpx.HTTPError)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/slow").mock(
            side_effect=httpx.ConnectTimeout("timed out")
        )
        resp = BaseReconModule.safe_http_get(
            "https://example.com/slow", timeout=1.0
        )
    assert resp is None


def test_safe_http_get_returns_none_on_connect_error() -> None:
    """safe_http_get swallows httpx.ConnectError (DNS, refused, unreachable)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/down").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        resp = BaseReconModule.safe_http_get("https://example.com/down")
    assert resp is None


def test_safe_http_get_passes_headers() -> None:
    """safe_http_get forwards custom headers to httpx."""
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200)

    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/headers").mock(side_effect=_capture)
        resp = BaseReconModule.safe_http_get(
            "https://example.com/headers",
            headers={"X-Test-Header": "ssrf-defense"},
        )
    assert resp is not None
    assert captured.get("x-test-header") == "ssrf-defense"


def test_safe_http_get_does_not_follow_redirects() -> None:
    """safe_http_get does NOT follow redirects (SSRF pivot defense).

    A redirect from an allowed URL to a private/internal URL must NOT
    be auto-followed; the caller receives the 3xx response and can
    decide to reject it.
    """
    with respx.mock(assert_all_called=False) as mock_router:
        # Server returns a redirect to localhost (RFC 1918 / loopback).
        mock_router.get("https://example.com/redirect").mock(
            return_value=httpx.Response(
                302, headers={"Location": "http://127.0.0.1:8080/admin"}
            )
        )
        resp = BaseReconModule.safe_http_get("https://example.com/redirect")
    assert resp is not None
    # Stopped at the redirect; never reached the loopback target.
    assert resp.status_code == 302
    assert resp.headers.get("location") == "http://127.0.0.1:8080/admin"


@pytest.mark.asyncio
async def test_safe_http_get_async_returns_response_on_200(
    ssrf_probe: _SSRFProbe,
) -> None:
    """safe_http_get_async returns the httpx.Response on success."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/async").mock(
            return_value=httpx.Response(200, content=b"hello")
        )
        resp = await ssrf_probe.probe("https://example.com/async")
    assert resp is not None
    assert resp.status_code == 200
    assert resp.content == b"hello"


@pytest.mark.asyncio
async def test_safe_http_get_async_returns_none_on_error(
    ssrf_probe: _SSRFProbe,
) -> None:
    """safe_http_get_async swallows httpx.HTTPError (timeout, connect, etc.)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/boom").mock(
            side_effect=httpx.ReadTimeout("read failed")
        )
        resp = await ssrf_probe.probe("https://example.com/boom", timeout=1.0)
    assert resp is None


@pytest.mark.asyncio
async def test_safe_http_get_async_does_not_follow_redirects(
    ssrf_probe: _SSRFProbe,
) -> None:
    """safe_http_get_async does NOT follow redirects (SSRF pivot defense)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://example.com/redir").mock(
            return_value=httpx.Response(
                301, headers={"Location": "http://10.0.0.1/internal"}
            )
        )
        resp = await ssrf_probe.probe("https://example.com/redir")
    assert resp is not None
    assert resp.status_code == 301
    assert resp.headers.get("location") == "http://10.0.0.1/internal"


def test_safe_http_get_is_static() -> None:
    """safe_http_get is a @staticmethod — callable on the class itself."""
    # If it weren't static, this would require an instance.
    assert isinstance(
        BaseReconModule.__dict__["safe_http_get"], staticmethod
    )


def test_safe_http_get_async_is_instance_method() -> None:
    """safe_http_get_async is an instance method (uses self)."""
    # It must be on the class but not a staticmethod.
    fn = BaseReconModule.__dict__["safe_http_get_async"]
    assert not isinstance(fn, staticmethod)
