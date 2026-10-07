"""Tests for the DNS enumeration module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.rdatatype
import dns.resolver
import pytest

from app.modules.base import ModuleInput
from app.modules.dns_enum import DNSEnumModule


@pytest.fixture
def module() -> DNSEnumModule:
    return DNSEnumModule()


def make_rdata(rtype: int, value: str, **extra: object) -> MagicMock:
    """Helper to create a mock rdata object."""
    rdata = MagicMock()
    rdata.to_text = MagicMock(return_value=value)
    if rtype == dns.rdatatype.A or rtype == dns.rdatatype.AAAA:
        # The module does `str(rdata.address)` — set __str__ so it returns `value`
        rdata.__str__ = MagicMock(return_value=value)
        rdata.address = value
    elif rtype in (dns.rdatatype.NS, dns.rdatatype.CNAME):
        rdata.target = value + "."
    elif rtype == dns.rdatatype.MX:
        rdata.preference = 10
        rdata.exchange = value
    elif rtype == dns.rdatatype.TXT:
        rdata.strings = [value.encode()]
    elif rtype == dns.rdatatype.SOA:
        rdata.mname = value
        rdata.rname = "admin.example.com."
        rdata.serial = 2024010101
        rdata.refresh = 7200
        rdata.retry = 1800
        rdata.expire = 1209600
        rdata.minimum = 3600
    elif rtype == dns.rdatatype.SRV:
        rdata.port = 443
        rdata.priority = 10
        rdata.weight = 5
        rdata.target = value
    for k, v in extra.items():
        setattr(rdata, k, v)
    return rdata


def make_answer(*rdatas: MagicMock) -> MagicMock:
    """Helper to create a mock Answer object (iterable)."""
    answer = MagicMock()
    # Make it iterable
    answer.__iter__ = lambda self: iter(rdatas)
    # Also make `len()` work and `__bool__` return True if there are records
    if rdatas:
        answer.__bool__ = lambda self: True
        answer.__len__ = lambda self: len(rdatas)
    return answer


def make_resolver_with(answers_by_rtype: dict[int, MagicMock]) -> MagicMock:
    """Build a mock resolver that returns specific answers per record type."""
    resolver = MagicMock()

    def _resolve(domain: str, rtype: int, **kwargs: object) -> MagicMock:
        if rtype in answers_by_rtype:
            return answers_by_rtype[rtype]
        # NoAnswer
        raise dns.resolver.NoAnswer

    resolver.resolve = MagicMock(side_effect=_resolve)
    return resolver


# ---- Happy paths ----

@pytest.mark.asyncio
async def test_a_record_queried(module: DNSEnumModule) -> None:
    """A records produce IP_ADDRESS findings."""
    resolver = make_resolver_with({
        dns.rdatatype.A: make_answer(make_rdata(dns.rdatatype.A, "93.184.216.34")),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    a_findings = [f for f in result.findings if f.source == "dns_a"]
    assert len(a_findings) == 1
    assert a_findings[0].value == "93.184.216.34"
    assert a_findings[0].type.value == "ip_address"
    assert a_findings[0].confidence == 0.95


@pytest.mark.asyncio
async def test_mx_record_queried(module: DNSEnumModule) -> None:
    """MX records produce findings with preference metadata."""
    mx_rdata = make_rdata(dns.rdatatype.MX, "mail.example.com")
    resolver = make_resolver_with({
        dns.rdatatype.MX: make_answer(mx_rdata),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    mx_findings = [f for f in result.findings if f.source == "dns_mx"]
    assert len(mx_findings) == 1
    assert "mail" in mx_findings[0].value
    assert mx_findings[0].finding_metadata["preference"] == 10


@pytest.mark.asyncio
async def test_txt_record_spf_classified(module: DNSEnumModule) -> None:
    """TXT records with SPF are tagged in metadata."""
    spf_rdata = make_rdata(
        dns.rdatatype.TXT, "v=spf1 include:_spf.example.com ~all"
    )
    resolver = make_resolver_with({
        dns.rdatatype.TXT: make_answer(spf_rdata),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    txt_findings = [f for f in result.findings if f.source == "dns_txt"]
    assert len(txt_findings) == 1
    assert "spf1" in txt_findings[0].value
    assert txt_findings[0].finding_metadata["type"] == "spf"


@pytest.mark.asyncio
async def test_txt_record_dmarc_classified(module: DNSEnumModule) -> None:
    """TXT records with DMARC are tagged in metadata."""
    dmarc_rdata = make_rdata(
        dns.rdatatype.TXT, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    )
    resolver = make_resolver_with({
        dns.rdatatype.TXT: make_answer(dmarc_rdata),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    txt_findings = [f for f in result.findings if f.source == "dns_txt"]
    assert txt_findings[0].finding_metadata["type"] == "dmarc"


@pytest.mark.asyncio
async def test_ns_records_queried(module: DNSEnumModule) -> None:
    """NS records produce findings."""
    ns_rdata = make_rdata(dns.rdatatype.NS, "ns1.example.com")
    resolver = make_resolver_with({
        dns.rdatatype.NS: make_answer(ns_rdata),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    ns_findings = [f for f in result.findings if f.source == "dns_ns"]
    assert len(ns_findings) == 1
    assert ns_findings[0].value == "ns1.example.com"


@pytest.mark.asyncio
async def test_multiple_a_records(module: DNSEnumModule) -> None:
    """Multiple A records produce multiple findings."""
    resolver = make_resolver_with({
        dns.rdatatype.A: make_answer(
            make_rdata(dns.rdatatype.A, "1.1.1.1"),
            make_rdata(dns.rdatatype.A, "2.2.2.2"),
            make_rdata(dns.rdatatype.A, "3.3.3.3"),
        ),
    })

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    a_findings = [f for f in result.findings if f.source == "dns_a"]
    assert len(a_findings) == 3
    assert {f.value for f in a_findings} == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}


# ---- Error handling ----

@pytest.mark.asyncio
async def test_nxdomain_aborts_early(module: DNSEnumModule) -> None:
    """NXDOMAIN stops further queries (domain doesn't exist)."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(
        side_effect=dns.resolver.NXDOMAIN("domain does not exist")
    )

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="nonexistent.example"))

    assert len(result.findings) == 0
    assert any("NXDOMAIN" in e for e in result.errors)


@pytest.mark.asyncio
async def test_timeout_aborts_remaining_record_types(module: DNSEnumModule) -> None:
    """Timeout on one record type aborts the remaining record queries (resilience fix)."""
    # A succeeds, then MX times out (loop breaks before TXT/CNAME/SOA/SRV/etc.)
    def _resolve(domain: str, rtype: int, **kwargs: object) -> MagicMock:
        if rtype == dns.rdatatype.A:
            return make_answer(make_rdata(dns.rdatatype.A, "1.2.3.4"))
        if rtype == dns.rdatatype.MX:
            raise dns.exception.Timeout
        raise dns.resolver.NoAnswer

    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=_resolve)

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    # A succeeded
    assert any(f.source == "dns_a" for f in result.findings)
    # MX timed out — loop broke before MX could be recorded
    assert not any(f.source == "dns_mx" for f in result.findings)
    # Timeout error recorded (dnspython formats it as "The DNS operation timed out")
    assert any("timeout" in e.lower() or "timed out" in e.lower() for e in result.errors)


# ---- AXFR ----

@pytest.mark.asyncio
async def test_axfr_refused_no_finding(module: DNSEnumModule) -> None:
    """If AXFR is refused (most common), no AXFR finding is produced."""
    # NS query succeeds, but AXFR raises
    ns_rdata = make_rdata(dns.rdatatype.NS, "ns1.example.com")

    def _resolve(domain: str, rtype: int, **kwargs: object) -> MagicMock:
        if rtype == dns.rdatatype.NS:
            return make_answer(ns_rdata)
        raise dns.resolver.NoAnswer

    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=_resolve)

    with patch.object(module, "_build_resolver", return_value=resolver):
        # _attempt_axfr uses dns.query.xfr + dns.zone.from_xfr, which would
        # raise in a real env. With mocks, we let it raise.
        with patch("dns.query.xfr", side_effect=Exception("AXFR refused")):
            result = await module.run(ModuleInput(target="example.com"))

    assert not any(f.source == "dns_axfr" for f in result.findings)


@pytest.mark.asyncio
async def test_axfr_succeeds_produces_high_severity_finding(module: DNSEnumModule) -> None:
    """Successful AXFR (rare) produces a HIGH-severity finding."""
    ns_rdata = make_rdata(dns.rdatatype.NS, "ns1.example.com")

    def _resolve(domain: str, rtype: int, **kwargs: object) -> MagicMock:
        if rtype == dns.rdatatype.NS:
            return make_answer(ns_rdata)
        raise dns.resolver.NoAnswer

    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=_resolve)

    # Mock a successful AXFR
    mock_zone = MagicMock()
    mock_zone.nodes = [MagicMock() for _ in range(42)]  # 42 records

    with patch.object(module, "_build_resolver", return_value=resolver):
        with patch("dns.query.xfr", return_value=MagicMock()):
            with patch("dns.zone.from_xfr", return_value=mock_zone):
                result = await module.run(ModuleInput(target="example.com"))

    axfr_findings = [f for f in result.findings if f.source == "dns_axfr"]
    assert len(axfr_findings) == 1
    assert axfr_findings[0].finding_metadata["event"] == "axfr_succeeded"
    assert axfr_findings[0].finding_metadata["records"] == 42
    assert axfr_findings[0].finding_metadata["severity"] == "HIGH"
    assert axfr_findings[0].confidence == 1.0


# ---- rdata formatting ----

def test_format_rdata_a(module: DNSEnumModule) -> None:
    """A record formatting."""
    rdata = make_rdata(dns.rdatatype.A, "1.2.3.4")
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.A, metadata)
    assert value == "1.2.3.4"
    assert metadata == {}


def test_format_rdata_aaaa(module: DNSEnumModule) -> None:
    """AAAA (IPv6) record formatting."""
    rdata = make_rdata(dns.rdatatype.AAAA, "2001:db8::1")
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.AAAA, metadata)
    assert value == "2001:db8::1"


def test_format_rdata_txt_spf(module: DNSEnumModule) -> None:
    """TXT record formatting tags SPF correctly."""
    rdata = make_rdata(dns.rdatatype.TXT, "v=spf1 -all")
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.TXT, metadata)
    assert "spf1" in value
    assert metadata["type"] == "spf"


def test_format_rdata_txt_dkim(module: DNSEnumModule) -> None:
    """TXT record formatting tags DKIM correctly."""
    rdata = make_rdata(
        dns.rdatatype.TXT,
        "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg",
    )
    metadata: dict = {}
    module._format_rdata(rdata, dns.rdatatype.TXT, metadata)
    assert metadata["type"] == "dkim"


def test_format_rdata_txt_long(module: DNSEnumModule) -> None:
    """Long TXT records (likely verification tokens) are tagged."""
    long_txt = "google-site-verification=abc123def456ghi789" + "x" * 30
    rdata = make_rdata(dns.rdatatype.TXT, long_txt)
    metadata: dict = {}
    module._format_rdata(rdata, dns.rdatatype.TXT, metadata)
    assert metadata["type"] == "verification"


def test_format_rdata_cname(module: DNSEnumModule) -> None:
    """CNAME record formatting."""
    rdata = make_rdata(dns.rdatatype.CNAME, "cdn.example.com")
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.CNAME, metadata)
    assert value == "cdn.example.com"


def test_format_rdata_srv(module: DNSEnumModule) -> None:
    """SRV record formatting extracts port + priority + weight."""
    rdata = make_rdata(dns.rdatatype.SRV, "sip.example.com")
    rdata.port = 5060
    rdata.priority = 10
    rdata.weight = 5
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.SRV, metadata)
    assert value == "sip.example.com"
    assert metadata["port"] == 5060
    assert metadata["priority"] == 10
    assert metadata["weight"] == 5


def test_format_rdata_fallback_to_text(module: DNSEnumModule) -> None:
    """Unknown rdatatype falls back to rdata.to_text()."""
    # Use a fake rdatatype value (not in our switch)
    rdata = MagicMock()
    rdata.to_text = MagicMock(return_value="custom-record-value")
    metadata: dict = {}
    value = module._format_rdata(rdata, 99999, metadata)
    assert value == "custom-record-value"


def test_format_rdata_handles_exception(module: DNSEnumModule) -> None:
    """If rdata formatting raises, log debug + return None."""
    rdata = MagicMock()
    # Make .address raise (so the A/AAAA branch fails)
    type(rdata).address = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.A, metadata)
    assert value is None


def test_format_rdata_soa(module: DNSEnumModule) -> None:
    """SOA record formatting extracts mname + serial + timing."""
    rdata = make_rdata(dns.rdatatype.SOA, "ns1.example.com")
    metadata: dict = {}
    value = module._format_rdata(rdata, dns.rdatatype.SOA, metadata)
    assert value == "ns1.example.com"
    assert metadata["mname"] == "ns1.example.com"
    assert metadata["serial"] == 2024010101


# ---- NoNameservers error path ----

@pytest.mark.asyncio
async def test_no_nameservers_aborts_remaining_record_types(module: DNSEnumModule) -> None:
    """When all resolvers fail, NoNameservers is recorded and the loop breaks early."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=dns.resolver.NoNameservers("all resolvers down"))

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    # One error recorded (the rest of the loop is short-circuited)
    assert len(result.errors) == 1
    assert "DNS query failed at" in result.errors[0]
    # No findings, but module didn't crash
    assert result.findings == []


@pytest.mark.asyncio
async def test_query_records_propagates_no_nameservers(module: DNSEnumModule) -> None:
    """NoNameservers in inner _query_records propagates and triggers early break."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=dns.resolver.NoNameservers("all down"))

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    # Exactly 1 error (loop broke after the first NoNameservers — audit fix)
    assert len(result.errors) == 1
    assert "DNS query failed at" in result.errors[0]


@pytest.mark.asyncio
async def test_axfr_initial_ns_query_fails(module: DNSEnumModule) -> None:
    """If the initial NS query for AXFR fails, AXFR returns empty (no error)."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer)

    with patch.object(module, "_build_resolver", return_value=resolver):
        result = await module.run(ModuleInput(target="example.com"))

    # No AXFR findings
    assert not any(f.source == "dns_axfr" for f in result.findings)
    # No AXFR-specific errors
    assert not any("AXFR" in e for e in result.errors)


@pytest.mark.asyncio
async def test_axfr_timeout_caught_silently(module: DNSEnumModule) -> None:
    """AXFR timeout is caught and not surfaced as an error."""
    # NS query succeeds
    ns_rdata = make_rdata(dns.rdatatype.NS, "ns1.example.com")

    def _resolve(domain: str, rtype: int, **kwargs: object) -> MagicMock:
        if rtype == dns.rdatatype.NS:
            return make_answer(ns_rdata)
        raise dns.resolver.NoAnswer

    resolver = MagicMock()
    resolver.resolve = MagicMock(side_effect=_resolve)

    with patch.object(module, "_build_resolver", return_value=resolver):
        with patch("asyncio.wait_for", side_effect=TimeoutError):
            result = await module.run(ModuleInput(target="example.com"))

    # No AXFR findings, no errors
    assert not any(f.source == "dns_axfr" for f in result.findings)
    assert not any("AXFR" in e for e in result.errors)


# ---- Metadata ----

def test_module_metadata(module: DNSEnumModule) -> None:
    """Module has the right Tier 1 metadata."""
    assert module.name == "dns_enum"
    assert module.tier.value == "tier_1"
    assert "T1590.002" in module.mitre_techniques
    assert module.enabled_by_default is True


# ---- Resolver config ----

def test_resolver_uses_public_servers(module: DNSEnumModule) -> None:
    """Resolver is configured with public DNS servers (no auth required)."""
    resolver = module._build_resolver()
    assert "8.8.8.8" in resolver.nameservers
    assert "1.1.1.1" in resolver.nameservers
    assert resolver.timeout > 0
    assert resolver.lifetime > 0


def test_ai_prompt_is_substantive(module: DNSEnumModule) -> None:
    """AI prompt has the required structure (covers missing line 303)."""
    prompt = module.get_ai_prompt()
    assert "DNS" in prompt
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "HIGH" in prompt
    assert "DMARC" in prompt  # should mention email security
    assert len(prompt) > 200
