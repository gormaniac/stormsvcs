"""Tests for parsing bgp.he.net's domain RDAP records."""

import datetime

import pytest

from bgphesvc import rdap, whois

from .fakebgphe import load


def ms(*args) -> int:
    return int(datetime.datetime(*args, tzinfo=datetime.UTC).timestamp() * 1000)


def card(*props):
    return ["vcard", [["version", {}, "text", "4.0"], *props]]


def test_rdap_matches_whois():
    # RDAP and whois text parse into the same fields.
    for name in ("microsoft.com", "vertex.link", "bbc.co.uk", "example.org"):
        rec = rdap.parseDomain(name, load(f"rdap_{name}.json"))
        assert rec.keys() == whois.parseDomain(name, "").keys()
        assert rec["registrar"].keys() == whois.parseDomain(name, "")["registrar"].keys()
        for contact in rec["contacts"]:
            assert contact.keys() == {
                "type", "id", "name", "orgname", "address", "city", "state", "postalcode",
                "country", "phone", "fax", "email",
            }


def test_rdap_microsoft():
    rec = rdap.parseDomain("microsoft.com", load("rdap_microsoft.com.json"))
    text = whois.parseDomain("microsoft.com", load("whois_microsoft.com.json")["data"])
    for key in ("created", "updated", "expires", "registrant", "status", "nameservers", "dnssec"):
        assert rec[key] == text[key], key
    assert rec["asof"] == ms(2026, 10, 31, 10, 42, 59)
    # The registry's name for the registrar, the registrar's own whois server.
    assert rec["registrar"] == {
        "name": "MarkMonitor Inc.",
        "url": None,
        "whois": "whois.markmonitor.com",
        "ianaid": "292",
        "email": "abusecomplaints@markmonitor.com",
        "phone": "+1.2086851750",
    }
    assert [c["type"] for c in rec["contacts"]] == ["registrant", "tech"]
    assert rec["contacts"][0] == {
        "type": "registrant",
        "id": None,
        "name": "Domain Administrator",
        "orgname": "Microsoft Corporation",
        "address": "One Microsoft Way",
        "city": "Redmond",
        "state": "WA",
        "postalcode": "98052",
        "country": "US",
        "phone": "+1.4258828080",
        "fax": "+1.4259367329",
        "email": "admin@domains.microsoft",
    }
    assert rec["emails"] == ["admin@domains.microsoft", "msnhst@microsoft.com"]


def test_rdap_registry_only():
    # .uk has no registrar record, and its registrant is redacted.
    rec = rdap.parseDomain("bbc.co.uk", load("rdap_bbc.co.uk.json"))
    assert rec["created"] == ms(1994, 12, 13, 3, 49, 48)
    assert rec["registrar"]["name"] == "British Broadcasting Corporation"
    assert rec["registrar"]["url"] == "https://www.bbc.co.uk/"
    assert rec["registrar"]["email"] == "nominet.admins@bbc.co.uk"
    assert rec["nameservers"][0] == "ddns0.bbc.co.uk"
    assert rec["contacts"] == [] and rec["registrant"] is None

    rec = rdap.parseDomain("example.org", load("rdap_example.org.json"))
    assert rec["dnssec"] == "signedDelegation"
    assert rec["registrar"]["ianaid"] == "376"


def test_rdap_records():
    with pytest.raises(rdap.BadRdap):
        rdap.records([])
    with pytest.raises(rdap.BadRdap):
        rdap.records("nope")
    with pytest.raises(rdap.BadRdap):
        rdap.records({"objectClassName": "entity"})
    # A bare object, and related records that aren't domains.
    primary, related = rdap.records({"ldhName": "x.com"})
    assert primary == {"ldhName": "x.com"} and related == []
    _, related = rdap.records([{}, [{"objectClassName": "entity"}, "nope", {"ldhName": "x.com"}]])
    assert related == [{"ldhName": "x.com"}]


def test_rdap_vcards():
    entity = {
        "roles": ["administrative", "billing"],
        "handle": "H1",
        "vcardArray": card(
            ["fn", {}, "text", "  "],
            ["org", {}, "text", "Org"],
            ["adr", {"label": "1 Main St\nTown"}, "text", ["", "", "", "", "", "", "United States"]],
            ["tel", {"type": ["fax"]}, "uri", "tel:+1.555"],
            ["tel", {"type": "voice"}, "uri", "tel:+1.444"],
            ["email", {}, "text", "REDACTED FOR PRIVACY"],
            ["email", {}, "text", "Real@Example.com"],
            ["url", {}, "uri", "example.com"],
            "bad",
            ["short"],
        ),
    }
    props = rdap.vcard(entity)
    assert rdap._url(props) == "http://example.com"
    info = rdap.contact(entity, "admin")
    assert info["name"] is None and info["orgname"] == "Org"
    assert info["address"] == "1 Main St Town"
    assert info["country"] is None
    assert info["phone"] == "+1.444" and info["fax"] == "+1.555"
    assert info["email"] == "real@example.com"
    assert info["id"] == "H1"

    # An entity with nothing but redactions isn't a contact.
    assert rdap.contact({"vcardArray": card(["fn", {}, "text", "REDACTED"])}, "tech") is None
    assert rdap.contact({"vcardArray": "nope"}, "tech") is None

    payload = [
        {
            "ldhName": "x.com",
            "status": ["active", 5],
            "secureDNS": {"delegationSigned": "maybe"},
            "events": ["nope", {"eventAction": "registration", "eventDate": "bad"}],
            "nameservers": [{"ldhName": "NS1.X.COM."}, "nope", {"ldhName": ""}],
            "entities": [entity, "nope", {"roles": "registrant"}],
        },
        None,
    ]
    rec = rdap.parseDomain("x.com", payload)
    assert rec["status"] == ["active"]
    assert rec["dnssec"] is None and rec["created"] is None
    assert rec["nameservers"] == ["ns1.x.com"]
    assert [c["type"] for c in rec["contacts"]] == ["admin", "billing"]
    assert rec["emails"] == ["real@example.com"]


def test_rdap_eppstatus():
    assert rdap.eppStatus("client delete prohibited") == "clientDeleteProhibited"
    assert rdap.eppStatus("pending-delete") == "pendingDelete"
    assert rdap.eppStatus("active") == "active"
