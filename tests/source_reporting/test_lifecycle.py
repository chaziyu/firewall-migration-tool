"""Unit tests for FortiGate and PAN-OS lifecycle & firmware evaluation."""

from __future__ import annotations

from datetime import date
import pytest

from fwmigrate.source_reporting import lifecycle


@pytest.fixture(autouse=True)
def _reset_cache():
    lifecycle.clear_lifecycle_cache()
    yield
    lifecycle.clear_lifecycle_cache()


def test_fortigate_model_normalization_and_serial_derivation():
    assert lifecycle.normalize_fortigate_model("FGT60F") == "FG-60F"
    assert lifecycle.normalize_fortigate_model("fg100e") == "FG-100E"
    assert lifecycle.normalize_fortigate_model("FGVM64") == "FG-VM"
    assert lifecycle.normalize_fortigate_model("FortiGate-200F") == "FG-200F"
    assert lifecycle.normalize_fortigate_model("Unknown") == ""

    assert lifecycle.derive_fortigate_model_from_serial("FGT60FTK21012345") == "FGT60F"
    assert lifecycle.derive_fortigate_model_from_serial("FGVM02TM21001234") == "FGVM02"
    assert lifecycle.derive_fortigate_model_from_serial("Unknown") == ""


def test_fortigate_variant_suffix_fallback_and_vm_handling():
    res_poe = lifecycle.evaluate_fortigate_lifecycle(
        "FG-60F-POE",
        "7.4.13",
        allow_online=False,
        today=date(2026, 11, 24),
    )
    assert res_poe["model_known"] is True
    assert res_poe["model_display"] == "FortiGate-60F"

    res_vm = lifecycle.evaluate_fortigate_lifecycle(
        "FGVM64",
        "7.4.13",
        allow_online=False,
        today=date(2026, 11, 24),
    )
    assert res_vm["is_vm"] is True
    assert res_vm["hw_status"] == "vm"
    assert res_vm["badge_text"] == "Lifecycle OK · Up to Date"
    assert res_vm["badge_variant"] == "allow"


def test_fortigate_badge_priority_order():
    today = date(2026, 11, 24)

    # Hardware EOS beats Branch EOS
    hw_eos = lifecycle.evaluate_fortigate_lifecycle(
        "FGT60D",
        "6.0.1",
        allow_online=False,
        today=today,
    )
    assert hw_eos["badge_text"] == "Hardware EOS"
    assert hw_eos["badge_variant"] == "deny"

    # Branch EOS beats Patch Available on active hardware
    branch_eos = lifecycle.evaluate_fortigate_lifecycle(
        "FGT60F",
        "7.2.1",
        allow_online=False,
        today=today,
    )
    assert branch_eos["badge_text"] == "Branch EOS"
    assert branch_eos["badge_variant"] == "deny"

    # Patch Available when branch is supported and newer patch exists
    patch_avail = lifecycle.evaluate_fortigate_lifecycle(
        "FGT60F",
        "7.4.1",
        allow_online=False,
        today=today,
    )
    assert patch_avail["badge_text"].startswith("Patch Available (")
    assert patch_avail["badge_variant"] == "warn"


def test_fortigate_serial_fallback_never_leaks_serial_in_card():
    res = lifecycle.evaluate_fortigate_lifecycle(
        None,
        "7.4.13",
        serial_raw="FGT60FTK99999999",
        allow_online=False,
        today=date(2026, 11, 24),
    )
    card = lifecycle.build_fortigate_lifecycle_card(res)
    assert res["model_canonical"] == "FG-60F"
    assert "FGT60FTK99999999" not in str(card)
    assert card["refresh_params"] == {
        "vendor": "fortigate",
        "model": "FG-60F",
        "firmware": "7.4.13",
    }


def test_panos_version_tuple_and_badge_priority():
    assert lifecycle._parse_panos_version_tuple("10.2.7") < lifecycle._parse_panos_version_tuple("10.2.7-h3")
    assert lifecycle._parse_panos_version_tuple("10.2.7-h3") < lifecycle._parse_panos_version_tuple("10.2.18-h15")

    today = date(2026, 11, 24)
    eol = lifecycle.evaluate_paloalto_lifecycle("10.2.7", allow_online=False, today=today)
    assert eol["badge_text"] == "Branch EOL"
    assert eol["badge_variant"] == "deny"

    patch_avail = lifecycle.evaluate_paloalto_lifecycle("11.1.4-h1", allow_online=False, today=today)
    assert patch_avail["badge_text"].startswith("Patch Available (")
    assert patch_avail["badge_variant"] == "warn"

    eol_soon = lifecycle.evaluate_paloalto_lifecycle("11.1.16-h6", allow_online=False, today=today)
    assert eol_soon["badge_text"] == "Branch EOL Soon"
    assert eol_soon["badge_variant"] == "warn"

    up_to_date = lifecycle.evaluate_paloalto_lifecycle("12.1.10-h6", allow_online=False, today=today)
    assert up_to_date["badge_text"] == "PAN-OS Up to Date"
    assert up_to_date["badge_variant"] == "allow"

    schema_only = lifecycle.evaluate_paloalto_lifecycle(
        "11.1.0",
        is_exact_version=False,
        allow_online=False,
        today=today,
    )
    card = lifecycle.build_paloalto_lifecycle_card(schema_only)
    assert "XML schema version" in card["rows"][0]["value"]
    assert card["refresh_params"]["exact"] is False


def test_cache_only_and_disable_online_checks(monkeypatch):
    called = []
    monkeypatch.setattr(lifecycle, "_fetch_endoflife_branches", lambda: called.append("eol") or {})
    monkeypatch.setattr(lifecycle, "_fetch_fortinet_rss_latest", lambda: called.append("rss") or {})
    monkeypatch.setattr(lifecycle, "_fetch_panos_endoflife_branches", lambda: called.append("pa") or {})

    # cache_only=True must not make HTTP calls when cache is cold, and sets needs_live_refresh=True
    fg_cold = lifecycle.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", cache_only=True)
    pa_cold = lifecycle.evaluate_paloalto_lifecycle("11.1.16-h6", cache_only=True)
    assert called == []
    assert fg_cold["needs_live_refresh"] is True
    assert pa_cold["needs_live_refresh"] is True

    # DISABLE_ONLINE_CHECKS=1 disables needs_live_refresh and outbound checks
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "1")
    fg_offline = lifecycle.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", cache_only=True)
    pa_offline = lifecycle.evaluate_paloalto_lifecycle("11.1.16-h6", cache_only=False)
    assert fg_offline["needs_live_refresh"] is False
    assert pa_offline["needs_live_refresh"] is False
    assert called == []


def test_live_refresh_warm_cache_and_failure_fallback(monkeypatch):
    calls = {"fg": 0, "rss": 0, "pa": 0}

    def fake_fg():
        calls["fg"] += 1
        return {"7.4": {"release_date": "2023-05-11", "eoes": "2027-05-11", "eos": "2028-11-11", "latest": "7.4.99"}}

    def fake_rss():
        calls["rss"] += 1
        return {"7.4": "7.4.99"}

    def fake_pa():
        calls["pa"] += 1
        return {"11.1": {"release_date": "2023-11-03", "eos": "2027-05-03", "latest": "11.1.99", "latest_date": "2026-11-24"}}

    monkeypatch.setattr(lifecycle, "_fetch_endoflife_branches", fake_fg)
    monkeypatch.setattr(lifecycle, "_fetch_fortinet_rss_latest", fake_rss)
    monkeypatch.setattr(lifecycle, "_fetch_panos_endoflife_branches", fake_pa)

    fg_live = lifecycle.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", cache_only=False)
    assert fg_live["latest_in_branch"] == "7.4.99"
    assert fg_live["source_label"] == "Live (endoflife.date + Fortinet RSS)"

    # Subsequent cache_only=True hits warm cache and does not request refresh
    fg_warm = lifecycle.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", cache_only=True)
    assert fg_warm["needs_live_refresh"] is False
    assert fg_warm["latest_in_branch"] == "7.4.99"
    assert calls["fg"] == 1 and calls["rss"] == 1

    # Network failure falls back gracefully to offline snapshot
    lifecycle.clear_lifecycle_cache()
    monkeypatch.setattr(lifecycle, "_fetch_panos_endoflife_branches", lambda: (_ for _ in ()).throw(OSError("offline")))
    pa_fallback = lifecycle.evaluate_paloalto_lifecycle("11.1.16-h6", cache_only=False)
    assert "Offline snapshot" in pa_fallback["source_label"]
    assert pa_fallback["latest_in_branch"] == "11.1.16-h6"


def test_excel_row_builders():
    fg_res = lifecycle.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", allow_online=False)
    fg_rows = dict(lifecycle.build_fortigate_lifecycle_excel_rows(fg_res))
    assert "Lifecycle Status" in fg_rows
    assert fg_rows["Hardware Model"] == "FortiGate-60F"
    assert "Offline snapshot" in fg_rows["Lifecycle Data Source"]

    pa_res = lifecycle.evaluate_paloalto_lifecycle("11.1.16-h6", allow_online=False)
    pa_rows = dict(lifecycle.build_paloalto_lifecycle_excel_rows(pa_res))
    assert "Lifecycle Status" in pa_rows
    assert "11.1.16-h6" in pa_rows["Current PAN-OS"]
    assert "Offline snapshot" in pa_rows["Lifecycle Data Source"]
