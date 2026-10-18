"""Optional built-app browser check for ASA, SRX and Check Point destination review."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile

from playwright.sync_api import expect, sync_playwright


CASES = (
    ("cisco_asa", "cisco-asa-migration-title", "single", "9.20", "routed",
     "! Empty reviewed configuration\n", "Cisco ASA command preview", "Download ASA configuration", "asa_config.cfg"),
    ("juniper_srx", "juniper-srx-migration-title", "root", "25.2R1", "standalone",
     "## Empty reviewed configuration\n", "Juniper SRX command preview", "Download Junos set file", "juniper_config.set"),
    ("checkpoint", "checkpoint-migration-title", "Default Domain", "1.8.1", "management",
     json.dumps({"format": "checkpoint-export-v1", "api_version": "1.8.1", "management_server": "browser-mgmt",
                 "domain": "Default Domain", "selected_domain": "Default Domain", "responses": []}),
     None, "Download Management requests", "checkpoint_management_operations.json"),
)


def run(url, chromium):
    source = Path(__file__).parents[1] / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"
    results = []
    with sync_playwright() as playwright, tempfile.TemporaryDirectory() as temporary:
        browser = playwright.chromium.launch(executable_path=chromium, args=["--no-sandbox"])
        for vendor, heading, context, version, mode, target, preview_label, download_label, filename in CASES:
            page = browser.new_page(viewport={"width": 390, "height": 844})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            page.get_by_role("button", name="Plan migration", exact=True).click()
            page.get_by_label("Target platform").select_option(f"fortigate_to_{vendor}")
            page.get_by_label("Drop your configuration here", exact=True).set_input_files(str(source))
            panel = page.locator(f'section[aria-labelledby="{heading}"]')
            expect(panel).to_be_visible()
            page.get_by_role("button", name="2. Target setup", exact=True).click()
            panel.get_by_label(re.compile(r"^(Source )?FortiGate VDOM")).select_option("root")
            if vendor != "checkpoint":
                labels = ("ASA context", "Cisco ASA syntax baseline", "ASA firewall mode") if vendor == "cisco_asa" else (
                    "Target context", "Junos version", "Target operating mode")
                for label, value in zip(labels, (context, version, mode)):
                    panel.get_by_label(label).select_option(value)
                panel.get_by_label("Target VLAN platform").select_option("asav" if vendor == "cisco_asa" else "vsrx")
                panel.get_by_label(re.compile(r"I verified VLAN capacity")).check()
                if vendor == "juniper_srx":
                    panel.get_by_label("Routing table").select_option("inet.0")
            else:
                panel.get_by_label("Management server label", exact=True).fill("browser-mgmt")
                panel.get_by_label("Management Domain", exact=True).fill(context)
            panel.get_by_label("Upload destination snapshot", exact=True).set_input_files(
                {"name": "reviewed-destination.txt", "mimeType": "text/plain", "buffer": target.encode()})
            snapshot = panel.get_by_role("region", name="Destination snapshot", exact=True)
            for field, value in (("context", context), ("version", version), ("mode", mode)):
                snapshot.get_by_label(f"Snapshot {field}", exact=True).fill(value)
            for checkbox in snapshot.get_by_role("checkbox").all():
                checkbox.check()
            with page.expect_response(lambda response: response.url.endswith("/design/prepare")) as prepared:
                panel.get_by_role("button", name="Prepare review" if vendor == "checkpoint" else "Prepare migration review", exact=True).click()
            assert prepared.value.status == 200, prepared.value.text()
            review = prepared.value.json()
            if vendor != "checkpoint":
                assert review["draft"]["options"]["vlan_interfaces_available"] is True
            assert review["report"]["destination_snapshot_compared"] is True
            assert review["report"]["coverage"]["source_record_count"] > 0
            coverage = panel.locator("details").filter(has=page.get_by_text(re.compile(r"^Source coverage")))
            coverage.locator("summary").first.click()
            expect(panel.get_by_role("table", name="Scoped source coverage")).to_be_visible()
            overflow = page.evaluate("""() => [...document.querySelectorAll('main *')]
                .filter(node => node.getBoundingClientRect().right > innerWidth && getComputedStyle(node).position !== 'absolute' && !node.closest('.report-table-wrap'))
                .slice(0, 12).map(node => ({tag: node.tagName, cls: node.className, text: node.textContent.slice(0, 100)}))""")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"{vendor}: {overflow}"
            if vendor == "checkpoint":
                panel.get_by_label("Check Point plan items").locator('input[type="checkbox"]:enabled').first.check()
                approve = panel.get_by_role("button", name="Approve selected items and build reviewed files", exact=True)
            else:
                panel.locator('table input[type="checkbox"]:enabled').first.check()
                panel.get_by_role("button", name="Review selected changes", exact=True).click()
                approve = panel.get_by_role("button", name="Approve these changes and build export", exact=True)
            with page.expect_response(lambda response: response.url.endswith("/build")) as built:
                approve.click()
            assert built.value.status == 200, built.value.text()
            artifact = built.value.json()["artifact"]
            if preview_label:
                expect(panel.get_by_label(preview_label)).to_have_value(artifact["command_text"])
                expected_bytes = artifact["command_text"].encode()
                digest = artifact["command_sha256"]
            else:
                expected_bytes = artifact["files"][filename]["content"].encode()
                expect(panel.locator(".migration-command-preview")).to_have_text(expected_bytes.decode())
                digest = artifact["file_sha256"][filename]
            with page.expect_download() as downloaded:
                panel.get_by_role("button", name=download_label, exact=True).click()
            command_path = Path(temporary) / filename
            downloaded.value.save_as(command_path)
            assert command_path.read_bytes() == expected_bytes
            assert hashlib.sha256(expected_bytes).hexdigest() == digest
            with page.expect_download() as bundled:
                panel.get_by_role("button", name="Download reviewed bundle" if vendor == "checkpoint" else "Download reviewed migration bundle", exact=True).click()
            bundle_path = Path(temporary) / f"{vendor}.zip"
            bundled.value.save_as(bundle_path)
            with zipfile.ZipFile(bundle_path) as bundle:
                assert bundle.read(filename) == expected_bytes
            assert not errors, errors
            results.append({"vendor": vendor, "flow": "PASS", "narrow_viewport": True, "sha256": digest})
            page.close()
        browser.close()
    print(json.dumps(results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5057")
    parser.add_argument("--chromium", required=True)
    arguments = parser.parse_args()
    run(arguments.url, arguments.chromium)
