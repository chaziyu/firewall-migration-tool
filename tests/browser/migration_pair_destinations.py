"""Built-app acceptance for all eight offline migration pairs (no device connections)."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile

from playwright.sync_api import expect, sync_playwright


PAIRS = (
    "fortigate_to_cisco_asa", "fortigate_to_juniper_srx", "fortigate_to_checkpoint",
    "palo_alto_to_fortigate", "palo_alto_to_juniper_srx", "palo_alto_to_cisco_asa",
    "palo_alto_to_checkpoint", "palo_alto_to_cisco_ftd",
)


def run(url, chromium, large_source=None, large_only=False):
    fixtures = Path(__file__).parents[1] / "fixtures"
    results = []
    with sync_playwright() as playwright, tempfile.TemporaryDirectory() as temporary:
        browser = playwright.chromium.launch(executable_path=chromium, args=["--no-sandbox"])
        cases = [] if large_only else [(pair, width, None) for pair in PAIRS for width in (390, 1440)]
        if large_source:
            cases.extend((pair, 390, Path(large_source)) for pair in PAIRS[:2])
        for pair, width, custom_source in cases:
            print(f"Checking {pair} at {width}px", flush=True)
            page = browser.new_page(viewport={"width": width, "height": 900})
            errors, reviews, approvals, artifacts = [], [], [], []
            page.on("pageerror", lambda error: errors.append(str(error)))

            if custom_source:
                # Capture real large responses before forwarding them unchanged; the inspector can evict their bodies.
                def capture_large_response(route):
                    response = route.fetch(timeout=120000)
                    if response.ok:
                        records = reviews if route.request.url.endswith("/design/prepare") else artifacts
                        records[:] = [response.json()]
                    route.fulfill(response=response)

                page.route("**/api/migration/*/design/prepare", capture_large_response)
                page.route("**/api/migration/*/build", capture_large_response)

            def response_received(response):
                if response.request.method == "POST" and response.ok:
                    if response.url.endswith("/design/prepare") and not custom_source:
                        reviews[:] = [response.json()]
                    elif response.url.endswith("/design/approve"):
                        approvals.append(response.request.post_data_json)

            page.on("response", response_received)
            page.on("response", lambda response: print(f"HTTP {response.status}: {response.url}", flush=True) if response.status >= 400 else None)
            page.goto(url)
            page.get_by_role("button", name="Plan migration", exact=True).click()
            vendor = "fortigate" if pair.startswith("fortigate") else "palo_alto"
            page.get_by_label("Source vendor").select_option(vendor)
            page.get_by_label("Target platform").select_option(pair)
            source = custom_source or (fixtures / "fortigate/multi_vendor_explicit.conf" if vendor == "fortigate"
                                       else fixtures / "palo_alto/all_targets_explicit.xml")
            page.get_by_label("Drop your configuration here", exact=True).set_input_files(str(source))
            confirm = page.get_by_role("button", name="Approve and generate", exact=True)
            expect(confirm).to_be_enabled(timeout=120000)
            nav = page.get_by_role("navigation", name="Migration workspace", exact=True)
            expect(nav.get_by_role("button")).to_have_count(3)
            expect(nav.get_by_role("button", name="2. Review conversion", exact=True)).to_have_attribute("aria-current", "step")
            assert not approvals, "Proposals must not approve automatically"
            assert reviews
            review = reviews[-1]
            rows = review["draft"].get("configuration", review["report"].get("items", []))
            eligible = [row for row in rows if row.get("render_disposition") in {"CREATE", "REUSE"}
                        and not row.get("blockers", row.get("blocking_reasons", []))]
            depended_on = {key for row in eligible for key in row["dependencies"]}
            leaf = next((row for row in reversed(eligible) if row["key"] not in depended_on), None)
            if leaf and len(eligible) > 1:
                # Find the row through the shared search, including items beyond the first page.
                page.get_by_label("Find a configuration item", exact=True).fill(leaf["source_name"])
                checkbox = page.get_by_role("checkbox", name=f"Select {leaf.get('source_vdom', leaf.get('source_scope'))} {leaf['source_name']}", exact=True)
                if checkbox.count() == 1:
                    checkbox.uncheck()
                    page.get_by_label("Find a configuration item", exact=True).fill("")
                else:
                    leaf = None
            else:
                leaf = None
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), pair
            with page.expect_response(lambda response: response.url.endswith("/build"), timeout=120000) as built:
                confirm.click()
            assert built.value.ok, built.value.text()
            artifact = (artifacts[-1] if custom_source else built.value.json())["artifact"]
            assert len(approvals) == 1
            if leaf:
                assert leaf["key"] not in approvals[0]["selected_items"]
                report_row = next(row for row in artifact["report"]["items"] if row["key"] == leaf["key"])
                assert report_row["render_disposition"] == "NOT_APPROVED" or (pair == "palo_alto_to_fortigate" and report_row.get("approved") is False and "Not selected for engineer approval." in report_row["blocking_reasons"])
                expect(page.get_by_role("heading", name=re.compile("Partial"))).to_be_visible()
            if "files" in artifact:
                files = artifact["files"]
                labels = {
                    "checkpoint_management_operations.json": "Download Management requests" if pair.startswith("fortigate") else "Download Management API requests",
                    "checkpoint_management.sh": "Download Management commands" if pair.startswith("fortigate") else "Download Fresh-package Management commands",
                    "checkpoint_bindings.json": "Download UID manifest" if pair.startswith("fortigate") else "Download UID bindings and file manifest",
                    "gaia_config.clish": "Download Gaia config" if pair.startswith("fortigate") else "Download Gaia configuration",
                    "cisco_fmc_operations.json": "Download FMC REST API request specification",
                    "cisco_fmc_curl.sh": "Download Fresh-policy FMC curl shell script",
                    "cisco_fmc_bindings.json": "Download ID bindings and file manifest",
                    "ftd_application_instructions.txt": "Download FTD application instructions",
                }
                expected_files = {name: (file["content"].encode(), file["sha256"]) for name, file in files.items() if name in labels}
            else:
                name, label = ("fortigate_config.conf", "Download FortiGate .conf") if pair.endswith("fortigate") else (
                    ("juniper_config.set", "Download Junos set file") if pair.endswith("juniper_srx") else
                    ("asa_config.cfg", "Download ASA" if pair.startswith("fortigate") else "Download ASA .cfg"))
                text = artifact.get("command_text", "\n".join(artifact.get("commands", [])))
                expected_files = {name: (text.encode(), artifact["command_sha256"])}
                labels = {name: label}
                preview = page.locator('textarea[readonly]').first
                expect(preview).to_have_value(text)
            downloaded_files = {}
            for name, (expected_bytes, digest) in expected_files.items():
                print(f"Downloading {pair}: {name}", flush=True)
                action = page.get_by_role("button", name=labels[name], exact=True)
                if "files" in artifact:
                    preview_name = labels[name].removeprefix("Download ")
                    tab = page.get_by_role("tab", name=preview_name, exact=True)
                    if tab.count():
                        tab.click()
                    expect(page.locator('textarea[readonly]').first).to_have_value(expected_bytes.decode())
                if not expected_bytes and action.is_disabled():
                    continue
                with page.expect_download(timeout=120000 if custom_source else 30000) as downloaded:
                    action.click()
                path = Path(temporary) / name
                downloaded.value.save_as(path)
                assert path.read_bytes() == expected_bytes, (pair, name)
                assert hashlib.sha256(expected_bytes).hexdigest() == digest, (pair, name)
                downloaded_files[name] = digest
            with page.expect_download(timeout=120000 if custom_source else 30000) as bundled:
                page.get_by_role("button", name=re.compile(r"^Download (migration bundle|reviewed bundle)$")).click()
            bundle_path = Path(temporary) / "bundle.zip"
            bundled.value.save_as(bundle_path)
            with zipfile.ZipFile(bundle_path) as bundle:
                for name, (expected_bytes, _) in expected_files.items():
                    assert bundle.read(name) == expected_bytes, (pair, name)
            assert not errors, errors
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), pair
            results.append({"pair": pair, "width": width, "large_source": bool(custom_source), "files": downloaded_files, "result": "PASS"})
            page.close()
        browser.close()
    print(json.dumps(results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5057")
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--large-source")
    parser.add_argument("--large-only", action="store_true")
    args = parser.parse_args()
    if args.large_only and not args.large_source:
        parser.error("--large-only requires --large-source")
    run(args.url, args.chromium, args.large_source, args.large_only)
