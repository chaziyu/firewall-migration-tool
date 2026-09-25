"""Run a deterministic FAST Excel export benchmark without CI timing limits."""

from __future__ import annotations

import argparse
import io
import json
import time
import tracemalloc

from fwmigrate.source_reporting import ExcelExportMetrics, ExcelExportProfile
from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.export.excel import export_excel
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.validation.validator import validate_config


def make_source(addresses: int, groups: int, services: int, policies: int) -> str:
    blocks = [
        "config firewall address\n"
        + "".join(
            f'    edit "addr{i}"\n'
            f"        set subnet 10.{i // 65536}.{(i // 256) % 256}.{i % 256} 255.255.255.255\n"
            "    next\n"
            for i in range(addresses)
        )
        + "end",
        "config firewall addrgrp\n"
        + "".join(
            f'    edit "group{i}"\n        set member "addr{i % max(addresses, 1)}"\n    next\n'
            for i in range(groups)
        )
        + "end",
        "config firewall service custom\n"
        + "".join(
            f'    edit "svc{i}"\n        set tcp-portrange {1000 + i}\n    next\n'
            for i in range(services)
        )
        + "end",
        "config firewall policy\n"
        + "".join(
            f"    edit {i + 1}\n"
            f'        set name "policy{i}"\n'
            f'        set srcaddr "addr{i % max(addresses, 1)}"\n'
            '        set dstaddr "all"\n'
            f'        set service "svc{i % max(services, 1)}"\n'
            "        set action accept\n"
            + (f'        set custom-policy-option "future-{i}"\n' if i == 0 else "")
            + "    next\n"
            for i in range(policies)
        )
        + "end",
        "config router static\n"
        + "".join(
            f"    edit {i + 1}\n        set dst 192.0.{i % 256}.0 255.255.255.0\n"
            "        set gateway 192.0.2.1\n    next\n"
            for i in range(max(1, policies // 20))
        )
        + "end",
        '''config system interface
    edit "wan1"
        set ip 192.0.2.1 255.255.255.0
    next
end
config vpn ipsec phase1-interface
    edit "bench-vpn"
        set interface "wan1"
        set remote-gw 203.0.113.10
        set psksecret "benchmark-secret"
    next
end
config vpn ipsec phase2-interface
    edit "bench-vpn-p2"
        set phase1name "bench-vpn"
        set src-subnet 10.0.0.0 255.0.0.0
        set dst-subnet 172.16.0.0 255.240.0.0
    next
end
config firewall benchmark-unsupported
    edit "future-source"
        set future-custom-setting "preserve-this"
        append future-list "one" "two"
    next
end''',
    ]
    return "\n".join(blocks)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addresses", type=int, default=1000)
    parser.add_argument("--groups", type=int, default=500)
    parser.add_argument("--services", type=int, default=500)
    parser.add_argument("--policies", type=int, default=2000)
    parser.add_argument("--measure-memory", action="store_true")
    args = parser.parse_args()

    source = make_source(args.addresses, args.groups, args.services, args.policies)
    started = time.perf_counter()
    extracted = extract_fortigate_config(
        parse_fortigate_config(source),
        config=ExtractionConfig(),
    )
    extraction_seconds = time.perf_counter() - started
    started = time.perf_counter()
    derived = build_derived_views(extracted.config)
    validation = validate_config(extracted.config, derived=derived)
    analysis_seconds = time.perf_counter() - started

    output = io.BytesIO()
    metrics = ExcelExportMetrics()
    started = time.perf_counter()
    export_excel(
        extracted=extracted,
        derived=derived,
        validation=validation,
        output=output,
        profile=ExcelExportProfile.FAST,
        metrics=metrics,
    )
    export_seconds = time.perf_counter() - started
    peak_bytes = None
    if args.measure_memory:
        tracemalloc.start()
        memory_output = io.BytesIO()
        export_excel(
            extracted=extracted,
            derived=derived,
            validation=validation,
            output=memory_output,
            profile=ExcelExportProfile.FAST,
        )
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    print(json.dumps({
        "input_counts": vars(args),
        "extraction_seconds": round(extraction_seconds, 3),
        "analysis_seconds": round(analysis_seconds, 3),
        "fast_export_seconds": round(export_seconds, 3),
        "peak_traced_bytes": peak_bytes,
        "xlsx_bytes": output.tell(),
        "export_metrics": metrics.as_dict(),
    }, indent=2))


if __name__ == "__main__":
    main()
