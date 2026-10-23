"""Measure warmed Excel exports, pipeline allocations and process RSS per case.

Examples:
  python scripts/benchmark_excel_exports.py --vendor all --measure-memory
  python scripts/benchmark_excel_exports.py --vendor fortigate --workload wrapped --scale 5
  OPENPYXL_LXML=False python scripts/benchmark_excel_exports.py --vendor all
  python scripts/benchmark_excel_exports.py --vendor fortigate --http --concurrency 4 --read-delay-ms 10

Fixtures and generated source are synthetic. Output contains metrics, never source
values. Each vendor/profile case runs in a fresh child process. Tracemalloc measures
an additional complete pipeline pass, excluding imports and the existing input
string. RSS includes the process, input, warmups, timed passes and memory pass.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import gc
import io
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
from time import perf_counter, sleep
import tracemalloc


FIXTURES = {
    'fortigate': None,
    'palo_alto': 'palo_alto/integrated_panorama.xml',
    'cisco_asa': 'cisco_asa/nat_pipeline_conformance.txt',
    'cisco_ftd': 'cisco_ftd/fmc_selected_domains.json',
    'juniper_srx': None,
    'checkpoint': 'checkpoint/multidomain_full.json',
}


def source_for(args):
    if args.input:
        return args.input.read_text(encoding='utf-8')
    if args.vendor == 'fortigate':
        from benchmark_fortigate_fast_excel import make_source
        count = args.scale
        source = make_source(1000 * count, 500 * count, 500 * count, 2000 * count)
        extra = {
            'basic': '',
            'wrapped': '        set comments "' + ('long readable comment ' * 50) + '"\n',
            'nat': '        set nat enable\n        set dstintf wan1\n',
            'validation': '        set srcaddr missing-address\n',
        }[args.workload]
        return source.replace('        set action accept\n', '        set action accept\n' + extra)
    if args.vendor == 'juniper_srx':
        return '\n'.join(['set system host-name benchmark-srx'] + [
            f'set security address-book global address host-{i} 192.0.2.1/32' for i in range(1000 * args.scale)])
    return (Path(__file__).resolve().parents[1] / 'tests/fixtures' / FIXTURES[args.vendor]).read_text(encoding='utf-8')


def worker(args):
    import openpyxl
    from openpyxl.xml import LXML
    from fwmigrate.collection.snapshot import sanitize_source
    from fwmigrate.source_reporting import ExcelExportMetrics, SourceReportMetrics, source_reporters
    from fwmigrate.source_reporting.builtin import register_builtin_source_reporters

    register_builtin_source_reporters()
    source = source_for(args)
    reporter = source_reporters.get(args.vendor)
    client_app = None
    if args.http:
        from fwmigrate.web import create_app
        client_app = create_app({'TESTING': True, 'API_RATE_LIMIT_PER_MINUTE': 100000,
                                'MAX_CONCURRENT_REQUESTS': max(2, args.concurrency)})

    def run_once():
        started = perf_counter()
        if client_app is not None:
            response = client_app.test_client().post('/api/extract/excel', json={
                'source_vendor': args.vendor, 'excel_profile': args.profile,
                'source': {'vendor': args.vendor, 'source_text': source}}, buffered=False)
            try:
                size = 0
                for chunk in response.iter_encoded():
                    size += len(chunk)
                    if args.read_delay_ms:
                        sleep(args.read_delay_ms / 1000)
                return {'total_seconds': perf_counter() - started, 'status': response.status_code, 'bytes': size}
            finally:
                response.close()
        analysis_metrics, export_metrics = SourceReportMetrics(), ExcelExportMetrics()
        safe = sanitize_source(args.vendor, source)
        analysis_started = perf_counter()
        analysis = reporter.analyze_source(safe, metrics=analysis_metrics)
        export_started = perf_counter()
        with io.BytesIO() as output:
            options = {'profile': args.profile}
            if args.vendor == 'fortigate':
                options['metrics'] = export_metrics
            reporter.export_excel(analysis, output, **options)
            exported = perf_counter()
            size = output.tell()
            output.seek(0)
            # Read back ZIP/worksheet metadata outside the measured generation time.
            workbook = openpyxl.load_workbook(output, read_only=True)
            sheets = len(workbook.sheetnames)
            workbook.close()
        return {'total_seconds': exported - started, 'analysis_seconds': export_started - analysis_started,
                'export_seconds': exported - export_started, 'bytes': size, 'sheets': sheets, 'status': 200,
                'analysis_metrics': analysis_metrics.as_dict(), 'export_metrics': export_metrics.as_dict()}

    for _ in range(args.warmup):
        run_once()
    samples = []
    for _ in range(args.repeat):
        gc.collect()
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            samples.extend(pool.map(lambda _: run_once(), range(args.concurrency)))
    peak = export_peak = None
    if args.measure_memory:
        gc.collect()
        tracemalloc.start()
        run_once()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if client_app is None:
            analysis = reporter.analyze_source(sanitize_source(args.vendor, source))
            gc.collect()
            tracemalloc.start()
            with io.BytesIO() as output:
                reporter.export_excel(analysis, output, profile=args.profile)
                _, export_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            del analysis
    try:
        import resource
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_rss *= 1 if sys.platform == 'darwin' else 1024
    except ImportError:
        peak_rss = None
    successes = [sample for sample in samples if sample['status'] == 200]
    result = {'vendor': args.vendor, 'profile': args.profile, 'workload': args.workload, 'scale': args.scale,
              'mode': 'http' if args.http else 'pipeline', 'concurrency': args.concurrency,
              'openpyxl': openpyxl.__version__, 'lxml': LXML, 'peak_rss_bytes': peak_rss,
              'peak_traced_pipeline_bytes': peak, 'peak_traced_export_bytes': export_peak,
              'statuses': {str(status): sum(sample['status'] == status for sample in samples)
                                                            for status in sorted({sample['status'] for sample in samples})}}
    for key in ('total_seconds', 'analysis_seconds', 'export_seconds'):
        values = sorted(sample[key] for sample in successes if key in sample)
        if values:
            result[key] = {'median': statistics.median(values), 'p95': values[math.ceil(len(values) * .95) - 1]}
    if successes:
        result['sample'] = successes[-1]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', choices=['all', *FIXTURES], default='all')
    parser.add_argument('--profile', choices=['both', 'fast', 'full'], default='fast')
    parser.add_argument('--input', type=Path)
    parser.add_argument('--scale', type=int, default=1)
    parser.add_argument('--workload', choices=['basic', 'wrapped', 'nat', 'validation'], default='basic')
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--warmup', type=int, default=1)
    parser.add_argument('--http', action='store_true')
    parser.add_argument('--concurrency', type=int, default=1)
    parser.add_argument('--read-delay-ms', type=float, default=0)
    parser.add_argument('--measure-memory', action='store_true')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.scale, args.repeat, args.concurrency) < 1 or args.warmup < 0 or not 0 <= args.read_delay_ms <= 1000:
        parser.error('counts must be positive; warmup nonnegative; read delay between 0 and 1000 ms')
    if args.input and args.vendor == 'all':
        parser.error('--input requires one vendor')
    if args.workload != 'basic' and args.vendor != 'fortigate':
        parser.error('synthetic workload variants require --vendor fortigate')
    if args.worker:
        print(json.dumps(worker(args)))
        return
    for vendor in FIXTURES if args.vendor == 'all' else [args.vendor]:
        for profile in ['fast', 'full'] if args.profile == 'both' else [args.profile]:
            command = [sys.executable, str(Path(__file__).resolve()), '--worker', '--vendor', vendor,
                       '--profile', profile, '--scale', str(args.scale), '--workload', args.workload,
                       '--repeat', str(args.repeat), '--warmup', str(args.warmup), '--concurrency', str(args.concurrency),
                       '--read-delay-ms', str(args.read_delay_ms)]
            if args.input:
                command.extend(['--input', str(args.input.resolve())])
            if args.http:
                command.append('--http')
            if args.measure_memory:
                command.append('--measure-memory')
            result = subprocess.run(command, capture_output=True, text=True, env=os.environ)
            if result.returncode:
                raise SystemExit(f'Benchmark failed for {vendor}/{profile}; inspect the case locally.')
            print(result.stdout.strip(), flush=True)


if __name__ == '__main__':
    main()
