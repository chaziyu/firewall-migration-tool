import runpy
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


CONFIG = Path(__file__).resolve().parents[1] / 'gunicorn.conf.py'


def test_gunicorn_defaults_and_effective_worker_guards():
    config = runpy.run_path(str(CONFIG))
    assert (config['workers'], config['threads']) == (1, 4)
    config['on_starting'](SimpleNamespace(cfg=SimpleNamespace(workers=1)))
    config['nworkers_changed'](None, 1, None)
    for count in (0, 2, 4):
        with pytest.raises(RuntimeError, match='exactly one'):
            config['on_starting'](SimpleNamespace(cfg=SimpleNamespace(workers=count)))
        with pytest.raises(RuntimeError, match='exactly one'):
            config['nworkers_changed'](None, count, 1)


@pytest.mark.skipif(sys.platform == 'win32', reason='Gunicorn requires Unix')
def test_gunicorn_launch_and_worker_overrides():
    env = {**os.environ, 'PYTHONPATH': str(CONFIG.parent / 'src'), 'GUNICORN_CMD_ARGS': ''}
    command = [sys.executable, '-m', 'gunicorn', '--config', str(CONFIG),
               "fwmigrate.web:create_app({'WEB_MODE': 'public'})"]
    for arguments, settings in [(['--workers', '2'], {}),
                                ([], {'GUNICORN_CMD_ARGS': '--workers 2'})]:
        result = subprocess.run([*command, *arguments, '--bind', '127.0.0.1:0'],
                                env={**env, **settings}, capture_output=True, text=True, timeout=15)
        assert result.returncode != 0
        assert 'exactly one Gunicorn worker' in result.stderr

    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen([*command, '--bind', f'127.0.0.1:{port}'], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        from urllib.error import URLError
        from urllib.request import urlopen

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with urlopen(f'http://127.0.0.1:{port}/api/vendors', timeout=1) as response:
                    assert response.status == 200
                    break
            except URLError:
                time.sleep(0.1)
        else:
            pytest.fail('Gunicorn did not serve the application')
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
