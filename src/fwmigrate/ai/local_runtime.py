"""Owned localhost llama-server lifecycle."""

import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import AISettings
from .local_model import LocalModelManager
from .local_paths import bundled_runtime_dir


@dataclass(frozen=True, slots=True)
class LocalRuntimeInfo:
    base_url: str
    api_key: str
    model_id: str
    pid: int


class LocalAIRuntimeManager:
    def __init__(self, settings: AISettings, *, model_manager=None, runtime_path: Path | None = None):
        self.settings = settings
        self.model_manager = model_manager or LocalModelManager()
        self.runtime_path = Path(runtime_path) if runtime_path else None
        self._lock = threading.Lock()
        self._process = None
        self._runtime = None
        self._state = "STOPPED"
        self._install_thread = None

    def status(self) -> dict:
        model = self.model_manager.status()
        executable = self._executable()
        state = ("RUNTIME_REQUIRED" if not executable.is_file()
                 else self._state if model["installed"] else model["state"])
        if state == "READY" and self._runtime and self._is_sleeping(self._runtime):
            state = "SLEEPING"
        return {**model, "state": state, "runtime_version": "b11200",
                "runtime_available": executable.is_file()}

    def is_available_or_installable(self) -> bool:
        status = self.status()
        return bool(status["runtime_available"] and status["installed"])

    def start_install(self) -> dict:
        with self._lock:
            if self._install_thread and self._install_thread.is_alive():
                return self.model_manager.status()
            status = self.model_manager.status()
            if status["installed"]:
                return status
            self.model_manager.mark_downloading()
            self._install_thread = threading.Thread(target=self.model_manager.ensure_installed,
                                                    name="local-ai-model-download", daemon=True)
            self._install_thread.start()
            return self.model_manager.status()

    def remove_model(self) -> None:
        self.stop()
        self.model_manager.remove()

    def ensure_ready(self) -> LocalRuntimeInfo:
        with self._lock:
            model_path = self.model_manager.ensure_installed()
            executable = self._executable()
            if not executable.is_file():
                self._state = "FAILED"
                raise RuntimeError("The pinned local AI runtime is unavailable for this platform")
            if self._process is not None and self._process.poll() is None and self._runtime is not None:
                try:
                    if self._healthy(self._runtime.base_url):
                        self._state = "READY"
                        return self._runtime
                except OSError:
                    pass
                self._stop_owned()
            self._state = "STARTING"
            kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                      "stderr": subprocess.DEVNULL, "close_fds": True}
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            for attempt in range(3):
                api_key = secrets.token_urlsafe(32)
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
                base_url = f"http://127.0.0.1:{port}"
                command = [str(executable), "--model", str(model_path), "--host", "127.0.0.1",
                           "--port", str(port), "--ctx-size", str(self.settings.local_context_size),
                           "--parallel", "1", "--reasoning", "off", "--no-webui",
                           "--sleep-idle-seconds", str(self.settings.local_idle_seconds), "--api-key", api_key,
                           "--threads", str(self.settings.local_threads or self._default_threads())]
                try:
                    self._process = subprocess.Popen(command, **kwargs)
                except OSError as exc:
                    self._state = "FAILED"
                    raise RuntimeError("Local AI runtime could not be started") from exc
                self._runtime = LocalRuntimeInfo(base_url, api_key, self.settings.local_model,
                                                 self._process.pid)
                deadline = time.monotonic() + self.settings.local_startup_timeout_seconds
                while time.monotonic() < deadline and self._process.poll() is None:
                    try:
                        if self._healthy(base_url):
                            self._state = "READY"
                            return self._runtime
                    except OSError:
                        pass
                    time.sleep(0.25)
                exited_early = self._process.poll() is not None
                self._stop_owned()
                if not exited_early:
                    break
            self._state = "FAILED"
            raise RuntimeError("Local AI runtime failed to become ready")

    def start(self) -> LocalRuntimeInfo:
        return self.ensure_ready()

    def restart(self) -> LocalRuntimeInfo:
        self.stop()
        return self.ensure_ready()

    def stop(self) -> None:
        with self._lock:
            self._stop_owned()
            self._state = "STOPPED"

    def _stop_owned(self) -> None:
        process, self._process = self._process, None
        self._runtime = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def _healthy(self, base_url: str) -> bool:
        try:
            with urlopen(base_url + "/health", timeout=1) as response:
                return response.status == 200
        except HTTPError as exc:
            if exc.code == 503:
                return False
            raise OSError("Local AI health check failed") from exc
        except URLError as exc:
            raise OSError("Local AI runtime is not ready") from exc

    @staticmethod
    def _is_sleeping(runtime: LocalRuntimeInfo) -> bool:
        request = Request(runtime.base_url + "/props", headers={"Authorization": f"Bearer {runtime.api_key}"})
        try:
            with urlopen(request, timeout=1) as response:
                return bool(json.loads(response.read()).get("is_sleeping"))
        except (OSError, ValueError, TypeError):
            return False

    def _executable(self) -> Path:
        if self.runtime_path:
            return self.runtime_path
        override = os.environ.get("AI_LLAMA_SERVER_PATH") if not getattr(sys, "frozen", False) else None
        return Path(override) if override else bundled_runtime_dir() / "llama-server.exe"

    @staticmethod
    def _default_threads() -> int:
        return max(2, min(8, (os.cpu_count() or 4) - 2))
