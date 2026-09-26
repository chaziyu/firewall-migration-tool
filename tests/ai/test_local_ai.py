import hashlib
import io
import json

from fwmigrate.ai.config import AISettings
from fwmigrate.ai.llama_cpp import LlamaCppProvider
from fwmigrate.ai.local_model import LocalModelManager
from fwmigrate.ai.local_runtime import LocalAIRuntimeManager, LocalRuntimeInfo
from fwmigrate.ai.manifests import LocalModelManifest


def _manifest(data=b"model"):
    return LocalModelManifest("test", "Test model", "model.gguf", "rev", "https://example/model",
                              hashlib.sha256(data).hexdigest(), len(data), "test", 32)


def test_model_download_verifies_and_installs_atomically(tmp_path, monkeypatch):
    from fwmigrate.ai import local_model

    calls = []
    monkeypatch.setattr(local_model, "urlopen", lambda *args, **kwargs: calls.append(args) or io.BytesIO(b"model"))
    manager = LocalModelManager(_manifest(), model_dir=tmp_path / "models")
    assert manager.ensure_installed().read_bytes() == b"model"
    assert manager.status()["state"] == "READY"
    assert not manager.part_path.exists()
    manager.ensure_installed()
    assert len(calls) == 1


def test_bad_model_digest_never_installs_partial_file(tmp_path, monkeypatch):
    from fwmigrate.ai import local_model

    monkeypatch.setattr(local_model, "urlopen", lambda *args, **kwargs: io.BytesIO(b"wrong"))
    manager = LocalModelManager(_manifest(), model_dir=tmp_path / "models")
    try:
        manager.ensure_installed()
    except RuntimeError as exc:
        assert "integrity" in str(exc)
    else:
        raise AssertionError("invalid model bytes were accepted")
    assert not manager.path.exists()
    assert not manager.part_path.exists()
    assert manager.status()["state"] == "FAILED"


def test_runtime_binds_to_loopback_and_stops_only_owned_child(tmp_path, monkeypatch):
    from fwmigrate.ai import local_runtime

    model_path = tmp_path / "model.gguf"
    model_path.write_bytes(b"model")

    class ModelManager:
        def ensure_installed(self): return model_path
        def status(self): return {"state": "READY", "installed": True}

    class Child:
        pid = 12
        stopped = False
        def poll(self): return None if not self.stopped else 0
        def terminate(self): self.stopped = True
        def wait(self, timeout): return 0

    child = Child()
    invoked = {}
    monkeypatch.setattr(local_runtime.subprocess, "Popen", lambda args, **kwargs: invoked.update(args=args, kwargs=kwargs) or child)
    manager = LocalAIRuntimeManager(AISettings(), model_manager=ModelManager(), runtime_path=tmp_path / "llama-server.exe")
    manager.runtime_path.touch()
    monkeypatch.setattr(manager, "_healthy", lambda url: True)
    runtime = manager.ensure_ready()
    assert runtime.base_url.startswith("http://127.0.0.1:")
    assert "--host" in invoked["args"] and invoked["args"][invoked["args"].index("--host") + 1] == "127.0.0.1"
    assert invoked["args"][invoked["args"].index("--api-key") + 1] == runtime.api_key
    monkeypatch.setattr(manager, "_is_sleeping", lambda runtime: True)
    assert manager.status()["state"] == "SLEEPING"
    manager.stop()
    assert child.stopped


def test_local_provider_uses_shared_json_schema_contract(monkeypatch):
    from fwmigrate.ai import llama_cpp

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"id": "local-1", "choices": [{"message": {"content": '{"ok":true}'}}],
                               "usage": {"prompt_tokens": 2, "completion_tokens": 1}}).encode()

    request_data = {}
    def open_request(request, timeout):
        request_data.update(url=request.full_url, headers=dict(request.header_items()), body=json.loads(request.data))
        return Response()
    monkeypatch.setattr(llama_cpp, "urlopen", open_request)

    class RuntimeManager:
        def ensure_ready(self): return LocalRuntimeInfo("http://127.0.0.1:9876", "ephemeral-key", "qwen3", 1)

    result = LlamaCppProvider(AISettings(), runtime_manager=RuntimeManager()).generate_structured(
        system_prompt="rules", payload={"operation": "questions"}, schema_name="test",
        schema={"type": "object", "additionalProperties": False})
    assert request_data["url"] == "http://127.0.0.1:9876/v1/chat/completions"
    assert request_data["headers"]["Authorization"] == "Bearer ephemeral-key"
    assert request_data["body"]["response_format"]["json_schema"]["name"] == "test"
    assert (result.data, result.provider, result.request_id, result.input_tokens) == ({"ok": True}, "local", "local-1", 2)
