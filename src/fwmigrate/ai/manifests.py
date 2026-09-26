"""Pinned model and runtime artifacts used by managed local AI."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LocalModelManifest:
    model_id: str
    display_name: str
    filename: str
    revision: str
    download_url: str
    sha256: str
    size_bytes: int
    license_id: str
    context_size: int


@dataclass(frozen=True, slots=True)
class LlamaRuntimeManifest:
    version: str
    platform: str
    architecture: str
    archive_url: str
    archive_sha256: str
    archive_size_bytes: int


LOCAL_MODEL = LocalModelManifest(
    model_id="qwen3-1.7b-q4_k_m",
    display_name="Qwen3-1.7B Q4_K_M",
    filename="Qwen3-1.7B-Q4_K_M.gguf",
    revision="daeb8e2d528a760970442092f6bf1e55c3b659eb",
    download_url=("https://huggingface.co/ggml-org/Qwen3-1.7B-GGUF/resolve/"
                  "daeb8e2d528a760970442092f6bf1e55c3b659eb/Qwen3-1.7B-Q4_K_M.gguf"),
    sha256="d2387ca2dbfee2ffabce7120d3770dadca0b293052bc2f0e138fdc940d9bc7b5",
    size_bytes=1_282_439_264,
    license_id="Apache-2.0",
    context_size=4096,
)

WINDOWS_X64_CPU_RUNTIME = LlamaRuntimeManifest(
    version="b11200",
    platform="windows",
    architecture="x86_64",
    archive_url="https://github.com/ggml-org/llama.cpp/releases/download/b11200/llama-b11200-bin-win-cpu-x64.zip",
    archive_sha256="b958c2f249b59335048a57993802b292faeffaee55555b71e59616d6c2c399ca",
    archive_size_bytes=19_154_722,
)
