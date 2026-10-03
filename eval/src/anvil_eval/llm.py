"""llama-server, started and spoken to the way Anvil would ship it (plan node serving).

``LlamaServer`` runs one pinned ``llama-server`` binary with one GGUF and waits for ``/health``.
``Client`` speaks its native endpoints: ``/apply-template`` renders the model's own chat template,
and ``/completion`` generates under a JSON-schema grammar with the raw next-token distribution at
every generated position (``n_probs``), which is where the evaluation reads its scores.

Placement is explicit: ``device="CUDA0"`` (RTX 4070), ``"CUDA1"`` (RTX 4060) or ``"cpu"``. The CPU
setting also hides every GPU from the process, so a CPU run cannot touch one by accident.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from anvil_eval.models import LLAMA_CPP_BUILD, LLAMA_CPP_DIR


class ServerError(RuntimeError):
    """llama-server did not start, or answered with something the harness cannot use."""


def _bin_dir() -> Path:
    return LLAMA_CPP_DIR / f"llama-{LLAMA_CPP_BUILD}"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class LlamaServer:
    model: Path
    device: str  # "CUDA0", "CUDA1", "CUDA0,CUDA1" or "cpu"
    ctx: int = 8192
    seed: int = 20261003
    threads: int | None = None
    port: int = 0
    log: Path | None = None
    extra: list[str] | None = None  # e.g. ["--n-cpu-moe", "24"] for a coder split across RAM

    def args(self) -> list[str]:
        a = [
            str(_bin_dir() / "llama-server"),
            "-m", str(self.model),
            "--host", "127.0.0.1", "--port", str(self.port),
            "-c", str(self.ctx), "--seed", str(self.seed),
            "-np", "1", "--no-webui", "--metrics",
        ]
        if self.device == "cpu":
            a += ["-ngl", "0", "--device", "none"]
        else:
            a += ["-ngl", "999", "--device", self.device]
        if self.threads:
            a += ["-t", str(self.threads)]
        return a + list(self.extra or [])

    def env(self) -> dict[str, str]:
        e = dict(os.environ, LD_LIBRARY_PATH=str(_bin_dir()))
        if self.device == "cpu":
            e["CUDA_VISIBLE_DEVICES"] = ""
        return e

    def __enter__(self) -> Client:
        if not self.model.is_file():
            raise ServerError(f"{self.model} is missing")
        if self.device != "cpu" and not set(self.device.split(",")) <= {"CUDA0", "CUDA1"}:
            raise ServerError(f"device must be cpu or CUDA0 and/or CUDA1, not {self.device!r}")
        self.port = self.port or _free_port()
        out = self.log.open("ab") if self.log else subprocess.DEVNULL
        self._proc = subprocess.Popen(self.args(), env=self.env(), stdout=out, stderr=out)
        client = Client(f"http://127.0.0.1:{self.port}")
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                code = self._proc.returncode
                raise ServerError(f"llama-server exited with {code}; see {self.log}")
            if client.healthy():
                return client
            time.sleep(0.5)
        self.__exit__(None, None, None)
        raise ServerError("llama-server did not become healthy within 600 s")

    def __exit__(self, *exc) -> None:
        proc = getattr(self, "_proc", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(30)
            except subprocess.TimeoutExpired:
                proc.kill()


class Client:
    def __init__(self, base: str, timeout: float = 600):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _call(self, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            raise ServerError(f"{path}: HTTP {exc.code}: {exc.read()[:500]!r}") from exc
        except OSError as exc:
            raise ServerError(f"{path}: {exc}") from exc

    def healthy(self) -> bool:
        try:
            return self._call("/health").get("status") == "ok"
        except ServerError:
            return False

    def props(self) -> dict:
        return self._call("/props")

    def apply_template(self, messages: list[dict], template_kwargs: dict | None = None) -> str:
        body: dict = {"messages": messages}
        if template_kwargs:
            body["chat_template_kwargs"] = template_kwargs
        return self._call("/apply-template", body)["prompt"]

    def complete(
        self, prompt: str, schema: dict, n_predict: int, n_probs: int, cache_prompt: bool = True
    ) -> dict:
        """Greedy, grammar-constrained completion with the raw top-``n_probs`` at each step."""
        return self._call(
            "/completion",
            {
                "prompt": prompt,
                "json_schema": schema,
                "n_predict": n_predict,
                "temperature": 0,
                "top_k": 1,
                "n_probs": n_probs,
                "post_sampling_probs": False,
                "cache_prompt": cache_prompt,
            },
        )
