"""Judge providers. Each returns the model's JSON text; validation happens in
the runner. No provider is given tools, and none ever receives credentials
found in scanned content.

* anthropic      — official ``anthropic`` SDK (install ``agentguard[judge]``).
* openai_compat  — any OpenAI-compatible /chat/completions endpoint (raw HTTP).
* ollama         — local Ollama /api/chat (raw HTTP, loopback allowed).
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Any, Protocol

from ..net.safe_http import BlockedRequest, FetchError, SafeHttpClient

DEFAULT_MODELS = {"anthropic": "claude-opus-5-5"}


class JudgeError(Exception):
    pass


class Provider(Protocol):
    name: str
    model: str
    hosts: list[str]

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise JudgeError("the Anthropic provider needs the optional extra: pip install 'agentguard[judge]'") from exc
        self._anthropic = anthropic
        self.client = anthropic.Anthropic()  # credentials from the environment / `ant auth login`
        self.model = model or DEFAULT_MODELS["anthropic"]
        self.hosts = [urllib.parse.urlsplit(str(self.client.base_url)).hostname or "api.anthropic.com"]

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        a = self._anthropic
        try:
            resp = self.client.beta.messages.create(
                model=self.model,
                max_tokens=4000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
                # On a safety decline, let the API retry on a fallback model chosen by refusal category.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except a.RateLimitError as exc:
            raise JudgeError("rate limited by the Anthropic API") from exc
        except a.APIStatusError as exc:
            raise JudgeError(f"Anthropic API error {exc.status_code}") from exc
        except a.APIConnectionError as exc:
            raise JudgeError("could not reach the Anthropic API") from exc
        if resp.stop_reason == "refusal":
            raise JudgeError("the model declined to classify this content")
        if resp.stop_reason == "max_tokens":
            raise JudgeError("verdict was cut off (max_tokens)")
        text = next((b.text for b in resp.content if b.type == "text"), None)
        if text is None:
            raise JudgeError("no text in response")
        return text


class OpenAICompatProvider:
    name = "openai_compat"

    def __init__(self, model: str, endpoint: str) -> None:
        if not model or not endpoint:
            raise JudgeError("openai_compat needs --llm-model and --llm-endpoint")
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        loopback = urllib.parse.urlsplit(self.endpoint).hostname in ("localhost", "127.0.0.1", "::1")
        self.http = SafeHttpClient(timeout=120, deadline_s=180, allow_http_loopback=loopback, allow_private=loopback)
        self.key = os.environ.get("AGENTGUARD_JUDGE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.hosts = self.http.hosts_contacted

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "verdict", "schema": schema, "strict": True}},
        }
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        try:
            resp = self.http.post_json(f"{self.endpoint}/chat/completions", body, headers=headers)
            data = resp.json()
        except (BlockedRequest, FetchError, ValueError) as exc:
            raise JudgeError(str(exc)[:200]) from exc
        if resp.status != 200:
            raise JudgeError(f"endpoint returned HTTP {resp.status}")
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise JudgeError("unexpected response shape") from exc


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, endpoint: str | None = None) -> None:
        if not model:
            raise JudgeError("ollama needs --llm-model")
        self.model = model
        self.endpoint = (endpoint or "http://127.0.0.1:11434").rstrip("/")
        loopback = urllib.parse.urlsplit(self.endpoint).hostname in ("localhost", "127.0.0.1", "::1")
        self.http = SafeHttpClient(timeout=300, deadline_s=360, allow_http_loopback=loopback, allow_private=loopback)
        self.hosts = self.http.hosts_contacted

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {"model": self.model, "stream": False, "format": schema, "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            resp = self.http.post_json(f"{self.endpoint}/api/chat", body)
            data = resp.json()
        except (BlockedRequest, FetchError, ValueError) as exc:
            raise JudgeError(str(exc)[:200]) from exc
        if resp.status != 200:
            raise JudgeError(f"Ollama returned HTTP {resp.status}")
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise JudgeError("unexpected response shape") from exc


def make_provider(name: str, model: str | None, endpoint: str | None) -> Provider:
    if name == "anthropic":
        return AnthropicProvider(model)
    if name == "openai_compat":
        return OpenAICompatProvider(model or "", endpoint or "")
    if name == "ollama":
        return OllamaProvider(model or "", endpoint)
    raise JudgeError(f"unknown judge provider {name!r}")
