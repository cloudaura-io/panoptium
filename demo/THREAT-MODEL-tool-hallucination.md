# Tool Call Hallucination

LLMs can return structured `tool_call` responses for tools that were not included in the request's `tools[]` array. This bypasses request-path defenses (like tool stripping) because the model generates the call from training data, conversation history, or prompt injection -- not from the tool definitions it received.

## How it happens

Without constrained decoding, LLM APIs do not enforce that response tool calls reference only tools from the request. The model predicts the next token based on context, and tool names seen during training or in the conversation are valid candidates.

OpenAI and Anthropic offer `strict: true` mode which constrains decoding to the defined schema, but it is opt-in, not default. Open-source models served via vLLM or Ollama in `auto` mode have no such constraint at all.

## Confirmed cases

- **Answer.AI (2026)** -- Claude Opus called `read_secret()` when only `read_url` was authorized. GPT and Gemini also vulnerable. ~50% success rate on smaller models. [Source](https://www.answer.ai/posts/2026-01-20-toolcalling.html)
- **ToolCommander (NAACL 2025)** -- 91.67% attack success rate for privacy theft, 100% for unscheduled tool calling via adversarial tool descriptions. [arXiv:2412.10198](https://arxiv.org/abs/2412.10198)
- **CVE-2025-32711 (EchoLeak)** -- Zero-click prompt injection in M365 Copilot (CVSS 9.3) coerced tool calls to exfiltrate files and chat logs. [Source](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)
- **OpenAI API** -- Multiple community reports of hallucinated function names not in `tools[]`. [Report 1](https://community.openai.com/t/how-to-stop-model-from-hallucinating-function-names/591674), [Report 2](https://community.openai.com/t/responses-hallucinated-tool-call/1251417)

## Mitigations

| Approach | Scope | Limitation |
|---|---|---|
| Response-path enforcement (gateway inspects response stream, blocks unauthorized tool calls) | Any provider/model | Name-based only -- cannot detect semantic equivalence via allowed tools |
| Provider `strict: true` (constrained decoding) | OpenAI, Anthropic | Opt-in; 20-tool limit on OpenAI; unavailable for open-source models |
| Agent-side validation (framework rejects unknown tool names before execution) | Framework-level | Not all frameworks implement it; model may retry repeatedly |

## What this does not cover

A model instructed to `bash("kubectl logs ...")` instead of calling `k8s_get_pod_logs` achieves the same result using an allowed tool. Name-based enforcement cannot detect this. Argument-level inspection or cross-request behavioral analysis would be required.
