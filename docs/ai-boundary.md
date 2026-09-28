# AI boundary

CausalForge treats model providers as untrusted, replaceable computation. The deterministic
security engine remains authoritative when no provider is configured.

## Provider contract

`LLMProvider.complete()` accepts a `StructuredRequest` containing a task name selected by
application code, a Pydantic-derived JSON Schema, a bounded token budget, and separate trusted
instruction and untrusted-data messages.

The provider returns a payload plus non-secret provider metadata and a payload hash. The
`StructuredOutputClient` validates the payload against the requested Pydantic model before any
caller can use it. Unknown fields, missing fields, malformed JSON, and provider transport errors
fail closed.

The OpenAI-compatible adapter is intentionally narrow: it sends one structured chat request and
has no tool execution, shell access, arbitrary URL fetching, or target-system credentials.

## Rule-only mode

`DeterministicFallbackProvider` is the default-safe path. It provides an empty, explicitly labeled
`HypothesisBatch` for the built-in hypothesis task and requires an explicit handler for every other
task. It cannot invent evidence or silently emulate a model. Rule-only detection, graph analysis,
RBAC reasoning, and claim verification remain usable without an LLM key.

## Prompt-injection boundary

Evidence and retrieved documents are untrusted data. `build_safe_context()`:

1. Redacts common credential-shaped fields.
2. Removes control characters and bounds strings.
3. Stores evidence and knowledge as labeled fragments.
4. Flags instruction-like text for analyst visibility.
5. Places serialized data in a user message separate from trusted instructions.

The system message tells the model how to reason; it never contains raw evidence text. This is a
boundary control, not a claim that a model cannot be manipulated. Deterministic verification and
policy gates remain mandatory after any model output.

## Audit requirements

Record provider name, model ID, task, output hash, prompt-template hash, and retrieved artifact IDs.
Do not record API keys, raw secret values, or hidden chain-of-thought.
