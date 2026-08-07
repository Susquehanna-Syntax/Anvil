# Anvil Implementation Plan — Routing Policy And Packet Format

**Read this before writing any step.** Every step in the Anvil implementation plan is a *worker packet*
executed by an agent running the `multi-model-agent-orchestrator` skill. This file is the routing policy
those packets must conform to. It is an extract of the skill, reproduced here so cold workers do not have
to load the skill to route correctly.

---

## The orchestrator rule

An **Opus main agent is the orchestrator**. It owns task framing, final synthesis, side effects, user
communication, and conflict resolution, and **never delegates any of them**. Workers never spawn workers.

**Do not write a step that delegates:** coordination, synthesis, user communication, or any destructive,
credentialed, external, or approval-requiring action. Those belong to the orchestrator or to the human.

**Do not write a step that delegates trivia.** If a step is a single-file edit, a one-line answer, or a
quick diagnostic, mark it `orchestrator-inline` — delegation must earn its cost.

---

## Anthropic worker routes (Claude Code subagents)

| Model | Best use | Guard |
|---|---|---|
| `opus` | hardest architecture; security/high-risk critique; the one genuinely hard parallel sub-problem | slowest and most costly — never for bounded chores |
| `sonnet` | **default strong worker**: implementation, refactor, code and security review, most parallel work | escalate only genuinely ambiguous architecture to `opus` |
| `haiku` | fastest worker: repo discovery, extraction, test-log triage, docs, mechanical edits, compact verification | give bounded checkable outputs; verify before high-stakes conclusions |

## OpenCode paid routes (external CLI) — escalation only

| Route | Best use |
|---|---|
| `openai/gpt-5.5` | strong cross-family critic, hard architecture, high-risk review |
| `openai/gpt-5.5-fast` | quick strong triage, fast reviewer, branch unblocker |
| `openai/gpt-5.4` | normal implementation and refactor |
| `openai/gpt-5.4-fast` | exploration, test-log triage, quick reviews |
| `openai/gpt-5.4-mini` / `-mini-fast` | docs, summaries, extraction, cheap parallel scouts |
| `openai/gpt-5.3-codex-spark` | code-focused mechanical edits and test repair |

**Paid routes require justification in the packet.** Use them for high-stakes final judgment, unresolved
conflicts, or after repeated weak free-worker evidence — not by default.

## OpenRouter free routes

Use explicit `provider/model:free` IDs. **Never** use the `openrouter/free` random router.

| Route | Best use | Guard |
|---|---|---|
| `qwen/qwen3-coder:free` | **default coding / technical scout** | verify important claims against primary sources and tests |
| `openai/gpt-oss-120b:free` | strong general scout or critic | keep reply budget tight |
| `openai/gpt-oss-20b:free` | fast source triage, table extraction, draft summaries | avoid hard final judgment |
| `cohere/north-mini-code:free` | narrow code, terminal, benchmark, repo checks | keep scope small and checkable |
| `poolside/laguna-m.1:free` | agentic software-engineering workflows | avoid sensitive private code |
| `poolside/laguna-xs-2.1:free`, `poolside/laguna-xs.2:free` | fast bounded code chores, docs, compact review | verify synthesis with a stronger route |
| `nvidia/nemotron-3-super-120b-a12b:free` | strong planning and secondary critique | time-box; validate schema |
| `nvidia/nemotron-3-nano-30b-a3b:free` | fast bounded reasoning and extraction | avoid final synthesis |
| `google/gemma-4-26b-a4b-it:free`, `google/gemma-4-31b-it:free` | multimodal extraction, docs, document-heavy scouting | verify coding conclusions |
| `meta-llama/llama-3.3-70b-instruct:free` | general fallback scout | verify technical claims |
| `qwen/qwen3-next-80b-a3b-instruct:free` | fast general/coding fallback | check important details |
| `nvidia/nemotron-3-ultra-550b-a55b:free` | slow background critic, deep planning | **keep OFF the critical path** — known to hang 10–20+ min |

---

## Cross-family critique rule — this is a hard requirement, not a preference

- Anthropic-written code and plans get an **OpenCode/OpenRouter critic**.
- OpenCode-written code gets an **`opus` or `sonnet` critic**.

Shared blind spots are the failure this prevents. Any step that produces security-relevant code, a
migration, an authorization decision, data-loss risk, or a licence conclusion **must** carry a critic step
from a different model family before its result is accepted.

---

## Mandatory packet format

Every step in the plan must be written as:

```text
Step ID:          <phase>.<n>
Phase/group:      serial | parallel group <n>
Depends on:       <step IDs, or "none">
Backend/model:    Claude Code subagent (opus|sonnet|haiku) | OpenCode route | orchestrator-inline
Objective:        <one sentence, imperative>
Scope and files:  <read scope; WRITE scope must be disjoint from every parallel sibling>
Forbidden actions:
Inputs/artifact refs:
Expected output schema:
Validation/evidence required:
Stop condition:
Why this model:   <one line tied to the routing table above>
```

**Write-scope discipline.** Two steps in the same parallel group must never write the same file. If they
would, either serialize them or split the file. State the write scope as explicit paths.

---

## Invocation notes (for the executing orchestrator)

**Anthropic worker:** dispatch a Claude Code subagent via the Agent/Task tool with the model pinned and
the packet as the prompt. A fresh subagent is cold — pass only the context it needs, by file path.

**OpenCode worker:**
```
opencode run -m <route> --format json --dir <worker-dir> "<packet>"
```
- `<worker-dir>` must contain **every** file the packet asks the worker to read. If the packet needs both
  the repo and an external manifest, use their common parent or copy the manifest into a read-only
  scratch dir first — otherwise OpenCode rejects `external_directory` reads and stops before synthesis.
- `--format json` emits NDJSON; the answer is in `text` events.
- On Windows, capture to a file with `-Encoding utf8` to avoid CP437 mojibake.
- **Always time-box.** Reroute once on timeout, empty output, or malformed output.

**Credentials:** read `OPENROUTER_API_KEY` from the environment and pass it to child processes without
printing it. On Windows check Process, then User, then Machine scope; set only the Process scope before
launching. **Never print, log, echo, or write the key.** Fail closed if it is missing.

---

## Review gates

| Work type | Gate |
|---|---|
| Code changes | tests, build/type/lint evidence, or a logged substitute |
| Research | source-quality notes and unresolved gaps |
| Security, migrations, data loss, auth, payments, deployment | **independent critic, different model family** |
| Final synthesis | cites worker evidence and states limitations |

---

## Rerouting

If a worker fails its schema, uses a forbidden tool, times out, or returns weak evidence: **reroute once**
to a stronger or different model, and log the reroute. Do not retry the same route repeatedly.
