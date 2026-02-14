---
name: codebase-retrieval
description: Use the codebase MCP server to semantically search the repo, narrow to 1–5 target files, and only then read/edit. Prefer evidence from repository code over guesses.
---

## What I do
- Turn vague repo questions into high-signal semantic retrieval queries.
- Iterate retrieval 1–4 times to converge on the right files/symbols.
- Produce a small, evidence-backed target set (usually 1–5 files) before any significant reading or edits.

## When to use me
Use me when the task depends on **this repository’s reality**, e.g.:
- “Where is X implemented?”, “How does Y work in this repo?”
- Debugging stack traces / logs that reference repo code
- Refactors that must match existing patterns
- Any time you’re not sure which files are relevant

## How to use the codebase MCP (playbook)
1) **Start with semantic retrieval** (never skip unless the user already gave exact file paths).
2) Run **at least one** query. If the results are weak/ambiguous, run 1–3 more:
    - include synonyms / alternative component names
    - include exact error text or log fragments
    - include likely entrypoints (CLI command, HTTP route, job name, config key)
3) From hits, pick **1–5 candidate files**, then read only the necessary sections:
    - definitions, call sites, config wiring, and tests
4) If still unclear:
    - run another retrieval pass with refined terms
    - only then fall back to grep/glob/list (when you have exact strings)

## Output expectations
- Always cite evidence: file paths + symbol names + what you observed.
- Avoid “repo-wide” claims unless you truly verified broadly.

## Anti-patterns
- Jumping straight to editing without any retrieval.
- Treating external/library behavior as repo facts (use the `context7-docs` skill for that).
