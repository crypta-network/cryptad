You are a refactoring agent working in a JVM codebase (Java/Kotlin). Your goal is to eliminate IntelliJ IDEA/Qodana inspection warnings for: “Non-distinguishable logging calls” (inspection ID: LoggingSimilarMessage).

What the inspection means:
Multiple SLF4J / Log4j2 logging statements within the same class have message templates that are too similar, making it hard to tell which call site emitted a given line.

Scope:
$ARGUMENTS

Hard requirements:
- Preserve behavior: do not change log levels, control flow, or side effects.
- Keep parameterized logging: do NOT introduce eager string concatenation.
- Keep the same arguments being logged unless you find an actual bug.
- Do not log secrets/credentials/tokens/PII. If any such data is currently logged, redact or remove it (and note it).
- Ensure placeholder/argument counts remain correct (SLF4J-style `{}`).
- Prefer stable, searchable templates (avoid embedding high-cardinality values into the template text itself).

Refactoring rules (apply in this order):
1) Preferred fix: make each flagged log statement’s *message template* clearly unique by encoding “what happened”.
    - Add a short, specific action + domain noun (e.g., “Created user”, “Failed to parse config”, “Retrying request”, “Cache refresh complete”).
    - If helpful, include a consistent context prefix like “[Class#method] …” or an “event=<NAME> …” token in the template.
    - Avoid generic templates repeated across methods such as “Message: {}”, “Result: {}”, “Processing {}”.

2) If multiple call sites are truly the same event and the only difference is which method emits it:
    - Still differentiate templates (preferred), OR
    - Consolidate into one log call only when it does NOT reduce diagnosability (be careful: moving the log can hide the original call site).

3) If a warning appears in generated code or code that must retain an exact template (contract with external tooling):
    - Add a local suppression comment for this inspection near the specific statement and explain why in a code comment.

Process:
- Find all LoggingSimilarMessage occurrences (use existing IDE/Qodana output if available; otherwise detect by scanning for logger/log statements with identical or highly similar first-argument string literals within the same class).
- Apply the refactoring rules.
- Run unit tests/build checks and ensure compilation succeeds.
- Produce a brief report:
    - Files changed
    - For each changed log statement: before template -> after template
    - Any suppressions added and the justification

Deliverable:
A set of commit-ready changes that removes the inspection warnings while keeping logging performant and semantically correct.
