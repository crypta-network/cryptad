# Documentation style guide

This document defines the rules and conventions for Cryptad repo documentation in `README.md`, `docs/**/*.md`, and root markdown files.

Prerequisite: read `writing-guide.md` first.

## Document structure

### Start with the task or definition

Open with one sentence that tells the reader what this page covers.

Good:

> This document describes Cryptad's standard branching and release workflow.

Also good:

> Use this guide to build the Cryptad JAR and run the test suite with the Gradle wrapper.

Avoid openings that spend a paragraph warming up before naming the topic.

### Put prerequisites and scope up front

State required tools, privileges, operating systems, or branch assumptions near the top.

### One task or concept per section

Do not mix release policy, installer behavior, and local development commands in the same section unless the connection is the point.

### Progressive disclosure

Move from the common path to the special case:

1. Quick path
2. Variations by platform or role
3. Edge cases and troubleshooting

### Short paragraphs

Keep paragraphs to one to three sentences unless a longer explanation is necessary for safety or compatibility.

### Use tables for matrices

Use tables when comparing platforms, package formats, or command variants.

## Commands must be reproducible

- Use `python3` for Python commands.
- Use the Gradle wrapper: `./gradlew`.
- Do not document `--no-daemon`, `--parallel`, or ad-hoc JVM flags because the repo explicitly forbids them.
- If a command differs by platform, split the examples clearly instead of squeezing variants into one line.

## Cross-referencing

- Link to the exact local file when another repo document is the source of truth.
- Prefer a brief pointer over duplicating policy text.
- Mark archival material such as `docs/legacy/*` as historical when you reference it.

## What good Cryptad docs look like

- They tell the reader what to do first.
- They name the exact file, branch, tag, or service involved.
- They make operator-facing consequences obvious.
- They avoid stale or conflicting release-note copies outside the canonical changelog artifacts used by the release workflow.

## Evaluation checklist

- [ ] The opening says what the page is for.
- [ ] Prerequisites and scope are near the top.
- [ ] Commands follow repo conventions and are copyable.
- [ ] Platform-specific differences are explicit.
- [ ] Links point to the repo's actual source-of-truth files.
