---
name: gh-address-comments
description: Help address review/issue comments on the open GitHub PR for the current branch using gh CLI; verify gh auth first and prompt the user to authenticate if not logged in.
metadata:
  short-description: Address comments in a GitHub PR review
---

# PR Comment Handler

Guide to find the open PR for the current branch and address its comments with gh CLI. Run all `gh` commands with elevated network access.

Prereq: ensure `gh` is authenticated for the `leumor` account. This repository's GitHub review,
issue, PR, and CI operations must always use `leumor`, even when another account is active in
`gh`. Verify access with `gh auth token --user leumor >/dev/null`. If it fails, ask the user to run
`gh auth login` for `leumor` before proceeding.

For every `gh` command in this workflow, inject the account token explicitly:

```bash
GH_TOKEN="$(gh auth token --user leumor)" gh <command>
```

Do not rely on the active/default `gh` account. If a GitHub MCP or plugin tool is used for a write
operation, verify the resulting comment/review/PR author is `leumor`; otherwise redo the operation
with the explicit `leumor` token.

## 1) Inspect comments needing attention
- Run scripts/fetch_comments.py which will print out all the comments and review threads on the PR

## 2) Ask the user for clarification
- Number all the review threads and comments and provide a short summary of what would be required to apply a fix for it
- Ask the user which numbered comments should be addressed

## 3) If user chooses comments
- Apply fixes for the selected comments

Notes:
- If gh hits auth/rate issues mid-run, prompt the user to re-authenticate as `leumor` with
  `gh auth login`, then retry with `GH_TOKEN="$(gh auth token --user leumor)"`.
