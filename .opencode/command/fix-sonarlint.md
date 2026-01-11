Fix all problems in file $1. After each fix cycle, run `./gradlew test`. Iterate until tests pass and no SonarLint problems remain.

## Constraints
- Do **not** rename packages.
- Do **not** suppress warnings. Fix root causes with minimal changes that do not alter behavior.
- Do **not** change or add features.
- Do **not** use unnecessary fully qualified names. Instead, use import.
- Other MCP servers you may use:
  - **context7** for exact library docs: `resolve-library-id` → `get-library-docs` for the precise version.
  - **exa** for web/code search of errors, API usage, and examples. Do **not** use exa to list files.
- Use web search via **exa** if stuck on any problem.

Procedure:
1) Run `./gradlew test` in the project root (limit to file $1 related tests). Parse the failure output to collect file paths and lines.
2) Run gradle sonarlintFile task, analysis problems in build/reports/sonarLint/sonarlintFile/sonarlintFile.xml, and fix them. Use context7, eva or web search to understand what the problem codes refer to.
3) Repeat steps 1–2 until green and no problems remain.
4) Run full test suite.
5) When APIs are unclear:
   - context7-mcp: resolve-library-id → get-library-docs for the exact version.
   - exa: search for the stack trace or API and retrieve authoritative references.
6) Do not rename package

## Warnings to be ignored
- Rename this package name to match the regular expression '^[a-z_]+(\.[a-z_][a-z0-9_]*)*$'. (java:S120)
- java:S107

## Warnings to be ignored for Unit Test files
- Rename this method name to match the regular expression '^[a-z][a-zA-Z0-9]*$'. (java:S100)
