Run gradle sonarlintFile on $2, and resolve all $1 issues in that file (issue list can be found in build/reports/sonarLint/sonarlintFile/sonarlintFile.xml). Use websearch to understand what the issue type $1 refers to.

NEVER suppress any issues.

After all issues fixed, run full test suite and make sure no failures.