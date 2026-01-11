---
description: Create a Github PR
---

Go through git commit history of current branch, read the diffs of source code, and create a Github PR into develop branch using mcp server. If there're any files that require git commit, run gradle spotlessApply first, and use $git-commit-helper skill to commit and push. If you're currently on develop or main branch, create a new feature or bugfix branch before you commit anything.