git cherry pick 

$1

from upstream's next branch into current local branch. note that
1. package name of current local branch has been renamed from freenet.* to network.crypta.*
2. local branch's source code has been reformatted
make sure to:
1. solve any merge conflicts. 
2. After cherry-picks, run Gradle test and fix any test failures
3. After fixing all test failures, run Gradle’s spotlessApply task to reformat the modified files. 
4. Git commit all uncommitted changes

Do a final code review, indicate must fix issues before release
