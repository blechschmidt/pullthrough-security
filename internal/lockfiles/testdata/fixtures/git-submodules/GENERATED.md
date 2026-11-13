# git-submodules

Generated 2026-11-12 with git 2.43.0 on the host, in an empty scratch directory, with no user or
system git configuration (`HOME=<scratch>/home`, `GIT_CONFIG_NOSYSTEM=1`):

    git init -b main
    git remote add origin https://github.com/octocat/linguist.git
    git submodule add https://github.com/octocat/Hello-World.git vendor-hello
    git submodule add --name lib-spoon https://github.com/octocat/Spoon-Knife.git libs/spoon
    git -C libs/spoon checkout --quiet bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f
    git add libs/spoon
    git submodule add ../test-repo1.git rel/test-repo1
    git submodule add -b main https://github.com/octocat/Spoon-Knife.git tracking/spoon
    git commit --quiet -m "Add submodules"
    git ls-tree -r HEAD | awk '$1 == "160000"' > <scratch>/GITLINKS

`.gitmodules` is the file git wrote (byte-identical to `git show HEAD:.gitmodules`). `GITLINKS` is the
raw output of the last command. The submodule checkouts and `.git` are not included. The `origin`
remote is never contacted; it only gives the relative URL a base.

Notable features:

- `.gitmodules` is git-config syntax: one `[submodule "<name>"]` section per submodule, keys indented
  with one tab, LF line endings, sections in the order the submodules were added.
- The section name is not always the path: `lib-spoon` has `path = libs/spoon` (from `--name`). For the
  other three, git used the path as the name, slashes included (`rel/test-repo1`, `tracking/spoon`).
- `rel/test-repo1` has the relative `url = ../test-repo1.git`, stored as typed. git resolved it against
  the superproject's `origin` (https://github.com/octocat/linguist.git) to
  https://github.com/octocat/test-repo1.git for the clone; the resolved URL is only in `.git/config`.
- `tracking/spoon` has `branch = main` (from `-b main`); the other sections have no `branch` key.
- `lib-spoon` and `tracking/spoon` have the same URL, https://github.com/octocat/Spoon-Knife.git, but
  pin different commits.
- `.gitmodules` holds no commits. The pins are the gitlinks: GITLINKS lines are
  `160000 commit <40-hex sha>`, a TAB, then the path; sorted by path, not in `.gitmodules` order.
- Pinned commits (branch tips as of 2026-11-12):
  - vendor-hello 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d, the tip of Hello-World's `master`.
  - libs/spoon bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f, the parent of the Spoon-Knife `main` tip,
    checked out by hand before `git add`.
  - rel/test-repo1 57523742631876181d95bc268e09fb3fd1a4d85e, the tip of test-repo1's default branch
    `gh-pages`, also tagged `1.0` and `2.0`.
  - tracking/spoon d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9, the tip of Spoon-Knife's `main`.
