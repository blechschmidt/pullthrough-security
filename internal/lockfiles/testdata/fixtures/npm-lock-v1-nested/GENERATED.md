# npm-lock-v1-nested

Hand-written in npm 6's lockfileVersion 1 layout, for what the generated npm-lock-v1 fixture does
not have: a nested `dependencies` tree (debug's own ms 2.0.0 next to the top-level ms 2.1.3), a
bundled dependency, a `file:` dependency, plus npm 6's spellings of an alias (`npm:…`) and of a
GitHub dependency (`github:…#<commit>`). pack-with-bundle reuses left-pad's integrity value.
