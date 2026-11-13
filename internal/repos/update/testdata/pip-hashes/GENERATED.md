# pip-hashes

Generated 2026-11-13 by real uv 0.11.14 on the host (scratch `UV_CACHE_DIR`). Unedited tool output.

    uv pip compile --universal --python-version 3.9 --generate-hashes requirements.in -o requirements.txt

- before/requirements.txt: requirements.in was `requests[socks]==2.32.3`, `idna==3.7`,
  `click==8.1.7`, `colorama==0.4.5`.
- after/requirements.txt: the same command with `idna==3.8` and `colorama==0.4.6` in requirements.in.
  It differs from before/requirements.txt in the idna and colorama pins and their `--hash` lines only.

pip-compile layout: `name==version \` then one `    --hash=sha256:… \` line per distribution file
(charset-normalizer has 172), then `    # via …` comments. A universal resolution: urllib3 is pinned
twice, `urllib3==2.6.3 ; python_full_version < '3.10'` and `urllib3==2.8.0 ; python_full_version >= '3.10'`.
