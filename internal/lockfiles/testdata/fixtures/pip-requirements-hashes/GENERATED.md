# pip-requirements-hashes

Generated 2026-11-12 on the host (no container) by a real tool. Neither file
was edited by hand afterwards.

- Tool: uv 0.11.14 (x86_64-unknown-linux-gnu), `uv pip compile` subcommand.
- Target interpreter: the system CPython 3.12.3 (`/usr/bin/python3.12`). It is
  selected with the `UV_PYTHON` environment variable so that the command
  recorded in the file header stays exactly the one below. The uv cache was
  in a scratch directory.
- Commands (run in a directory that holds only `requirements.in`):

      printf 'requests==2.32.3\npackaging==24.1\n' > requirements.in
      UV_PYTHON=/usr/bin/python3.12 UV_CACHE_DIR=<scratch>/uv-cache \
        uv pip compile --generate-hashes --emit-index-url requirements.in -o requirements.txt

Notable features of requirements.txt:
- The header comment records the generating command, followed by an `--index-url https://pypi.org/simple` line (from `--emit-index-url`).
- 6 `==` pins: certifi 2026.10.23, charset-normalizer 3.5.2, idna 3.20, packaging 24.1, requests 2.32.3, urllib3 2.8.0.
- After each pin come `\`-continued `--hash=sha256:` lines, one per file of that release on PyPI: charset-normalizer has 172 hashes, every other package has 2 (wheel + sdist).
- Direct requirements are annotated `# via -r requirements.in` (packaging, requests). Transitive ones are annotated `# via requests` (certifi, charset-normalizer, idna, urllib3).
- There are no environment markers, extras, git/URL requirements or dev/main split. The resolution is for one interpreter (CPython 3.12), not universal.
