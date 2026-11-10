# Git test-set fixture

Clones `octocat/Hello-World` (a tiny, stable public repository) through the
proxy's Git HTTPS smart-protocol backend. The fetch exercises the
`info/refs?service=git-upload-pack` advertisement and the `git-upload-pack`
pack negotiation, both of which route through `/v1/git/<repo>`.
