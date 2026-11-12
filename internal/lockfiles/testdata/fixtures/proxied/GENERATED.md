# proxied

Hand-written lock files resolved through the pull-through proxy, as its clients write them: through
a personal cache link (`https://proxy.example.com/u/<token>/v1/<upstream>/…`, the token here is
made up and fails the checksum), through TLS interception (`https://registry.npmjs.org/_pullthrough/v1/npm/…`),
through the plain mount under the public URL, and through a personal link on a host the test
configuration does not know (`cache.internal.example`). The golden test maps them with a proxy whose
public URL is https://proxy.example.com and checks that the token appears nowhere in the output.
`web/yarn.lock` resolves lodash through the "pypi" upstream: the parser keeps the dependency and
warns that the upstream is of another type.
