{
  # Minimal flake that builds one real package (GNU hello) from nixpkgs. With
  # the proxy configured as a substituter, `nix build` fetches the store path's
  # signed narinfo and its content-addressed NAR archive through the proxy:
  #
  #   nix build \
  #     --substituters https://proxy.example.com/v1/nix \
  #     --trusted-public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
  #     --option require-sigs true
  #
  # The proxy verifies each narinfo's ed25519 signature against the configured
  # trusted key and each NAR's SHA-256 against the content address in its URL
  # before caching or serving it.
  description = "pullthrough nix binary-cache pull-through test build";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = pkgs.hello;
    };
}
