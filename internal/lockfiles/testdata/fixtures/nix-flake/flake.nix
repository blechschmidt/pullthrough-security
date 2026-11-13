{
  description = "flake.lock fixture";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    flake-utils.url = "github:numtide/flake-utils";

    home-manager = {
      url = "github:nix-community/home-manager/release-24.11";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-compat = {
      url = "git+https://github.com/edolstra/flake-compat?ref=refs/tags/v1.1.0";
      flake = false;
    };

    flake-utils-v1.url = "https://github.com/numtide/flake-utils/archive/refs/tags/v1.0.0.tar.gz";
  };

  outputs = { self, ... }: { };
}
