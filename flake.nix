{
  description = "Pwnproxy";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { nixpkgs, ... }: {

    packages.x86_64-linux.default =
      let
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
      in
      pkgs.mitmproxy.overrideAttrs (
        finalAttrs: prevAttrs: {
          pname = "pwnproxy";
          version = "0.1.0";
          src = ./.;
        }
      );
  };
}
