{
  description = "Pwnproxy";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mitmproxy.overrideAttrs (
            finalAttrs: prevAttrs: {
              pname = "pwnproxy";
              version = "0.1.0";
              src = ./.;
            }
          );
        });
    };
}
