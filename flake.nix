{
  description = "Media audit tool for Arr-managed libraries";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = rec {
          auditarr = pkgs.buildGoModule rec {
            pname = "auditarr";
            version = "0.1.0";
            
            src = ./.;
            
            vendorHash = null;
            
            meta = with pkgs.lib; {
              description = "Non-destructive audit tool for Arr media libraries";
              license = licenses.mit;
              mainProgram = "auditarr";
            };
          };
          default = auditarr;
        };
        
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.auditarr;
        };
        
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ go golangci-lint ];
        };
      }) // {
        nixosModules.default = import ./nix/module.nix;
      };
}
