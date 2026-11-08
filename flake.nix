{
  description = "Catalog-driven hardening for NixOS";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      testSystem = "x86_64-linux";
    in
    {
      lib = import ./lib { inherit lib; };

      nixosModules = {
        hardening = import ./modules;
        stig = import ./catalogs/stig;
        default = {
          imports = [
            self.nixosModules.hardening
            self.nixosModules.stig
          ];
        };
      };

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);

      devShells = forAllSystems (system: {
        default = (pkgsFor system).mkShellNoCC {
          packages = with pkgsFor system; [
            nixfmt
            deadnix
            statix
          ];
        };
      });

      checks.${testSystem} = {
        eval = (pkgsFor testSystem).writeText "stig-eval-report" (
          import ./tests/eval.nix {
            inherit nixpkgs;
            module = self.nixosModules.default;
          }
        );
      }
      // lib.mapAttrs' (
        area: _:
        lib.nameValuePair "stig-${area}" (
          (pkgsFor testSystem).testers.runNixOSTest (
            import ./tests/stig/${area}.nix {
              module = {
                imports = [
                  self.nixosModules.default
                  ./tests/stig/base.nix
                ];
              };
            }
          )
        )
      ) (import ./tests/stig);
    };
}
