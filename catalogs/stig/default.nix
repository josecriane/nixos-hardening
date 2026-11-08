{ lib, ... }:
let
  hardeningLib = import ../../lib { inherit lib; };
in
{
  imports = [
    (hardeningLib.mkCatalog {
      name = "stig";
      catalog = lib.importJSON ./anduril-nixos.json;
      defaultProfile = "server";
      profiles = import ./profiles.nix;
      groups = import ./groups.nix;
      areas = [
        ./ssh.nix
        ./network.nix
        ./kernel.nix
        ./auditd.nix
        ./audit-rules.nix
        ./logging.nix
        ./login.nix
        ./passwords.nix
        ./pki.nix
        ./system.nix
      ];
    })
  ];
}
