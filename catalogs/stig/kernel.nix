{ lib, hardening, ... }:
let
  on = hardening.enforced "stig";

  implemented = [
    "V-268160"
    "V-268161"
    "V-268168"
    "V-268173"
  ];
in
{
  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    boot.kernel.sysctl = lib.mkMerge [
      (lib.mkIf (on "V-268160") { "kernel.kptr_restrict" = 1; })
      (lib.mkIf (on "V-268161") { "kernel.randomize_va_space" = 2; })
    ];

    boot.kernelParams = lib.mkIf (on "V-268168") [ "fips=1" ];

    security.apparmor.enable = lib.mkIf (on "V-268173") true;
  };
}
