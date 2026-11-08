{
  config,
  lib,
  pkgs,
  hardening,
  ...
}:
let
  on = hardening.enforced "stig";
  rules = config.hardening.stig.rules;

  banner = import ./banner.nix;

  implemented = [
    "V-268083"
    "V-268088"
    "V-268089"
    "V-268137"
    "V-268142"
    "V-268143"
    "V-268157"
    "V-268159"
    "V-268176"
  ];
in
{
  options.hardening.stig.rules = {
    V-268083 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.text = lib.mkOption {
          type = lib.types.lines;
          default = banner;
          description = "Text that sshd shows before authentication.";
        };
      };
    };

    V-268142 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.interval = lib.mkOption {
          type = lib.types.ints.between 1 600;
          default = 600;
          description = "Seconds without client response before sshd sends a keepalive.";
        };
      };
    };
  };

  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    services.openssh = lib.mkMerge [
      (lib.mkIf (on "V-268159") { enable = true; })
      (lib.mkIf (on "V-268137") { settings.PermitRootLogin = "no"; })
      (lib.mkIf (on "V-268089") {
        settings.Ciphers = [
          "aes256-ctr"
          "aes192-ctr"
          "aes128-ctr"
        ];
      })
      (lib.mkIf (on "V-268157") {
        settings.Macs = [
          "hmac-sha2-512"
          "hmac-sha2-256"
        ];
      })
      (lib.mkIf (on "V-268176") { settings.UsePAM = true; })
      (lib.mkIf (on "V-268088") { settings.LogLevel = "VERBOSE"; })
      (lib.mkIf (on "V-268083") {
        settings.Banner = "${pkgs.writeText "ssh-banner" rules.V-268083.settings.text}";
      })
      (lib.mkIf (on "V-268142") { settings.ClientAliveInterval = rules.V-268142.settings.interval; })
      (lib.mkIf (on "V-268143") { settings.ClientAliveCountMax = 1; })
    ];
  };
}
