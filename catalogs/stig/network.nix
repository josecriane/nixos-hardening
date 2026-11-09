{
  config,
  options,
  lib,
  hardening,
  ...
}:
let
  on = hardening.enforced "stig";
  rules = config.hardening.stig.rules;

  limitType = lib.types.submodule {
    options = {
      port = lib.mkOption {
        type = lib.types.port;
        description = "TCP destination port to limit.";
      };
      name = lib.mkOption {
        type = lib.types.str;
        description = "Name of the hashlimit table.";
      };
      above = lib.mkOption {
        type = lib.types.str;
        description = "Rate above which packets are refused, in iptables hashlimit syntax.";
      };
    };
  };

  limitCommand =
    limit:
    "ip46tables --append nixos-fw --protocol tcp --dport ${toString limit.port} --match hashlimit --hashlimit-name ${limit.name} --hashlimit-mode srcip --hashlimit-above ${limit.above} --jump nixos-fw-refuse";

  implemented = [
    "V-268078"
    "V-268141"
    "V-268146"
    "V-268147"
    "V-268149"
    "V-268150"
    "V-268151"
    "V-268158"
  ];
in
{
  options.hardening.stig.rules = {
    V-268149 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.servers = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = options.networking.timeServers.default;
          description = "NTP servers of the organization.";
        };
      };
    };

    V-268158 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.limits = lib.mkOption {
          type = lib.types.listOf limitType;
          default = [
            {
              port = 22;
              name = "stig_byte_limit";
              above = "1000000b/second";
            }
            {
              port = 80;
              name = "stig_conn_limit";
              above = "1000/minute";
            }
            {
              port = 443;
              name = "stig_conn_limit";
              above = "1000/minute";
            }
          ];
          description = "Per-source rate limits applied to TCP ports by the firewall.";
        };
      };
    };
  };

  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    networking = lib.mkMerge [
      (lib.mkIf (on "V-268078") { firewall.enable = true; })
      (lib.mkIf (on "V-268158") {
        firewall.enable = true;
        firewall.extraCommands = lib.concatMapStringsSep "\n" limitCommand rules.V-268158.settings.limits;
      })
      (lib.mkIf (on "V-268146") { wireless.enable = false; })
      (lib.mkIf (on "V-268149") { timeServers = rules.V-268149.settings.servers; })
    ];

    boot.kernel.sysctl = lib.mkIf (on "V-268141") { "net.ipv4.tcp_syncookies" = 1; };

    hardware.bluetooth.enable = lib.mkIf (on "V-268147") false;

    services.timesyncd = lib.mkMerge [
      (lib.mkIf (on "V-268151") { enable = true; })
      (lib.mkIf (on "V-268149") { servers = rules.V-268149.settings.servers; })
      (lib.mkIf (on "V-268150") { settings.Time.PollIntervalMaxSec = 60; })
    ];
  };
}
