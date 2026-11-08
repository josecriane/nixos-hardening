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

  implemented = [
    "V-268121"
    "V-268122"
    "V-268123"
    "V-268131"
    "V-268139"
    "V-268140"
    "V-268144"
    "V-268152"
    "V-268153"
    "V-268154"
    "V-268180"
  ];

  telnetPackages = [
    "libtelnet"
    "busybox"
    "inetutils"
    "telnet"
  ];

  auditDirectoryAttributes = {
    mode = if on "V-268121" then "0755" else "-";
    user = if on "V-268122" then "root" else "-";
    group = if on "V-268123" then "root" else "-";
  };

  aideConfig = pkgs.writeText "aide.conf" rules.V-268153.settings.config;

  aideCheck = pkgs.writeShellApplication {
    name = "aide-check";
    runtimeInputs = [
      pkgs.aide
      pkgs.mailutils
    ];
    text = ''
      database=/var/lib/aide/aide.db
      if [ ! -e "$database" ]; then
        aide -c /etc/aide.conf --init
        mv "$database.new" "$database"
      fi
      status=0
      output=$(aide -c /etc/aide.conf --check) || status=$?
      echo "$output"
      if [ "$status" -ne 0 ]; then
        echo "$output" | mail -s "aide integrity check run for ${config.networking.hostName}" ${lib.escapeShellArg rules.V-268153.settings.recipient}
      fi
      exit "$status"
    '';
  };
in
{
  options.hardening.stig.rules = {
    V-268139.settings.rules = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      description = "USBGuard rules in usbguard-rules.conf syntax. When null, the daemon reads the rules file on disk and blocks every other device.";
    };

    V-268140.settings.directories = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [
        "/tmp"
        "/var/tmp"
        "/dev/shm"
      ];
      description = "World-writable directories that get the sticky bit.";
    };

    V-268152.settings.allowedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "root"
        "@wheel"
      ];
      description = "Users and groups, as \"@group\", that can use the Nix daemon.";
    };

    V-268153.settings = {
      config = lib.mkOption {
        type = lib.types.lines;
        default = ''
          database_in=file:/var/lib/aide/aide.db
          database_out=file:/var/lib/aide/aide.db.new
          database_new=file:/var/lib/aide/aide.db.new
          report_url=stdout
          NORMAL = p+i+n+u+g+s+m+sha256
          /etc NORMAL
          !/etc/mtab
          !/etc/resolv.conf
        '';
        description = "Content of /etc/aide.conf.";
      };

      schedule = lib.mkOption {
        type = lib.types.str;
        default = "Sun *-*-* 00:00:00";
        description = "systemd calendar expression for the integrity check.";
      };

      recipient = lib.mkOption {
        type = lib.types.str;
        default = "root";
        description = "Mail address that receives the report when the check finds changes.";
      };
    };

    V-268180.settings.supportedReleases = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "26.05"
        "26.11"
      ];
      description = "NixOS releases that still receive security updates.";
    };
  };

  config = lib.mkMerge [
    {
      hardening.stig.rules = lib.genAttrs implemented (_: {
        implemented = true;
        status = lib.mkDefault "enforced";
      });
    }

    {
      assertions = [
        {
          assertion =
            !(on "V-268131")
            || !(lib.any (
              package: lib.elem (lib.getName package) telnetPackages
            ) config.environment.systemPackages);
          message = "V-268131: environment.systemPackages must not contain ${lib.concatStringsSep ", " telnetPackages}.";
        }
        {
          assertion = !(on "V-268144") || config.boot.initrd.luks.devices != { };
          message = "V-268144: boot.initrd.luks.devices must declare the encrypted devices.";
        }
        {
          assertion =
            !(on "V-268180") || lib.elem config.system.nixos.release rules.V-268180.settings.supportedReleases;
          message = "V-268180: NixOS ${config.system.nixos.release} is not in ${lib.concatStringsSep ", " rules.V-268180.settings.supportedReleases}.";
        }
      ];
    }

    (lib.mkIf (on "V-268139") {
      services.usbguard = {
        enable = true;
        rules = rules.V-268139.settings.rules;
      };
    })

    (lib.mkIf (on "V-268140") {
      systemd.tmpfiles.rules = map (
        directory: "z ${directory} 1777 - - -"
      ) rules.V-268140.settings.directories;
    })

    (lib.mkIf (on "V-268152") {
      nix.settings.allowed-users = rules.V-268152.settings.allowedUsers;
    })

    (lib.mkIf (on "V-268154") {
      nix.settings.require-sigs = true;
    })

    (lib.mkIf (on "V-268153") {
      environment.systemPackages = [ pkgs.aide ];
      environment.etc."aide.conf" = {
        source = aideConfig;
        mode = "0444";
      };
      systemd.services.aide = {
        description = "AIDE integrity check";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = lib.getExe aideCheck;
          StateDirectory = "aide";
        };
      };
      systemd.timers.aide = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = rules.V-268153.settings.schedule;
          Persistent = true;
        };
      };
    })

    (lib.mkIf (on "V-268121" || on "V-268122" || on "V-268123") {
      systemd.tmpfiles.rules = [
        "z /etc/audit ${auditDirectoryAttributes.mode} ${auditDirectoryAttributes.user} ${auditDirectoryAttributes.group} -"
      ];
    })
  ];
}
