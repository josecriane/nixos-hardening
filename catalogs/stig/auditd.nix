{
  config,
  lib,
  hardening,
  ...
}:
let
  on = hardening.enforced "stig";
  rules = config.hardening.stig.rules;

  percentOrMebibytes = lib.types.either lib.types.ints.positive (lib.types.strMatching "[0-9]+%");

  actionOption =
    default: description:
    lib.mkOption {
      type = lib.types.str;
      inherit default description;
    };

  failureAction = lib.types.enum [
    "SYSLOG"
    "SINGLE"
    "HALT"
  ];

  implemented = [
    "V-268080"
    "V-268090"
    "V-268092"
    "V-268093"
    "V-268101"
    "V-268102"
    "V-268103"
    "V-268104"
    "V-268105"
    "V-268106"
    "V-268110"
    "V-268111"
    "V-268112"
    "V-268113"
    "V-268114"
    "V-268120"
  ];
in
{
  options.hardening.stig.rules = {
    V-268093 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.backlogLimit = lib.mkOption {
          type = lib.types.ints.u32;
          default = 8192;
          description = "Size of the kernel audit backlog queue. The rule requires 8192 or more.";
        };
      };
    };

    V-268101 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.action = actionOption "syslog" "Action of auditd when free space drops below space_left.";
      };
    };

    V-268102 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.action = actionOption "syslog" "Action of auditd when free space drops below admin_space_left.";
      };
    };

    V-268103 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.spaceLeft = lib.mkOption {
          type = percentOrMebibytes;
          default = "25%";
          description = "Free space of the audit log filesystem at which auditd takes the space_left action.";
        };
      };
    };

    V-268104 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.adminSpaceLeft = lib.mkOption {
          type = percentOrMebibytes;
          default = "10%";
          description = "Free space of the audit log filesystem at which auditd takes the admin_space_left action.";
        };
      };
    };

    V-268105 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.action = lib.mkOption {
          type = failureAction;
          default = "HALT";
          description = "Action of auditd when the audit storage volume is full.";
        };
      };
    };

    V-268106 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.action = lib.mkOption {
          type = failureAction;
          default = "HALT";
          description = "Action of auditd when an audit processing error occurs.";
        };
      };
    };
  };

  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    security.audit = lib.mkMerge [
      (lib.mkIf (on "V-268080") { enable = true; })
      (lib.mkIf (on "V-268092") { enable = true; })
      (lib.mkIf (on "V-268093") {
        enable = true;
        backlogLimit = rules.V-268093.settings.backlogLimit;
      })
    ];

    security.auditd = lib.mkMerge [
      (lib.mkIf (on "V-268080") { enable = true; })
      (lib.mkIf (on "V-268101") { settings.space_left_action = rules.V-268101.settings.action; })
      (lib.mkIf (on "V-268102") { settings.admin_space_left_action = rules.V-268102.settings.action; })
      (lib.mkIf (on "V-268103") { settings.space_left = rules.V-268103.settings.spaceLeft; })
      (lib.mkIf (on "V-268104") { settings.admin_space_left = rules.V-268104.settings.adminSpaceLeft; })
      (lib.mkIf (on "V-268105") { settings.disk_full_action = rules.V-268105.settings.action; })
      (lib.mkIf (on "V-268106") { settings.disk_error_action = rules.V-268106.settings.action; })
      (lib.mkIf (on "V-268110") { settings.log_group = "root"; })
    ];

    environment.systemPackages = lib.mkIf (on "V-268090") [ config.security.auditd.package ];

    environment.etc = lib.mkIf (on "V-268120") { "audit/auditd.conf".mode = "0444"; };

    systemd.tmpfiles.rules =
      lib.optional (on "V-268111" || on "V-268112" || on "V-268113") "d /var/log/audit 0700 root root -"
      ++ lib.optional (
        on "V-268111" || on "V-268112" || on "V-268114"
      ) "Z /var/log/audit/*.log 0600 root root -";
  };
}
