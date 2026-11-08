{
  config,
  lib,
  pkgs,
  utils,
  hardening,
  ...
}:
let
  on = hardening.enforced "stig";
  rules = config.hardening.stig.rules;

  passwordServices = [
    "passwd"
    "chpasswd"
    "sudo"
  ];

  pwqualityLine = id: line: lib.optional (on id) line;

  pwqualityLines = lib.concatLists [
    (pwqualityLine "V-268126" "ucredit=-1")
    (pwqualityLine "V-268127" "lcredit=-1")
    (pwqualityLine "V-268128" "dcredit=-1")
    (pwqualityLine "V-268129" "difok=${toString rules.V-268129.settings.difok}")
    (pwqualityLine "V-268134" "minlen=${toString rules.V-268134.settings.minlen}")
    (pwqualityLine "V-268145" "ocredit=-1")
    (pwqualityLine "V-268169" "dictcheck=1")
  ];

  implemented = [
    "V-268126"
    "V-268127"
    "V-268128"
    "V-268129"
    "V-268130"
    "V-268132"
    "V-268133"
    "V-268134"
    "V-268135"
    "V-268145"
    "V-268169"
    "V-268170"
    "V-268174"
    "V-268175"
  ];

  duplicateUids =
    let
      uids = lib.filter (uid: uid != null) (lib.mapAttrsToList (_: user: user.uid) config.users.users);
    in
    lib.unique (lib.filter (uid: lib.count (other: other == uid) uids > 1) uids);
in
{
  options.hardening.stig.rules = {
    V-268129 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.difok = lib.mkOption {
          type = lib.types.ints.positive;
          default = 8;
          description = "Number of characters that must differ from the old password.";
        };
      };
    };

    V-268133 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.maxDays = lib.mkOption {
          type = lib.types.ints.positive;
          default = 180;
          description = "Maximum password lifetime in days.";
        };
      };
    };

    V-268134 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.minlen = lib.mkOption {
          type = lib.types.ints.positive;
          default = 15;
          description = "Minimum password length.";
        };
      };
    };

    V-268174 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.days = lib.mkOption {
          type = lib.types.ints.between 0 35;
          default = 35;
          description = "Days of inactivity after which new accounts are disabled.";
        };
      };
    };
  };

  config = lib.mkMerge [
    {
      hardening.stig.rules = lib.genAttrs implemented (_: {
        implemented = true;
        status = lib.mkDefault "enforced";
      });

      environment.etc."security/pwquality.conf" = lib.mkIf (pwqualityLines != [ ]) {
        text = lib.concatLines pwqualityLines;
      };

      security.loginDefs.settings = lib.mkMerge [
        (lib.mkIf (on "V-268130") { ENCRYPT_METHOD = "SHA512"; })
        (lib.mkIf (on "V-268175") { ENCRYPT_METHOD = "SHA512"; })
        (lib.mkIf (on "V-268132") { PASS_MIN_DAYS = 1; })
        (lib.mkIf (on "V-268133") { PASS_MAX_DAYS = rules.V-268133.settings.maxDays; })
      ];

      assertions = lib.optional (on "V-268135") {
        assertion = duplicateUids == [ ];
        message = "V-268135: users.users declares duplicate UIDs: ${toString duplicateUids}.";
      };
    }

    (lib.mkIf (on "V-268170") {
      security.pam.services = lib.genAttrs passwordServices (_: {
        rules.password.pwquality = {
          order = 10000;
          control = "requisite";
          modulePath = "${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so";
        };
      });
    })

    (lib.mkIf (on "V-268175") {
      security.pam.services = lib.genAttrs passwordServices (_: {
        rules.password.unix.settings.sha512 = true;
      });
    })

    (lib.mkIf (on "V-268174") {
      environment.etc."default/useradd".source = lib.mkForce (
        pkgs.writeText "useradd" ''
          GROUP=100
          HOME=${config.users.defaultUserHome}
          SHELL=${utils.toShellPath config.users.defaultUserShell}
          INACTIVE=${toString rules.V-268174.settings.days}
        ''
      );
    })
  ];
}
