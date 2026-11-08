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

  faillock = rules.V-268081.settings;
  faillockArgs = {
    inherit (faillock) deny;
    fail_interval = faillock.interval;
    unlock_time = 0;
    audit = true;
  };

  lock = rules.V-268086.settings;
  lockSeconds = lock.minutes * 60;
  gnomeLock = on "V-268086" && lock.method == "gnome";
  swayidleLock = on "V-268086" && lock.method == "swayidle";

  implemented = [
    "V-268081"
    "V-268082"
    "V-268084"
    "V-268085"
    "V-268086"
    "V-268087"
    "V-268138"
    "V-268155"
    "V-268156"
    "V-268171"
    "V-268172"
    "V-268181"
  ];
in
{
  options.hardening.stig.rules = {
    V-268081 = lib.mkOption {
      type = lib.types.submodule {
        options.settings = {
          deny = lib.mkOption {
            type = lib.types.ints.between 1 3;
            default = 3;
            description = "Consecutive failed logons that lock the account.";
          };
          interval = lib.mkOption {
            type = lib.types.ints.between 1 900;
            default = 900;
            description = "Seconds in which the failed logons are counted.";
          };
          services = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [
              "login"
              "sshd"
            ];
            description = "PAM services that enforce the lockout.";
          };
        };
      };
    };

    V-268082 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.text = lib.mkOption {
          type = lib.types.lines;
          default = banner;
          description = "Text that getty shows before the console logon prompt.";
        };
      };
    };

    V-268084 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.text = lib.mkOption {
          type = lib.types.str;
          default = banner;
          description = "Text that GDM shows on the graphical logon screen.";
        };
      };
    };

    V-268085 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.maxLogins = lib.mkOption {
          type = lib.types.ints.between 1 10;
          default = 10;
          description = "Concurrent sessions allowed per account.";
        };
      };
    };

    V-268086 = lib.mkOption {
      type = lib.types.submodule {
        options.settings = {
          minutes = lib.mkOption {
            type = lib.types.ints.between 1 10;
            default = 10;
            description = "Minutes of inactivity before the graphical session locks.";
          };

          method = lib.mkOption {
            type = lib.types.enum [
              "gnome"
              "swayidle"
            ];
            default = "gnome";
            description = "gnome locks through dconf idle-delay and xautolock. swayidle runs a user service for Wayland compositors without an idle lock, such as niri.";
          };

          lockCommand = lib.mkOption {
            type = lib.types.str;
            default = "${lib.getExe pkgs.swaylock} -f";
            defaultText = lib.literalExpression "${lib.getExe pkgs.swaylock} -f";
            description = "Command that swayidle runs to lock the session.";
          };
        };
      };
    };

    V-268171 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.seconds = lib.mkOption {
          type = lib.types.ints.between 4 3600;
          default = 4;
          description = "Seconds of delay after a failed logon.";
        };
      };
    };
  };

  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    assertions = lib.optionals (on "V-268172") [
      {
        assertion = config.services.getty.autologinUser == null;
        message = "V-268172: services.getty.autologinUser must be null.";
      }
      {
        assertion = !config.services.displayManager.autoLogin.enable;
        message = "V-268172: services.displayManager.autoLogin.enable must be false.";
      }
    ];

    security.pam = {
      services = lib.mkMerge [
        (lib.mkIf swayidleLock { swaylock = { }; })
        (lib.mkIf (on "V-268171") {
          login.failDelay = {
            enable = true;
            delay = rules.V-268171.settings.seconds * 1000000;
          };
        })
        (lib.mkIf (on "V-268081") (
          lib.genAttrs faillock.services (
            service:
            let
              unix = config.security.pam.services.${service}.rules.auth.unix.order;
              module = "${config.security.pam.package}/lib/security/pam_faillock.so";
            in
            {
              rules = {
                auth = {
                  faillock-preauth = {
                    order = unix - 10;
                    control = "required";
                    modulePath = module;
                    settings = faillockArgs // {
                      preauth = true;
                      silent = true;
                      even_deny_root = true;
                    };
                  };
                  faillock-authfail = {
                    order = unix + 10;
                    control = "[default=die]";
                    modulePath = module;
                    settings = faillockArgs // {
                      authfail = true;
                      even_deny_root = true;
                    };
                  };
                  faillock-authsucc = {
                    order = unix + 20;
                    control = "sufficient";
                    modulePath = module;
                    settings.authsucc = true;
                  };
                };
                account.faillock = {
                  order = config.security.pam.services.${service}.rules.account.unix.order - 10;
                  control = "required";
                  modulePath = module;
                };
              };
            }
          )
        ))
      ];

      loginLimits = lib.mkIf (on "V-268085") [
        {
          domain = "*";
          item = "maxlogins";
          type = "hard";
          value = toString rules.V-268085.settings.maxLogins;
        }
      ];
    };

    services = {
      getty.helpLine = lib.mkIf (on "V-268082") rules.V-268082.settings.text;

      displayManager.gdm.banner = lib.mkIf (on "V-268084") rules.V-268084.settings.text;

      logind.settings.Login = lib.mkIf (on "V-268086") {
        IdleAction = "lock";
        IdleActionSec = toString lockSeconds;
      };

      xserver.xautolock = lib.mkIf gnomeLock {
        enable = true;
        time = lock.minutes;
        locker = "${lib.getExe' config.systemd.package "loginctl"} lock-session";
      };
    };

    systemd.user.services.hardening-idle-lock = lib.mkIf swayidleLock {
      description = "Session lock after ${toString lock.minutes} minutes of inactivity";
      partOf = [ "graphical-session.target" ];
      after = [ "graphical-session.target" ];
      wantedBy = [ "graphical-session.target" ];
      serviceConfig = {
        ExecStart = lib.concatStringsSep " " [
          "${lib.getExe pkgs.swayidle} -w"
          "timeout ${toString lockSeconds} ${lib.escapeShellArg lock.lockCommand}"
          "lock ${lib.escapeShellArg lock.lockCommand}"
        ];
        Restart = "on-failure";
      };
    };

    security = {
      sudo = lib.mkMerge [
        (lib.mkIf (on "V-268155") { extraConfig = "Defaults timestamp_timeout=0"; })
        (lib.mkIf (on "V-268156") { wheelNeedsPassword = true; })
      ];

      loginDefs.settings = lib.mkMerge [
        (lib.mkIf (on "V-268171") { FAIL_DELAY = rules.V-268171.settings.seconds; })
        (lib.mkIf (on "V-268181") { UMASK = "077"; })
      ];
    };

    programs.dconf.profiles.user.databases = lib.mkIf gnomeLock (
      lib.mkBefore [
        {
          settings."org/gnome/desktop/session".idle-delay = lib.gvariant.mkUint32 lockSeconds;
          locks = [ "org/gnome/desktop/session/idle-delay" ];
        }
      ]
    );

    environment.systemPackages = lib.mkIf (on "V-268087") [ pkgs.vlock ];

    users.mutableUsers = lib.mkIf (on "V-268138") false;
  };
}
