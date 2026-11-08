{ nixpkgs, module }:
let
  inherit (nixpkgs) lib;

  base = {
    fileSystems."/" = {
      device = "/dev/null";
      fsType = "ext4";
    };
    boot.loader.grub.enable = false;
    system.stateVersion = "25.11";
    users.users.admin = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      hashedPassword = "$6$rounds=65536$evaltest$3S6pnVuEy1EjIdt7OuvRTO2q3NL7bK4A9KzUiNnxjEqvtiGUv8ObXh5eTmmtWTJxJWNoJhVYsjj1vwuWBfqOI/";
    };
  };

  site = {
    hardening.stig.rules = {
      V-268108.settings.url = "https://logs.example.org:19532";
      V-268109.settings.trustedCertificateFile = "/etc/ssl/certs/logs-ca.pem";
      V-268124.settings.caBundle = "/etc/ssl/certs/site-ca.pem";
      V-268178.settings.domains.example = {
        id_provider = "ldap";
        ldap_uri = "ldaps://ldap.example.org";
      };
      V-268144 = {
        status = "exception";
        reason = "Evaluation test host without disks.";
      };
    };
  };

  configFor =
    extra:
    (lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        module
        base
        site
        extra
      ];
    }).config;

  evaluates = extra: (builtins.tryEval (configFor extra).system.build.toplevel.drvPath).success;

  server = configFor { hardening.stig.enable = true; };

  grouped = configFor {
    hardening.stig = {
      enable = true;
      profile = "workstation";
      groups.ssh = {
        status = "notApplicable";
        reason = "Checked by the evaluation test.";
      };
      rules.V-268137 = {
        status = "exception";
        reason = "Checked by the evaluation test.";
      };
    };
  };
  report = server.hardening.report.stig;
  ruleCount = lib.length (lib.attrNames report.rules);
  summaryTotal = lib.foldl' lib.add 0 (lib.attrValues report.summary);
in
assert evaluates { hardening.stig.enable = true; };
assert
  !evaluates {
    hardening.stig.enable = true;
    hardening.stig.rules.V-268137.status = "exception";
  };
assert evaluates {
  hardening.stig.enable = true;
  hardening.stig.rules.V-268137 = {
    status = "exception";
    reason = "Checked by the evaluation test.";
  };
};
assert
  !evaluates {
    hardening.stig.enable = true;
    hardening.stig.rules.V-268125.status = "enforced";
  };
assert evaluates { hardening.stig.rules.V-268137.status = "exception"; };
assert grouped.hardening.stig.rules.V-268142.status == "notApplicable";
assert grouped.hardening.stig.rules.V-268159.status == "notApplicable";
assert grouped.hardening.stig.rules.V-268137.status == "exception";
assert
  !evaluates {
    hardening.stig.enable = true;
    hardening.stig.groups.ssh.status = "exception";
  };
assert lib.elem "V-268080" report.groups.audit;
assert ruleCount == 103;
assert summaryTotal == ruleCount;
assert report.summary.enforced > 0;
builtins.toJSON report.summary
