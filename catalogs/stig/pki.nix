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
    "V-268124"
    "V-268136"
    "V-268177"
    "V-268178"
    "V-268179"
  ];
in
{
  options.hardening.stig.rules = {
    V-268124 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.caBundle = lib.mkOption {
          type = lib.types.path;
          description = "PEM file with the accepted root and intermediate CA certificates, installed as /etc/sssd/pki/sssd_auth_ca_db.pem.";
        };
      };
    };

    V-268178 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.domains = lib.mkOption {
          type = lib.types.attrsOf (
            lib.types.attrsOf (
              lib.types.oneOf [
                lib.types.str
                lib.types.int
                lib.types.bool
              ]
            )
          );
          description = "sssd domains, keyed by domain name, written as [domain/<name>] sections.";
        };
      };
    };

    V-268179 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.certPolicy = lib.mkOption {
          type = lib.types.str;
          default = "ca,signature,ocsp_on, crl_auto";
          description = "Value of cert_policy in pam_pkcs11.conf.";
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
    }

    (lib.mkIf (on "V-268124") {
      services.sssd.enable = true;
      environment.etc."sssd/pki/sssd_auth_ca_db.pem".source = rules.V-268124.settings.caBundle;
    })

    (lib.mkIf (on "V-268136") {
      environment.systemPackages = [ pkgs.opencryptoki ];
    })

    (lib.mkIf (on "V-268177") {
      security.pam.p11.enable = true;
    })

    (lib.mkIf (on "V-268178") {
      services.sssd = {
        enable = true;
        settings = {
          sssd = {
            services = "nss, pam";
            domains = lib.concatStringsSep ", " (lib.attrNames rules.V-268178.settings.domains);
          };
          nss = { };
          pam.offline_credentials_expiration = 1;
        }
        // lib.mapAttrs' (
          name: value: lib.nameValuePair "domain/${name}" value
        ) rules.V-268178.settings.domains;
      };
    })

    (lib.mkIf (on "V-268179") {
      environment.etc."pam_pkcs11/pam_pkcs11.conf".text = ''
        pam_pkcs11 {
          use_first_pass = false;
          use_authtok = false;
          card_only = false;
          wait_for_card = false;
          use_pkcs11_module = opensc;
          pkcs11_module opensc {
            module = ${pkgs.opensc}/lib/opensc-pkcs11.so;
            slot_num = 0;
            ca_dir = /etc/sssd/pki;
            crl_dir = /var/cache/pam_pkcs11/crls;
            cert_policy = ${rules.V-268179.settings.certPolicy};
          }
          use_mappers = null;
        }
      '';
    })
  ];
}
