{
  config,
  lib,
  hardening,
  ...
}:
let
  on = hardening.enforced "stig";
  rules = config.hardening.stig.rules;

  implemented = [
    "V-268107"
    "V-268108"
    "V-268109"
    "V-268115"
    "V-268116"
    "V-268117"
    "V-268118"
  ];
in
{
  options.hardening.stig.rules = {
    V-268108 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.url = lib.mkOption {
          type = lib.types.str;
          example = "https://logs.example.org:19532";
          description = "URL of the remote server that receives the journal.";
        };
      };
    };

    V-268109 = lib.mkOption {
      type = lib.types.submodule {
        options.settings.trustedCertificateFile = lib.mkOption {
          type = lib.types.str;
          example = "/etc/ssl/journal/ca.pem";
          description = "CA certificate in PEM format that authenticates the remote logging server.";
        };
      };
    };
  };

  config = {
    hardening.stig.rules = lib.genAttrs implemented (_: {
      implemented = true;
      status = lib.mkDefault "enforced";
    });

    services.journald = lib.mkMerge [
      (lib.mkIf (on "V-268107") { settings.Journal.Audit = true; })
      (lib.mkIf (on "V-268108") {
        upload = {
          enable = true;
          settings.Upload.URL = rules.V-268108.settings.url;
        };
      })
      (lib.mkIf (on "V-268109") {
        upload = {
          enable = true;
          settings.Upload.TrustedCertificateFile = rules.V-268109.settings.trustedCertificateFile;
        };
      })
    ];

    systemd.tmpfiles.rules =
      lib.optional (on "V-268117") "d /var/log/journal 2755 root systemd-journal -"
      ++ lib.optional (on "V-268115") "Z /var/log/journal - root - -"
      ++ lib.optional (on "V-268116") "Z /var/log/journal - - systemd-journal -"
      ++ lib.optional (on "V-268118") "Z /var/log/journal/*/*.journal* 0640 - - -";
  };
}
