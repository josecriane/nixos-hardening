{ module }:
let
  mkCert =
    pkgs:
    pkgs.runCommand "journal-cert" { nativeBuildInputs = [ pkgs.openssl ]; } ''
      mkdir $out
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout $out/key.pem -out $out/cert.pem \
        -subj "/CN=receiver" -addext "subjectAltName=DNS:receiver"
    '';
in
{
  name = "stig-logging";

  nodes.receiver =
    { pkgs, ... }:
    let
      cert = mkCert pkgs;
    in
    {
      services.journald.remote.enable = true;
      services.nginx = {
        enable = true;
        virtualHosts.receiver = {
          onlySSL = true;
          sslCertificate = "${cert}/cert.pem";
          sslCertificateKey = "${cert}/key.pem";
          listen = [
            {
              addr = "0.0.0.0";
              port = 19533;
              ssl = true;
            }
          ];
          locations."/".proxyPass = "http://127.0.0.1:19532";
        };
      };
      networking.firewall.allowedTCPPorts = [ 19533 ];
      environment.etc."journal-test/cert.pem".source = "${cert}/cert.pem";
    };

  nodes.machine =
    { pkgs, ... }:
    let
      cert = mkCert pkgs;
    in
    {
      imports = [ module ];
      hardening.stig = {
        enable = true;
        rules.V-268108 = {
          status = "enforced";
          settings.url = "https://receiver:19533";
        };
        rules.V-268109 = {
          status = "enforced";
          settings.trustedCertificateFile = "${cert}/cert.pem";
        };
      };
      services.journald.upload.settings.Upload = {
        ServerKeyFile = "-";
        ServerCertificateFile = "-";
      };
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    receiver.wait_for_unit("nginx.service")
    receiver.wait_for_unit("systemd-journal-remote.socket")

    with subtest("V-268107 journald runs and records audit messages"):
        machine.succeed("systemctl is-active systemd-journald.service")
        machine.succeed("grep -Eq '^Audit=(yes|true)' /etc/systemd/journald.conf")

    with subtest("V-268108 journal is uploaded to a remote URL"):
        machine.succeed("grep -i 'Url' /etc/systemd/journal-upload.conf | grep -q 'https://receiver:19533'")
        machine.wait_for_unit("systemd-journal-upload.service")

    with subtest("V-268109 the remote server is authenticated"):
        out = machine.succeed("grep -i 'TrustedCertificateFile' /etc/systemd/journal-upload.conf")
        assert "all" not in out.split("=", 1)[1].strip()
        machine.succeed("logger -t stig-logging marker-from-machine")
        receiver.wait_until_succeeds("journalctl -D /var/log/journal/remote --no-pager | grep -q marker-from-machine", timeout=120)

    machine.succeed("journalctl --flush")
    machine.succeed("journalctl --rotate")

    with subtest("V-268115 journal files are owned by root"):
        machine.succeed("test -d /var/log/journal")
        assert machine.succeed("find /var/log/journal -not -user root").strip() == ""

    with subtest("V-268116 journal files are group-owned by systemd-journal"):
        assert machine.succeed("find /var/log/journal -not -group systemd-journal").strip() == ""

    with subtest("V-268117 journal directories have mode 2755 or less"):
        assert machine.succeed("find /var/log/journal -type d -perm -2755 -not -perm 2755 -printf '%p %m\\n'").strip() == ""
        assert machine.succeed("stat -c %a /var/log/journal").strip() == "2755"

    with subtest("V-268118 journal files have mode 0640 or less"):
        assert machine.succeed("find /var/log/journal -type f -perm -640 -not -perm 640 -printf '%p %m\\n'").strip() == ""
        machine.succeed("systemd-tmpfiles --create")
        assert machine.succeed("find /var/log/journal -type f -not -perm 640").strip() == ""
  '';
}
