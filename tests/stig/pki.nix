{ module }:
{
  name = "stig-pki";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ module ];
      hardening.stig = {
        enable = true;
        rules = {
          V-268124.status = "enforced";
          V-268178.status = "enforced";
          V-268124.settings.caBundle = pkgs.runCommand "test-ca.pem" { } ''
            ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
              -subj "/C=US/O=Test/CN=Test Root CA" -keyout /dev/null -out $out
          '';
          V-268178.settings.domains.local = {
            id_provider = "proxy";
            proxy_lib_name = "files";
            auth_provider = "proxy";
            proxy_pam_target = "sssd-shadowutils";
          };
        };
      };
      environment.systemPackages = [ pkgs.openssl ];
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("V-268124 sssd trusts the configured CA bundle"):
        machine.succeed("openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem | grep -q 'CN *= *Test Root CA'")
        machine.wait_for_unit("sssd.service")

    with subtest("V-268136 p11sak is in PATH"):
        machine.succeed("test -x /run/current-system/sw/bin/p11sak")
        machine.succeed("which p11sak")

    with subtest("V-268177 pam_p11 is in the pam stack"):
        machine.succeed("grep -q pam_p11.so /etc/pam.d/sshd")
        machine.succeed("grep -q pam_p11.so /etc/pam.d/login")

    with subtest("V-268178 cached authenticators expire after one day"):
        out = machine.succeed("grep expiration /etc/sssd/sssd.conf").strip()
        assert out.replace(" ", "") == "offline_credentials_expiration=1", out

    with subtest("V-268179 revocation data is cached locally"):
        out = machine.succeed("grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf").strip()
        assert out == "cert_policy = ca,signature,ocsp_on, crl_auto;", out
  '';
}
