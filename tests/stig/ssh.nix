{ module }:
{
  name = "stig-ssh";

  nodes.machine = {
    imports = [ module ];
    hardening.stig.enable = true;
  };

  testScript = ''
    machine.start()

    def effective(key):
        return machine.succeed(f"sshd -G | grep -i '^{key} ' | cut -d' ' -f2-").strip()

    with subtest("V-268159 sshd runs"):
        machine.wait_for_unit("sshd.service")

    with subtest("V-268137 root login is denied"):
        assert effective("permitrootlogin") == "no"

    with subtest("V-268089 only FIPS ciphers, in order"):
        assert effective("ciphers") == "aes256-ctr,aes192-ctr,aes128-ctr"

    with subtest("V-268157 only FIPS MACs"):
        assert effective("macs") == "hmac-sha2-512,hmac-sha2-256"

    with subtest("V-268176 PAM is used"):
        assert effective("usepam") == "yes"

    with subtest("V-268088 verbose log level"):
        assert effective("loglevel") == "VERBOSE"

    with subtest("V-268083 consent banner is shown"):
        banner = effective("banner")
        assert banner != "none", "no banner configured"
        machine.succeed(f"grep -q 'authorized use only' {banner}")

    with subtest("V-268142 idle interval is at most 600 seconds"):
        assert 0 < int(effective("clientaliveinterval")) <= 600

    with subtest("V-268143 one missed keepalive ends the session"):
        assert effective("clientalivecountmax") == "1"
  '';
}
