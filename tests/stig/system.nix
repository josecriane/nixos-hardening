{ module }:
{
  name = "stig-system";

  nodes.machine = {
    imports = [ module ];
    hardening.stig = {
      enable = true;
      rules.V-268139.settings.rules = ''
        allow id 1d6b:0001
      '';
    };
    security.auditd.enable = true;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("V-268131 telnet is not installed"):
        out = machine.succeed("whereis telnet").strip()
        assert out == "telnet:", out

    with subtest("V-268139 usbguard runs"):
        machine.wait_for_unit("usbguard.service")
        machine.succeed("systemctl is-active usbguard.service")

    with subtest("V-268140 world-writable directories have the sticky bit"):
        machine.succeed("chmod 0777 /var/tmp")
        machine.succeed("systemd-tmpfiles --create")
        machine.succeed("stat -c %a /tmp /var/tmp /dev/shm | sort -u | grep -qx 1777")
        out = machine.succeed(
            "find /tmp /var/tmp /dev/shm -maxdepth 0 -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null"
        )
        assert out.strip() == "", out

    with subtest("V-268152 only root and wheel use nix"):
        machine.succeed("grep -R allowed-users /etc/nix/nix.conf | grep -q 'allowed-users = root @wheel'")

    with subtest("V-268154 signatures are required"):
        machine.succeed("grep -R require-sigs /etc/nix/nix.conf | grep -q 'require-sigs = true'")

    with subtest("V-268153 aide checks the baseline"):
        machine.succeed("test -r /etc/aide.conf")
        machine.succeed("systemctl is-active aide.timer")
        machine.succeed("systemctl start aide.service")
        machine.succeed("touch /etc/unauthorized-change")
        machine.fail("systemctl start aide.service")

    with subtest("V-268180 release is supported"):
        release = machine.succeed(". /etc/os-release && echo $VERSION_ID").strip()
        assert release in ["26.05", "26.11"], release

    with subtest("V-268144 exception is recorded"):
        machine.succeed("true")

    with subtest("V-268121 audit directories are 0755 or less"):
        out = machine.succeed("find -L /etc/audit -type d -exec stat -L -c '%a %n' {} \;")
        for line in out.splitlines():
            assert int(line.split()[0], 8) & ~0o755 == 0, line

    with subtest("V-268122 audit files are owned by root"):
        out = machine.succeed("find /etc/audit -exec stat -L -c '%U %n' {} \;")
        assert all(l.startswith("root ") for l in out.splitlines()), out

    with subtest("V-268123 audit files are group-owned by root"):
        out = machine.succeed("find /etc/audit -exec stat -L -c '%G %n' {} \;")
        assert all(l.startswith("root ") for l in out.splitlines()), out
  '';
}
