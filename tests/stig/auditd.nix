{ module }:
{
  name = "stig-auditd";

  nodes.machine = {
    imports = [ module ];
    hardening.stig.enable = true;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("auditd.service")

    def conf(key):
        return machine.succeed(f"grep -w '^{key}' /etc/audit/auditd.conf | cut -d= -f2-").strip()

    with subtest("V-268080 auditd and the audit rules service are active"):
        machine.succeed("systemctl is-active auditd.service")
        machine.succeed("systemctl is-active audit-rules-nixos.service")

    with subtest("V-268090 audit package is installed"):
        machine.succeed("test -x /run/current-system/sw/bin/auditctl")

    with subtest("V-268092 kernel audits early processes"):
        machine.succeed("grep -qw audit=1 /proc/cmdline")

    with subtest("V-268093 backlog limit is 8192 or greater"):
        assert int(machine.succeed("auditctl -s | awk '$1==\"backlog_limit\"{print $2}'")) >= 8192
        machine.succeed("grep -qw audit_backlog_limit=8192 /proc/cmdline")

    with subtest("V-268101 space_left_action is set"):
        assert conf("space_left_action") == "syslog"

    with subtest("V-268102 admin_space_left_action is set"):
        assert conf("admin_space_left_action") == "syslog"

    with subtest("V-268103 space_left is 25%"):
        assert conf("space_left") == "25%"

    with subtest("V-268104 admin_space_left is 10%"):
        assert conf("admin_space_left") == "10%"

    with subtest("V-268105 disk_full_action is HALT"):
        assert conf("disk_full_action") == "HALT"

    with subtest("V-268106 disk_error_action is HALT"):
        assert conf("disk_error_action") == "HALT"

    with subtest("V-268110 log_group is root"):
        assert conf("log_group") == "root"

    machine.wait_until_succeeds("test -f /var/log/audit/audit.log")

    with subtest("V-268111 audit directory and logs are owned by root"):
        out = machine.succeed("find /var/log/audit -exec stat -c '%U %n' {} \;")
        assert out.strip() and all(l.startswith("root ") for l in out.splitlines()), out

    with subtest("V-268112 audit directory and logs are group-owned by root"):
        out = machine.succeed("find /var/log/audit -exec stat -c '%G %n' {} \;")
        assert out.strip() and all(l.startswith("root ") for l in out.splitlines()), out

    with subtest("V-268113 audit directory has mode 0700"):
        out = machine.succeed("find /var/log/audit -type d -exec stat -c '%a %n' {} \;")
        assert out.strip() and all(l.startswith("700 ") for l in out.splitlines()), out

    with subtest("V-268114 audit logs have mode 0600"):
        out = machine.succeed("find /var/log/audit -type f -exec stat -c '%a %n' {} \;")
        assert out.strip() and all(l.startswith("600 ") for l in out.splitlines()), out

    with subtest("V-268120 audit configuration files have mode 444 or less"):
        out = machine.succeed(
            "find -L /etc/audit -type f -exec stat -L -c '%a %n' {} \; ; "
            "find -L /etc/systemd/system -iname 'audit*' -type f -exec stat -L -c '%a %n' {} \;"
        )
        assert out.strip()
        for line in out.splitlines():
            assert int(line.split()[0], 8) & 0o333 == 0, line
  '';
}
