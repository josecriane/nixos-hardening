{ module }:
{
  name = "stig-audit-rules";

  nodes.machine = {
    imports = [ module ];
    hardening.stig.enable = true;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("audit-rules-nixos.service")

    def loaded(pattern):
        return machine.succeed(f"auditctl -l | grep -E -- '{pattern}'").splitlines()

    def covers(lines, syscalls, arches=("b32", "b64"), extra=()):
        for arch in arches:
            found = False
            for line in lines:
                if f"arch={arch} " not in line or "-S " not in line:
                    continue
                names = set(line.split("-S ")[1].split()[0].split(","))
                if set(syscalls) <= names and all(e in line for e in extra):
                    found = True
            assert found, f"{arch} {syscalls} {extra} not in {lines}"

    with subtest("V-268091 privileged commands are audited"):
        out = loaded("-S execve")
        covers(out, ["execve"], extra=["-C uid!=euid", "euid=0"])
        covers(out, ["execve"], extra=["-C gid!=egid", "egid=0"])

    with subtest("V-268148 privileged execution is audited"):
        assert len(loaded("execpriv")) == 4

    with subtest("V-268094 mount is audited"):
        covers(loaded(r"-S mount "), ["mount"], extra=["auid>=1000"])

    with subtest("V-268095 rename, unlink, rmdir, renameat, unlinkat are audited"):
        covers(loaded("rename|unlink|rmdir"), ["rename", "unlink", "rmdir", "renameat", "unlinkat"])

    with subtest("V-268096 module syscalls are audited"):
        covers(loaded("init_module"), ["init_module", "finit_module", "delete_module"])

    with subtest("V-268097 cron configuration is watched"):
        out = "\n".join(loaded("cron"))
        for path in ("/var/cron/tabs", "/var/cron/cron.allow", "/var/cron/cron.deny"):
            assert f"-w {path} -p wa" in out, out

    with subtest("V-268098 failed file operations are audited"):
        out = loaded("open|truncate|creat")
        names = ["open", "creat", "truncate", "ftruncate", "openat", "open_by_handle_at"]
        covers(out, names, extra=["exit=-EACCES"])
        covers(out, names, extra=["exit=-EPERM"])

    with subtest("V-268099 chown family is audited"):
        covers(loaded("chown"), ["chown", "fchown", "lchown", "fchownat"])

    with subtest("V-268100 chmod family is audited"):
        covers(loaded("chmod"), ["chmod", "fchmod", "fchmodat"])

    with subtest("V-268119 login UIDs are immutable"):
        out = machine.succeed("auditctl -s | grep -i immutable")
        assert "loginuid_immutable 1 locked" in out, out

    with subtest("V-268163 security object changes are audited"):
        covers(
            loaded("xattr"),
            ["setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", "lremovexattr"],
        )

    with subtest("V-268164 usermod is audited"):
        loaded("usermod")

    with subtest("V-268165 chage and chcon are audited"):
        out = "\n".join(loaded("/bin/ch"))
        assert "bin/chage" in out and "bin/chcon" in out, out

    with subtest("V-268166 lastlog is watched"):
        loaded("-w /var/log/lastlog -p wa")

    with subtest("V-268167 account files are watched"):
        out = "\n".join(loaded("/etc"))
        for path in ("sudoers", "passwd", "shadow", "gshadow", "group", "security/opasswd"):
            assert f"-w /etc/{path} -p wa" in out, out
  '';
}
