{ module }:
{
  name = "stig-login";

  nodes.machine = {
    imports = [ module ];
    hardening.stig = {
      enable = true;
      rules.V-268084.status = "enforced";
      rules.V-268086.status = "enforced";
    };
    services.displayManager.gdm.enable = true;
    users.users.admin = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      hashedPassword = "$6$saltsalt$Wq0a2yUdI6nR5s9Y1zq9b4m1Fv0X8V0XvQe4F5l2o3q1m8Z6p7r8t9u0v1w2x3y4z5A6B7C8D9E0F1G2H3I4J.";
    };
  };

  nodes.wayland = {
    imports = [ module ];
    hardening.stig = {
      enable = true;
      rules.V-268086 = {
        status = "enforced";
        settings.method = "swayidle";
      };
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("V-268081 three failed logons in 15 minutes lock the account"):
        for service in ["login", "sshd"]:
            out = machine.succeed(f"grep pam_faillock /etc/pam.d/{service}")
            assert "preauth" in out and "authfail" in out, out
            assert "deny=3" in out and "fail_interval=900" in out and "unlock_time=0" in out, out
        machine.succeed("grep -q 'even_deny_root' /etc/pam.d/login")

    with subtest("V-268082 console banner is in /etc/issue"):
        machine.succeed("grep -q 'authorized use only' /etc/issue")
        machine.succeed("grep -q 'consent to this monitoring' /etc/issue")

    with subtest("V-268084 graphical banner is in the gdm dconf profile"):
        out = machine.succeed("DCONF_PROFILE=gdm dconf read /org/gnome/login-screen/banner-message-text")
        assert "authorized use only" in out, out
        assert "consent to this monitoring" in out, out

    with subtest("V-268085 at most 10 concurrent sessions"):
        conf = machine.succeed("grep -o 'conf=[^ ]*limits.conf' /etc/pam.d/login | cut -d= -f2").strip()
        machine.succeed(f"grep -Eq '^\\*[[:space:]]+hard[[:space:]]+maxlogins[[:space:]]+10$' {conf}")

    with subtest("V-268086 session locks after 10 minutes"):
        machine.succeed("DCONF_PROFILE=user dconf read /org/gnome/desktop/session/idle-delay | grep -qx 'uint32 600'")
        machine.succeed("grep -q 'IdleAction=lock' /etc/systemd/logind.conf")
        machine.succeed("grep -q 'IdleActionSec=600' /etc/systemd/logind.conf")
        machine.succeed("grep -q -- '-time 10' /etc/systemd/user/xautolock.service")

    with subtest("V-268086 swayidle locks the session after 10 minutes"):
        wayland.start()
        wayland.wait_for_unit("multi-user.target")
        unit = wayland.succeed("cat /etc/systemd/user/hardening-idle-lock.service")
        assert "swayidle" in unit and "timeout 600" in unit, unit
        assert "WantedBy=graphical-session.target" in unit, unit
        wayland.fail("test -e /etc/systemd/user/xautolock.service")

    with subtest("V-268087 vlock is installed"):
        machine.succeed("test -x /run/current-system/sw/bin/vlock")

    with subtest("V-268171 four second delay after a failed logon"):
        machine.succeed("grep -Eq '^FAIL_DELAY[[:space:]]+4$' /etc/login.defs")

    with subtest("V-268172 no automatic logon"):
        machine.fail("grep -rq -- '--autologin' /etc/systemd/system")
        machine.fail("grep -qi '^AutomaticLoginEnable *= *true' /etc/gdm/custom.conf")

    with subtest("V-268138 root account is locked"):
        status = machine.succeed("passwd -S root").split()[1]
        assert status in ["L", "NP"], status

    with subtest("V-268155 sudo asks for the password every time"):
        machine.succeed("grep -q '^Defaults timestamp_timeout=0' /etc/sudoers")

    with subtest("V-268156 wheel must reauthenticate"):
        out = machine.succeed("grep -iR '%wheel' /etc/sudoers")
        assert "NOPASSWD" not in out, out

    with subtest("V-268181 default umask is 077"):
        machine.succeed("grep -Eq '^UMASK[[:space:]]+077$' /etc/login.defs")
  '';
}
