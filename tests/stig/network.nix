{ module }:
{
  name = "stig-network";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ module ];
      hardening.stig.enable = true;
      services.timesyncd.enable = lib.mkForce true;
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("V-268078 firewall is enabled"):
        machine.wait_for_unit("firewall.service")
        machine.succeed("iptables -L | grep nixos-fw-log-refuse")

    with subtest("V-268141 TCP syncookies are on"):
        assert machine.succeed("sysctl -n net.ipv4.tcp_syncookies").strip() == "1"

    with subtest("V-268158 hashlimit rules are present"):
        out = machine.succeed("iptables -L | grep limit")
        assert "tcp dpt:ssh" in out, out
        assert "tcp dpt:http " in out, out
        assert "tcp dpt:https" in out, out
        machine.succeed("ip6tables -L | grep limit")

    with subtest("V-268146 wireless is disabled"):
        machine.fail("systemctl cat wpa_supplicant.service")

    with subtest("V-268147 bluetooth is disabled"):
        machine.fail("systemctl cat bluetooth.service")

    with subtest("V-268151 time synchronization is enabled"):
        machine.wait_for_unit("systemd-timesyncd.service")

    with subtest("V-268149 approved time servers are configured"):
        out = machine.succeed("timedatectl show-timesync | grep NTPServers")
        assert "nixos.pool.ntp.org" in out, out

    with subtest("V-268150 poll interval is at most 60 seconds"):
        machine.succeed("grep -q '^PollIntervalMaxSec=60$' /etc/systemd/timesyncd.conf")
  '';
}
