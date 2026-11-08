{ module }:
{
  name = "stig-kernel";

  nodes.machine = {
    imports = [ module ];
    hardening.stig.enable = true;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("V-268160 kernel pointers are restricted"):
        assert machine.succeed("sysctl -n kernel.kptr_restrict").strip() == "1"

    with subtest("V-268161 ASLR is fully enabled"):
        assert machine.succeed("sysctl -n kernel.randomize_va_space").strip() == "2"

    with subtest("V-268168 fips=1 is on the kernel command line"):
        machine.succeed("grep -qw 'fips=1' /proc/cmdline")

    with subtest("V-268173 apparmor.service is enabled and active"):
        machine.succeed("systemctl is-enabled apparmor.service")
        machine.succeed("systemctl is-active apparmor.service")
  '';
}
