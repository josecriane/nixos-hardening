{ module }:
{
  name = "stig-passwords";

  nodes.machine = {
    imports = [ module ];
    hardening.stig.enable = true;
    users.users.tester = {
      isNormalUser = true;
      initialPassword = "Aa1!aaaaaaaaaaaa";
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    def conf(key):
        return machine.succeed(f"grep ^{key} /etc/security/pwquality.conf").strip()

    def login_defs(key):
        return machine.succeed(f"grep ^{key} /etc/login.defs").strip()

    def change(new):
        return machine.execute(
            f"printf 'Aa1!aaaaaaaaaaaa\\n{new}\\n{new}\\n' | su tester -c passwd 2>&1"
        )

    with subtest("V-268126 one uppercase character"):
        assert conf("ucredit") == "ucredit=-1"

    with subtest("V-268127 one lowercase character"):
        assert conf("lcredit") == "lcredit=-1"

    with subtest("V-268128 one digit"):
        assert conf("dcredit") == "dcredit=-1"

    with subtest("V-268145 one special character"):
        assert conf("ocredit") == "ocredit=-1"

    with subtest("V-268129 difok is 8"):
        assert conf("difok") == "difok=8"

    with subtest("V-268134 minimum length is 15"):
        assert conf("minlen") == "minlen=15"

    with subtest("V-268169 dictionary check"):
        assert conf("dictcheck") == "dictcheck=1"

    with subtest("V-268170 pam_pwquality in passwd, chpasswd and sudo"):
        machine.succeed("grep -i pam_pwquality /etc/pam.d/passwd /etc/pam.d/chpasswd /etc/pam.d/sudo | grep -c requisite | grep -qx 3")

    with subtest("V-268170 weak passwords are rejected"):
        status, out = change("short1A!")
        assert status != 0 and "BAD PASSWORD" in out, out
        status, out = change("alllowercaseletters1!")
        assert status != 0 and "BAD PASSWORD" in out, out

    with subtest("V-268130 ENCRYPT_METHOD is SHA512"):
        assert login_defs("ENCRYPT_METHOD") == "ENCRYPT_METHOD SHA512"

    with subtest("V-268175 stored hashes use SHA512"):
        status, out = change("Zz9#different-Passw0rd")
        assert status == 0, out
        machine.succeed("grep '^tester:' /etc/shadow | cut -d'$' -f2 | grep -qx 6")
        machine.succeed("grep -q sha512 /etc/pam.d/passwd")

    with subtest("V-268132 minimum password age is 1"):
        assert login_defs("PASS_MIN_DAYS") == "PASS_MIN_DAYS 1"

    with subtest("V-268133 maximum password age is 180"):
        assert login_defs("PASS_MAX_DAYS") == "PASS_MAX_DAYS 180"

    with subtest("V-268174 inactive accounts are disabled after 35 days"):
        machine.succeed("grep -i inactive /etc/default/useradd | grep -qx INACTIVE=35")
        machine.succeed("useradd -D | grep -qx INACTIVE=35")

    with subtest("V-268135 no duplicate UIDs"):
        assert machine.succeed("awk -F ':' 'list[$3]++{print $1, $3}' /etc/passwd").strip() == ""
  '';
}
