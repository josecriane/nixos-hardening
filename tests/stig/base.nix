{ lib, ... }:
let
  waived = reason: {
    status = lib.mkOverride 950 "exception";
    reason = lib.mkOverride 950 reason;
  };
in
{
  users.users.operator = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    hashedPassword = "$6$rounds=65536$stigtest$2m3YfqVfS4qfgwbkiawzLhXRRq2jsNz8IDJuCvI8Hsq9qYKuC0XfAw4W.3eXFkYzlWz6vNxk6hZkKkxrN/GzT0";
  };

  services.timesyncd.enable = lib.mkForce true;

  hardening.stig.rules = {
    V-268108 = waived "The test VM has no journal upload target.";
    V-268109 = waived "The test VM has no journal upload target.";
    V-268124 = waived "The test VM has no PKI trust anchor.";
    V-268178 = waived "The test VM has no sssd domain.";
    V-268144 = waived "The test VM boots from an unencrypted virtual disk.";
  };
}
