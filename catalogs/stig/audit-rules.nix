{ lib, hardening, ... }:
let
  on = hardening.enforced "stig";

  watchedPaths = [
    "d /var/cron/tabs 0700 root root -"
    "f /var/cron/cron.allow 0600 root root -"
    "f /var/cron/cron.deny 0600 root root -"
    "f /var/log/lastlog 0644 root root -"
    "d /etc/security 0755 root root -"
    "f /etc/security/opasswd 0600 root root -"
  ];

  auditing = rules: {
    systemd.services.audit-rules-nixos.after = [ "systemd-tmpfiles-setup.service" ];
    systemd.tmpfiles.rules = watchedPaths;
    security = {
      audit = {
        enable = lib.mkDefault true;
        inherit rules;
      };
      auditd.enable = lib.mkDefault true;
    };
  };

  implemented = [
    "V-268091"
    "V-268094"
    "V-268095"
    "V-268096"
    "V-268097"
    "V-268098"
    "V-268099"
    "V-268100"
    "V-268119"
    "V-268148"
    "V-268163"
    "V-268164"
    "V-268165"
    "V-268166"
    "V-268167"
  ];
in
{
  config = lib.mkMerge (
    [
      {
        hardening.stig.rules = lib.genAttrs implemented (_: {
          implemented = true;
          status = lib.mkDefault "enforced";
        });
      }
    ]
    ++ [
      (lib.mkIf (on "V-268091" || on "V-268148") (auditing [
        "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
        "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv"
        "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv"
        "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"
      ]))
      (lib.mkIf (on "V-268094") (auditing [
        "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
        "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount"
      ]))
      (lib.mkIf (on "V-268095") (auditing [
        "-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
        "-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete"
      ]))
      (lib.mkIf (on "V-268096") (auditing [
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k module_chng"
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k module_chng"
      ]))
      (lib.mkIf (on "V-268097") (auditing [
        "-w /var/cron/tabs/ -p wa -k services"
        "-w /var/cron/cron.allow -p wa -k services"
        "-w /var/cron/cron.deny -p wa -k services"
      ]))
      (lib.mkIf (on "V-268098") (auditing [
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
        "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access"
        "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access"
      ]))
      (lib.mkIf (on "V-268099") (auditing [
        "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
      ]))
      (lib.mkIf (on "V-268100") (auditing [
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
      ]))
      (lib.mkIf (on "V-268148") (auditing [ ]))
      (lib.mkIf (on "V-268119") (auditing [ "--loginuid-immutable" ]))
      (lib.mkIf (on "V-268163") (auditing [
        "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
        "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
      ]))
      (lib.mkIf (on "V-268164") (auditing [
        "-a always,exit -F path=/run/current-system/sw/bin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod"
      ]))
      (lib.mkIf (on "V-268165") (auditing [
        "-a always,exit -F path=/run/current-system/sw/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"
        "-a always,exit -F path=/run/current-system/sw/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod"
      ]))
      (lib.mkIf (on "V-268166") (auditing [ "-w /var/log/lastlog -p wa -k logins" ]))
      (lib.mkIf (on "V-268167") (auditing [
        "-w /etc/sudoers -p wa -k identity"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/gshadow -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/security/opasswd -p wa -k identity"
      ]))
    ]
  );
}
