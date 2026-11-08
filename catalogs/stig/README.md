# Anduril NixOS STIG

`anduril-nixos.json` holds the rule metadata of the DISA Anduril
NixOS STIG: severity, STIG version, rule id, title and CCI references. The
source is the XCCDF file inside the official DISA zip:

```
https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Anduril_NixOS_V1R3_STIG.zip
```

To regenerate it for a release, download and unzip that file, then run `xq`
(from the `yq` package) on `U_Anduril_NixOS_STIG_<release>_Manual-xccdf.xml`:

```sh
xq --arg source "$url" '.Benchmark | {
  meta: {
    title: .title,
    version: .version,
    release: (."plain-text"[] | select(."@id" == "release-info") | ."#text"),
    source: $source
  },
  rules: ([.Group[] | {
    key: ."@id",
    value: {
      severity: .Rule."@severity",
      version: .Rule.version,
      rule: .Rule."@id",
      title: .Rule.title,
      cci: ([.Rule.ident] | flatten | map(."#text"))
    }
  }] | from_entries)
}' "$xccdf" > anduril-nixos.json
```


## Rules

Each identifier links to the rule text. CAT is the DISA severity. The module
column names the file under `catalogs/stig/` that implements the rule.

| Rule | CAT | Module | Title |
|------|-----|--------|-------|
| [V-268078](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268078) | II | `network.nix` | NixOS must enable the built-in firewall. |
| [V-268079](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268079) | II | manual | NixOS emergency or temporary user accounts must be provisioned with an expiration time of 72 hours or less. |
| [V-268080](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268080) | II | `auditd.nix` | NixOS must enable the audit daemon. |
| [V-268081](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268081) | II | `login.nix` | NixOS must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period. |
| [V-268082](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268082) | II | `login.nix` | NixOS must be configured to display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon. |
| [V-268083](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268083) | II | `ssh.nix` | NixOS must be configured to display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via an SSH logon. |
| [V-268084](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268084) | II | `login.nix` | NixOS must be configured to display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a graphical user logon. |
| [V-268085](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268085) | III | `login.nix` | NixOS must be configured to limit the number of concurrent sessions to 10 for all accounts and/or account types. |
| [V-268086](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268086) | II | `login.nix` | NixOS must initiate a session lock after a 10-minute period of inactivity for graphical user logon. |
| [V-268087](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268087) | II | `login.nix` | NixOS must provide the capability for users to directly initiate a session lock for all connection types. |
| [V-268088](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268088) | II | `ssh.nix` | NixOS must monitor remote access methods. |
| [V-268089](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268089) | I | `ssh.nix` | NixOS must implement DoW-approved encryption to protect the confidentiality of remote access sessions. |
| [V-268090](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268090) | II | `auditd.nix` | The NixOS audit package must be installed. |
| [V-268091](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268091) | II | `audit-rules.nix` | NixOS must generate audit records for all usage of privileged commands. |
| [V-268092](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268092) | II | `auditd.nix` | NixOS must enable auditing of processes that start prior to the audit daemon. |
| [V-268093](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268093) | II | `auditd.nix` | NixOS must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon. |
| [V-268094](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268094) | II | `audit-rules.nix` | Successful/unsuccessful uses of the mount syscall in NixOS must generate an audit record. |
| [V-268095](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268095) | II | `audit-rules.nix` | Successful/unsuccessful uses of the rename, unlink, rmdir, renameat, and unlinkat system calls in NixOS must generate an audit record. |
| [V-268096](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268096) | II | `audit-rules.nix` | Successful/unsuccessful uses of the init_module, finit_module, and delete_module system calls in NixOS must generate an audit record. |
| [V-268097](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268097) | II | `audit-rules.nix` | NixOS must generate an audit record for successful/unsuccessful modifications to the cron configuration. |
| [V-268098](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268098) | II | `audit-rules.nix` | NixOS must generate an audit record for successful/unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls. |
| [V-268099](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268099) | II | `audit-rules.nix` | Successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls in NixOS must generate an audit record. |
| [V-268100](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268100) | II | `audit-rules.nix` | Successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls in NixOS must generate an audit record. |
| [V-268101](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268101) | II | `auditd.nix` | NixOS must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent utilization. |
| [V-268102](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268102) | II | `auditd.nix` | NixOS must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 90 percent utilization. |
| [V-268103](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268103) | II | `auditd.nix` | NixOS must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity. |
| [V-268104](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268104) | II | `auditd.nix` | NixOS must take action when allocated audit record storage volume reaches 90 percent of the repository maximum audit record storage capacity. |
| [V-268105](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268105) | II | `auditd.nix` | The NixOS audit system must take appropriate action when the audit storage volume is full. |
| [V-268106](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268106) | II | `auditd.nix` | The NixOS audit system must take appropriate action when an audit processing failure occurs. |
| [V-268107](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268107) | II | `logging.nix` | NixOS must have the packages required for offloading audit logs installed and running. |
| [V-268108](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268108) | II | `logging.nix` | The NixOS audit records must be off-loaded onto a different system or storage media from the system being audited. |
| [V-268109](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268109) | II | `logging.nix` | NixOS must authenticate the remote logging server for off-loading audit logs. |
| [V-268110](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268110) | II | `auditd.nix` | NixOS audit daemon must generate logs that are group-owned by root. |
| [V-268111](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268111) | II | `auditd.nix` | NixOS audit directory and logs must be owned by root to prevent unauthorized read access. |
| [V-268112](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268112) | II | `auditd.nix` | NixOS audit directory and logs must be group-owned by root to prevent unauthorized read access. |
| [V-268113](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268113) | II | `auditd.nix` | NixOS audit log directory must have a mode of 0700 or less permissive. |
| [V-268114](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268114) | II | `auditd.nix` | NixOS audit logs must have a mode of 0600 or less permissive. |
| [V-268115](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268115) | II | `logging.nix` | NixOS journald directory and logs must be owned by root to prevent unauthorized read access. |
| [V-268116](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268116) | II | `logging.nix` | NixOS journald directory and logs must be group-owned by systemd-journald to prevent unauthorized read access. |
| [V-268117](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268117) | II | `logging.nix` | NixOS systemd-journald directory must have a mode of 2755 or less permissive. |
| [V-268118](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268118) | II | `logging.nix` | NixOS systemd-journald logs must have a mode of 0640 or less permissive. |
| [V-268119](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268119) | II | `audit-rules.nix` | NixOS audit system must protect logon UIDs from unauthorized change. |
| [V-268120](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268120) | II | `auditd.nix` | NixOS audit configuration files must have a mode of 444 or less permissive. |
| [V-268121](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268121) | II | `system.nix` | NixOS system configuration file directories must have a mode of "0755" or less permissive. |
| [V-268122](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268122) | II | `system.nix` | NixOS system configuration files and directories must be owned by root. |
| [V-268123](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268123) | II | `system.nix` | NixOS system configuration files and directories must be group-owned by root. |
| [V-268124](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268124) | II | `pki.nix` | NixOS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor. |
| [V-268125](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268125) | II | manual | NixOS must enforce authorized access to the corresponding private key for PKI-based authentication. |
| [V-268126](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268126) | II | `passwords.nix` | NixOS must enforce password complexity by requiring that at least one uppercase character be used. |
| [V-268127](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268127) | II | `passwords.nix` | NixOS must enforce password complexity by requiring that at least one lowercase character be used. |
| [V-268128](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268128) | II | `passwords.nix` | NixOS must enforce password complexity by requiring that at least one numeric character be used. |
| [V-268129](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268129) | II | `passwords.nix` | NixOS must require the change of at least 50 percent of the total number of characters when passwords are changed. |
| [V-268130](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268130) | I | `passwords.nix` | NixOS must store only encrypted representations of passwords. |
| [V-268131](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268131) | I | `system.nix` | NixOS must not have the telnet package installed. |
| [V-268132](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268132) | II | `passwords.nix` | NixOS must enforce 24 hours/one day as the minimum password lifetime. |
| [V-268133](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268133) | II | `passwords.nix` | NixOS must enforce a 180-day maximum password lifetime restriction. |
| [V-268134](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268134) | II | `passwords.nix` | NixOS must enforce a minimum 15-character password length. |
| [V-268135](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268135) | II | `passwords.nix` | NixOS must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users). |
| [V-268136](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268136) | II | `pki.nix` | NixOS must use multifactor authentication for network access to privileged accounts. |
| [V-268137](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268137) | II | `ssh.nix` | NixOS must not allow direct login to the root account via SSH. |
| [V-268138](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268138) | II | `login.nix` | NixOS must not allow direct login to the root account. |
| [V-268139](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268139) | II | `system.nix` | NixOS must enable USBguard. |
| [V-268140](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268140) | II | `system.nix` | A sticky bit must be set on all NixOS public directories to prevent unauthorized and unintended information transferred via shared system resources. |
| [V-268141](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268141) | II | `network.nix` | NixOS must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks. |
| [V-268142](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268142) | II | `ssh.nix` | NixOS must terminate all SSH connections after 10 minutes of becoming unresponsive. |
| [V-268143](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268143) | II | `ssh.nix` | NixOS must terminate all SSH connections after becoming unresponsive. |
| [V-268144](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268144) | I | `system.nix` | NixOS must protect the confidentiality and integrity of all information at rest. |
| [V-268145](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268145) | II | `passwords.nix` | NixOS must enforce password complexity by requiring that at least one special character be used. |
| [V-268146](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268146) | I | `network.nix` | NixOS must protect wireless access to and from the system using encryption. |
| [V-268147](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268147) | II | `network.nix` | NixOS must protect wireless access to the system using authentication of users and/or devices. |
| [V-268148](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268148) | II | `audit-rules.nix` | NixOS must prevent all software from executing at higher privilege levels than users executing the software. |
| [V-268149](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268149) | II | `network.nix` | NixOS must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoW network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). |
| [V-268150](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268150) | II | `network.nix` | NixOS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second. |
| [V-268151](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268151) | II | `network.nix` | NixOS must have time synchronization enabled. |
| [V-268152](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268152) | II | `system.nix` | NixOS must prohibit user installation of system software without explicit privileged status. |
| [V-268153](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268153) | II | `system.nix` | NixOS must notify designated personnel if baseline configurations are changed in an unauthorized manner. |
| [V-268154](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268154) | I | `system.nix` | NixOS must prevent the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. |
| [V-268155](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268155) | II | `login.nix` | NixOS must require users to reauthenticate for privilege escalation. |
| [V-268156](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268156) | II | `login.nix` | NixOS must require users to reauthenticate when changing roles. |
| [V-268157](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268157) | I | `ssh.nix` | NixOS must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions. |
| [V-268158](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268158) | II | `network.nix` | NixOS must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces. |
| [V-268159](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268159) | I | `ssh.nix` | NixOS must protect the confidentiality and integrity of transmitted information. |
| [V-268160](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268160) | II | `kernel.nix` | NixOS must implement nonexecutable data to protect its memory from unauthorized code execution. |
| [V-268161](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268161) | II | `kernel.nix` | NixOS must implement address space layout randomization to protect its memory from unauthorized code execution. |
| [V-268163](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268163) | II | `audit-rules.nix` | NixOS must generate audit records when successful/unsuccessful attempts to modify security objects occur. |
| [V-268164](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268164) | II | `audit-rules.nix` | NixOS must generate audit records when successful/unsuccessful attempts to delete privileges occur. |
| [V-268165](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268165) | II | `audit-rules.nix` | NixOS must generate audit records when successful/unsuccessful attempts to delete security objects occur. |
| [V-268166](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268166) | II | `audit-rules.nix` | NixOS must generate audit records when concurrent logons to the same account occur from different sources. |
| [V-268167](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268167) | II | `audit-rules.nix` | NixOS must generate audit records for all account creations, modifications, disabling, and termination events. |
| [V-268168](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268168) | I | `kernel.nix` | NixOS must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. |
| [V-268169](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268169) | II | `passwords.nix` | NixOS must prevent the use of dictionary words for passwords. |
| [V-268170](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268170) | II | `passwords.nix` | NixOS must enable the use of pwquality. |
| [V-268171](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268171) | II | `login.nix` | NixOS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| [V-268172](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268172) | I | `login.nix` | NixOS must not allow an unattended or automatic logon to the system via the console. |
| [V-268173](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268173) | II | `kernel.nix` | NixOS must be configured to use AppArmor. |
| [V-268174](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268174) | II | `passwords.nix` | NixOS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity. |
| [V-268175](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268175) | II | `passwords.nix` | NixOS must employ approved cryptographic hashing algorithms for all stored passwords. |
| [V-268176](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268176) | I | `ssh.nix` | NixOS must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions. |
| [V-268177](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268177) | II | `pki.nix` | NixOS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access. |
| [V-268178](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268178) | II | `pki.nix` | NixOS must prohibit the use of cached authenticators after one day. |
| [V-268179](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268179) | II | `pki.nix` | For PKI-based authentication, NixOS must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network. |
| [V-268180](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268180) | II | `system.nix` | NixOS must run a supported release of the operating system. |
| [V-268181](https://stigui.com/stigs/Anduril_NixOS_STIG/groups/V-268181) | II | `login.nix` | NixOS must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. |

## Areas

| Module            | Rules |
|-------------------|-------|
| `ssh.nix`         | sshd settings: ciphers, MACs, banner, PAM, log level, root login, keepalives |
| `network.nix`     | firewall, rate limits, syncookies, wireless, Bluetooth, time synchronization |
| `kernel.nix`      | kptr_restrict, ASLR, FIPS kernel parameter, AppArmor |
| `auditd.nix`      | auditd service, kernel audit parameters, auditd.conf thresholds and actions, audit log permissions |
| `audit-rules.nix` | syscall and watch rules, privileged commands, immutable login UID |
| `logging.nix`     | journald audit capture, journal upload to a remote server, journal permissions |
| `login.nix`       | faillock, logon banners, session limits and locks, no autologin, no root login, sudo reauthentication, umask |
| `passwords.nix`   | pwquality, password aging, SHA512 hashes, inactive accounts, unique UIDs |
| `pki.nix`         | sssd trust anchor and cached credentials, pam_p11, pam_pkcs11 certificate policy |
| `system.nix`      | telnet absent, USBGuard, sticky bits, nix users and signatures, AIDE, supported release, LUKS, /etc/audit ownership |

## Rules that need a value from the operator

| Rule     | Setting                                        |
|----------|------------------------------------------------|
| V-268108 | `settings.url` of the journal upload server    |
| V-268109 | `settings.trustedCertificateFile` of that server |
| V-268124 | `settings.caBundle`, the PEM trust anchor for sssd |
| V-268178 | `settings.domains`, the sssd domains           |

A host that does not set them must set the rule to `exception` with a reason.

## Graphical session lock

V-268086 locks the session with the method in `settings.method`. `gnome`, the
default, sets the dconf key `idle-delay` and runs xautolock. `swayidle` runs
the user service `hardening-idle-lock` for Wayland compositors without an idle
lock, such as niri. The service runs `settings.lockCommand` after
`settings.minutes` of inactivity and on `loginctl lock-session`. The default
command is `swaylock -f`. Both methods set `IdleAction=lock` in logind.

## Rules verified by an assertion

V-268131 (telnet), V-268135 (duplicate UIDs), V-268144 (LUKS), V-268172
(autologin) and V-268180 (supported release) fail the evaluation when the
configuration violates them.

## Manual rules

V-268079 (expiration of temporary accounts) and V-268125 (passphrases on
private keys) are procedures on live data. No module implements them, so they
stay `deferred` in the report.

## Profiles

`server` marks the graphical logon rules V-268084 and V-268086 as not
applicable. `workstation` exempts sshd, Wi-Fi, Bluetooth and USBGuard, and
lowers the auditd disk actions from `HALT` to `SYSLOG`.

## Groups

`hardening.stig.groups.<group>` sets the status and the reason of several
rules at once. A rule that the host sets explicitly keeps its own value.

| Group           | Rules |
|-----------------|-------|
| `audit`         | auditd, kernel audit parameters, audit rules, auditd.conf, journald audit capture: V-268080, V-268091 to V-268107, V-268110, V-268119, V-268120, V-268148, V-268163 to V-268167 |
| `ssh`           | sshd: V-268083, V-268088, V-268089, V-268137, V-268142, V-268143, V-268157, V-268159, V-268176 |
| `pki`           | smart cards and sssd: V-268124, V-268136, V-268177, V-268178, V-268179 |
| `remoteLogging` | journal upload: V-268108, V-268109 |

## Organization-specific values

The defaults are generic, not those of the US Department of War. V-268082,
V-268083 and V-268084 show the text of `settings.text`, a generic notice by
default. V-268149 uses the NTP pool of NixOS by default. An organization that
must use its own banner text or time servers sets those settings.
