# nixos-hardening

NixOS modules that apply compliance catalogs rule by rule. Every rule is a
typed option with a status and a reason. The configuration exports a report
of every rule, and a VM test covers every enforced rule.

## Catalogs

| Name                            | Source                        | Rules | Implemented |
|---------------------------------|-------------------------------|-------|-------------|
| [`stig`](catalogs/stig/README.md) | DISA Anduril NixOS STIG, V1R3 | 103   | 101         |

An implemented rule has a module that enforces it or an assertion that
verifies it. The remaining rules are manual procedures with nothing to
declare. The README of each catalog lists them, together with the origin of
its data file, its areas, its profiles and the settings an operator must set.

## Usage

```nix
{
  inputs.nixos-hardening.url = "github:josecriane/nixos-hardening";

  outputs = { nixpkgs, nixos-hardening, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        nixos-hardening.nixosModules.default
        {
          hardening.stig = {
            enable = true;
            profile = "workstation";
            rules.V-268083 = {
              status = "exception";
              reason = "Personal machine, no DoW banner.";
            };
            rules.V-268142.settings.interval = 300;
          };
        }
      ];
    };
  };
}
```

## Rule model

Each rule under `hardening.<catalog>.rules.<id>` has:

- `status`: `enforced`, `exception`, `notApplicable` or `deferred`.
- `reason`: text, required when `status` is not `enforced`.
- `implemented`: set by the module that enforces the rule.
- `settings`: options of that rule, when it has any.

A rule that no module implements defaults to `deferred`. A rule that a
module implements defaults to `enforced`. A profile changes defaults for a
class of machine. A host sets the final value.

A catalog can declare groups of rules. `hardening.<catalog>.groups.<group>`
takes a `status` and a `reason` and applies them to every rule of the group.
The precedence, from lowest to highest, is: module default, profile, group,
rule set by the host.

The evaluation fails when an enforced rule has no implementation, or when a
rule that is not enforced has no reason.

## Report

```sh
nix eval --json .#nixosConfigurations.host.config.hardening.report
```

The report lists every rule with its catalog metadata, status, reason and
implementation state, plus a count per status.
## Other catalogs

`lib.mkCatalog` builds a catalog module from a name, the catalog data, a set
of profiles and the modules that implement its rules. A repository that owns
the options a catalog touches defines that catalog with this function.

## Checks

```sh
nix fmt
nix flake check -L
```
