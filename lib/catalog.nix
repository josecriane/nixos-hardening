{ lib }:
{
  name,
  catalog,
  defaultProfile,
  profiles,
  areas ? [ ],
  groups ? { },
}:
{ config, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.hardening.${name};
  ruleModule = import ./rule.nix;

  mkRuleOption =
    id: rule:
    mkOption {
      type = types.submodule ruleModule;
      default = { };
      description = "${id} (${rule.severity}): ${rule.title}";
    };

  profileOverrides = lib.mapAttrsToList (
    profile: rules:
    lib.mkIf (cfg.profile == profile) (lib.mapAttrs (_: lib.mapAttrs (_: lib.mkOverride 900)) rules)
  ) profiles;

  needsReason =
    id: rule:
    lib.optional (cfg.enable && rule.implemented && rule.status != "enforced" && rule.reason == null) {
      assertion = false;
      message = "hardening.${name}.rules.${id} has status ${rule.status} and no reason.";
    };

  needsImplementation =
    id: rule:
    lib.optional (cfg.enable && rule.status == "enforced" && !rule.implemented) {
      assertion = false;
      message = "hardening.${name}.rules.${id} is enforced but no module implements it.";
    };

  statuses = import ./statuses.nix;

  groupModule = {
    options = {
      status = mkOption {
        type = types.nullOr (types.enum statuses);
        default = null;
        description = "Status applied to every rule of the group. A rule set explicitly keeps its own value.";
      };

      reason = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Reason applied to every rule of the group.";
      };
    };
  };

  checkedGroups = lib.mapAttrs (
    group: ids:
    assert lib.assertMsg (lib.all (
      id: catalog.rules ? ${id}
    ) ids) "hardening.${name}: group ${group} names a rule that is not in the catalog.";
    ids
  ) groups;

  mkGroupOption =
    group: ids:
    mkOption {
      type = types.submodule groupModule;
      default = { };
      description = "Status and reason of the ${group} rules: ${lib.concatStringsSep ", " ids}.";
    };

  groupOverrides = lib.mapAttrsToList (
    group: ids:
    let
      value = cfg.groups.${group};
    in
    lib.mkIf (value.status != null) (
      lib.genAttrs ids (
        _:
        {
          status = lib.mkOverride 850 value.status;
        }
        // lib.optionalAttrs (value.reason != null) { reason = lib.mkOverride 850 value.reason; }
      )
    )
  ) checkedGroups;

  groupNeedsReason =
    group: value:
    lib.optional
      (cfg.enable && value.status != null && value.status != "enforced" && value.reason == null)
      {
        assertion = false;
        message = "hardening.${name}.groups.${group} has status ${value.status} and no reason.";
      };
in
{
  imports = areas;

  options.hardening.${name} = {
    enable = lib.mkEnableOption "the ${catalog.meta.title} catalog";

    profile = mkOption {
      type = types.enum (lib.attrNames profiles);
      default = defaultProfile;
      description = "Set of default rule statuses for a class of machine.";
    };

    rules = lib.mapAttrs mkRuleOption catalog.rules;

    groups = lib.mapAttrs mkGroupOption checkedGroups;
  };

  config = {
    assertions = lib.concatLists (
      lib.mapAttrsToList (id: rule: needsReason id rule ++ needsImplementation id rule) cfg.rules
      ++ lib.mapAttrsToList groupNeedsReason cfg.groups
    );

    hardening.${name}.rules = lib.mkMerge (profileOverrides ++ groupOverrides);

    hardening.report.${name} = {
      inherit (catalog) meta;
      inherit (cfg) enable profile;
      groups = checkedGroups;
      rules = lib.mapAttrs (
        id: rule:
        catalog.rules.${id}
        // {
          inherit (rule) status reason implemented;
        }
      ) cfg.rules;
      summary = lib.genAttrs statuses (
        status: lib.count (rule: rule.status == status) (lib.attrValues cfg.rules)
      );
    };
  };
}
