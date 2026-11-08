{ lib }:
{
  name,
  catalog,
  defaultProfile,
  profiles,
  areas ? [ ],
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
  };

  config = {
    assertions = lib.concatLists (
      lib.mapAttrsToList (id: rule: needsReason id rule ++ needsImplementation id rule) cfg.rules
    );

    hardening.${name}.rules = lib.mkMerge profileOverrides;

    hardening.report.${name} = {
      inherit (catalog) meta;
      inherit (cfg) enable profile;
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
