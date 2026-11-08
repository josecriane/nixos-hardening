{ lib, ... }:
{
  options = {
    status = lib.mkOption {
      type = lib.types.enum (import ./statuses.nix);
      default = "deferred";
      description = "Whether this system applies the rule. Any value other than enforced needs a reason.";
    };

    reason = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Why the rule is not enforced on this system.";
    };

    implemented = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether a module knows how to enforce the rule.";
    };
  };
}
