{ config, lib, ... }:
{
  options.hardening.report = lib.mkOption {
    type = lib.types.attrsOf lib.types.raw;
    default = { };
    description = "State of every rule of every catalog, keyed by catalog name.";
  };

  config._module.args.hardening = {
    enforced =
      catalog: id:
      config.hardening.${catalog}.enable && config.hardening.${catalog}.rules.${id}.status == "enforced";
  };
}
