{ lib }:
{
  ruleModule = import ./rule.nix;
  mkCatalog = import ./catalog.nix { inherit lib; };
}
