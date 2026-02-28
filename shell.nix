let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-25.11";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

pkgs.mkShellNoCC {
  packages = with pkgs; [
    (python3.withPackages (ps: with ps; [
      pytest
      pytest-cov
      pytest-mock
      pytest-asyncio
      requests
      textual
      textual-dev
    ]))
  ];
}