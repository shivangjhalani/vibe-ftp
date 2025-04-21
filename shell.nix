{ pkgs ? import <nixpkgs> {
    config = {
      allowUnfree = true;
    };
  }
}:

pkgs.mkShell {
  packages = with pkgs; [
    gcc
    cmake
    openssl # Add openssl development package
  ];
}
