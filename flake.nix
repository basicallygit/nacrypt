{
  description = "Nix flake for nacrypt - A simple file encryption/decryption program";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.clangStdenv;
	    in
	    {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "nacrypt";
          version = "1.1.0";
          src = ./.;

          nativeBuildInputs = [
            pkgs.clang
            pkgs.gnumake
          ];

          buildInputs = [
            pkgs.libsodium
            pkgs.libseccomp
          ];

          makeFlags = [ "CLANG_CFI=y" ];

          installPhase = ''
            mkdir -p $out/bin
            cp nacrypt $out/bin/
          '';
        };

        devShells.default = pkgs.mkShell.override { inherit stdenv; } {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            lldb
            clang-tools
            valgrind
          ];
        };
      }
    );
}
