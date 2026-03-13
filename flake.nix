{
  description = "Nacrypt - A simple and easy to use file encryption utility";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        in
        {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "nacrypt";
          version = "1.2.7";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.rustPlatform.bindgenHook
          ];

          buildInputs = [
            pkgs.libsodium
          ];

          SODIUM_USE_PKG_CONFIG = "1";
		  SODIUM_SHARED = "1";

          
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            rustfmt
            rustc
            rust-analyzer
            cargo
            clippy
            strace
            pkg-config
          ];
        };
      }
    );
}
