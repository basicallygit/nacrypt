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
				stdenv = pkgs.clangStdenv;
				in
				{
				packages.default = pkgs.stdenv.mkDerivation {
					pname = "nacrypt";
					version = "1.2.0";
					src = ./.;

					nativeBuildInputs = [
						pkgs.clang
						pkgs.gnumake
					];

					buildInputs = [
						pkgs.libsodium
						pkgs.libseccomp
						pkgs.libcap
					];

					makeFlags = [
						"CLANG_CFI=y"
						"TIGHTENED_SANDBOX=y"
					];

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
						strace
					];
				};
			}
		);
}
