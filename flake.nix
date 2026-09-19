{
  description = "sipr — SIP testing tool and traffic generator in Rust, compatible with SIPp scenarios";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # Single source of truth: the workspace version in Cargo.toml.
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
    in
    {
      packages = forAllSystems (pkgs: rec {
        sipr = pkgs.rustPlatform.buildRustPackage {
          pname = "sipr";
          inherit version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          # Build only the binary crate; the workspace's library crates come
          # along as its dependencies.
          cargoBuildFlags = [ "-p" "sipr" ];

          # The test suite binds UDP/TCP sockets on loopback and spawns peers,
          # which the Nix build sandbox does not allow. Tests run in CI.
          doCheck = false;

          meta = {
            description = "SIP testing tool and traffic generator, compatible with SIPp scenarios";
            homepage = "https://github.com/tareqmy/sipr";
            changelog = "https://github.com/tareqmy/sipr/blob/master/CHANGELOG.md";
            license = pkgs.lib.licenses.mit;
            mainProgram = "sipr";
          };
        };
        default = sipr;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
            cargo-deny
          ];
        };
      });
    };
}
