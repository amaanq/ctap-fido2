{
  description = "CTAP2 client for FIDO2 hmac-secret over USB HID.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      inherit (inputs) self;
      inherit (lib) genAttrs optionals;

      eachSystem =
        f: genAttrs lib.systems.flakeExposed (system: f inputs.nixpkgs.legacyPackages.${system});

      # Fenix only ships binaries for tier-1 arches, so fall back to nixpkgs's rustc
      # everywhere else.
      hasFenix = system: inputs.fenix.packages ? ${system};
      hasMold = plat: plat.isLinux && (plat.isx86_64 || plat.isAarch64);

      buildContext = pkgs: rec {
        inherit (pkgs.stdenv.hostPlatform) system;
        fenixPkgs = if hasFenix system then inputs.fenix.packages.${system} else null;
        rustPlatform =
          if fenixPkgs != null then
            pkgs.makeRustPlatform {
              cargo = fenixPkgs.latest.cargo;
              rustc = fenixPkgs.latest.rustc;
            }
          else
            pkgs.rustPlatform;
        clippy = if fenixPkgs != null then fenixPkgs.latest.clippy else pkgs.clippy;
        nativeBuildInputs = [
          pkgs.pkg-config
        ]
        ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
          pkgs.clang
          pkgs.mold
        ];
        # hidapi needs libudev on Linux.
        buildInputs = optionals pkgs.stdenv.hostPlatform.isLinux [
          pkgs.udev
        ];
      };
    in
    {
      packages = eachSystem (
        pkgs:
        let
          ctx = buildContext pkgs;
        in
        {
          ctap-fido2 = ctx.rustPlatform.buildRustPackage {
            pname = "ctap-fido2";
            src = ./.;
            version = "0.1.0";

            cargoLock.lockFile = ./Cargo.lock;

            inherit (ctx) nativeBuildInputs buildInputs;

            meta = {
              description = "CTAP2 client for FIDO2 hmac-secret over USB HID";
              homepage = "https://github.com/amaanq/ctap-fido2";
              license = lib.licenses.mit;
              maintainers = [ lib.maintainers.amaanq ];
            };
          };

          default = self.packages.${ctx.system}.ctap-fido2;
        }
      );

      checks = eachSystem (
        pkgs:
        let
          ctx = buildContext pkgs;
        in
        {
          clippy = ctx.rustPlatform.buildRustPackage {
            pname = "ctap-fido2-clippy";
            src = ./.;
            version = "0.1.0";

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = ctx.nativeBuildInputs ++ [ ctx.clippy ];
            inherit (ctx) buildInputs;

            buildPhase = ''
              runHook preBuild
              cargo clippy --all-targets --locked -- -D warnings
              runHook postBuild
            '';
            doCheck = false;
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              runHook postInstall
            '';
          };
        }
      );

      devShells = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          toolchain =
            if hasFenix system then
              (inputs.fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
                "rust-analyzer"
              ])
            else
              pkgs.rustc;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nixfmt
              pkgs.pkg-config
              pkgs.taplo
              toolchain
            ]
            ++ optionals pkgs.stdenv.hostPlatform.isLinux [
              # hidapi needs libudev on Linux.
              pkgs.udev
            ]
            ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
              pkgs.clang
              pkgs.mold
            ];
          };
        }
      );
    };
}
