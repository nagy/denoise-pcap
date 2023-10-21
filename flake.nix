{
  description = "Filtering Internet background noise from network captures";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  inputs.pcap-utils.url = "github:nagy/pcap-utils";
  inputs.pcap-utils.inputs.nixpkgs.follows = "nixpkgs";
  inputs.haumea.inputs.nixpkgs.follows = "nixpkgs";

  inputs.nix-bundle.url = "github:matthewbauer/nix-bundle";
  inputs.nix-bundle.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, nur, pcap-utils, haumea, nix-bundle }@inputs:
    let
      pkgs = import nixpkgs ({
        system = "x86_64-linux";
        overlays = [ nur.overlay ];
      });
      inherit (pkgs) system lib;
    in
    let
      nixos-lib = import (nixpkgs + "/nixos/lib") { };
      scope = lib.makeScope pkgs.newScope (self:
        haumea.lib.load {
          src = ./nix;
          inputs = (builtins.removeAttrs pkgs [ "self" "super" "root" ]) // {
            flake-self = inputs.self;
            inherit nixos-lib;
          };
          loader = haumea.lib.loaders.callPackage;
          transformer = haumea.lib.transformers.liftDefault;
        });
    in
    let
      hyenvDev = pkgs.hy.withPackages (ps:
        with ps; [
          hyrule
          pcap-utils.outputs.packages.${system}.default
          tqdm
          scapy
          pytest
          pytest-golden
        ]);
    in
    {
      lib = scope;
      packages.${system} = {
        default = pkgs.python3.pkgs.buildPythonPackage {
          pname = "denoise-pcap";
          version = "1";
          format = "pyproject";
          src = lib.cleanSourceWith {
            src = self;
            filter = name: type:
              let name' = builtins.baseNameOf name;
              in name' == "denoise_pcap" || name' == "pytest.ini" || name'
                == "pyproject.toml" || (lib.hasSuffix ".py" name')
                || (lib.hasSuffix ".hy" name');
          };
          propagatedBuildInputs = with pkgs.python3.pkgs; [
            hy
            hyrule
            pcap-utils.outputs.packages.${system}.default
            tqdm
            flit
          ];
          pythonImportsCheck = [ "denoise_pcap" ];
        };
        bundle = nix-bundle.bundlers.nix-bundle ({
          inherit system;
          program = lib.getExe self.packages.${system}.default;
        });
      } // (
        # add all packages from lib/
        lib.filterAttrs (n: v: lib.isDerivation v) scope);
      devShells.${system}.default = pkgs.mkShell ({
        HYSTARTUP = pkgs.writeText "startup.hy" ''
          (eval-and-compile
            (import sys os))
          (eval-when-compile
            (require hyrule * :readers *))
          (import hyrule
                  denoise-pcap *)
          (setv repl-output-fn hyrule.pformat)
          (setv nom (Pcap.from-file   "result/nomarker.pcap"))
          (setv ben (Pcap.from-file   "result/benign.pcap"))
          (setv mal (Pcap.from-file   "result/malicious.pcap"))
        '';
        buildInputs = [ hyenvDev ];
      } // scope.testEnvMap);
      checks.${system}.default = pkgs.stdenv.mkDerivation ({
        name = "check";
        src = self;
        nativeBuildInputs = [ hyenvDev pkgs.wireshark-cli ];
        buildPhase = ''
          pytest --verbose
          touch $out
        '';
        dontInstall = true;
      } // scope.testEnvMap);
    };
}
