{
  description = "LID-DS evaluation lab: scenario targets, agent pentest harness and eBPF telemetry collector";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            # the cc-wrapper's hardening flags (-fstack-protector-strong,
            # -fzero-call-used-regs, ...) are rejected by the BPF target
            hardeningDisable = [ "all" ];
            packages = with pkgs; [
              # collector toolchain (vmlinux.h is generated from the running
              # kernel's BTF, so the collector is built on the host: make collector)
              clang
              bpftools
              libbpf
              linuxHeaders
              gnumake
              # lab operation
              docker
              docker-compose
              python3
              openssl
              gawk
            ];
            ARCH_INCLUDE = "${pkgs.linuxHeaders}/include";
          };
        });
    };
}
