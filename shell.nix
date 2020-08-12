# Use the Nix package manager to set up a self-contained working environment:
#
#   0) Install the Nix package manager
#   1) Save these contents to a file called shell.nix in some directory
#   2) Enter the directory
#   3) Execute nix-shell to drop into a shell with the dependencies installed
#   4) Hack to your heart's content
#   5) "exit" to return to the previous shell environment
#
{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    libsodium
    cgreen
  ];
}
