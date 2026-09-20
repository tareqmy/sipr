# Installation

Every release ships prebuilt binaries for macOS (Intel and Apple Silicon),
Linux (x86_64 and arm64, fully static musl builds) and Windows (x86_64), so
nothing needs to be compiled. Pick whichever method suits your machine.

## Homebrew (macOS, Linux)

```sh
brew tap tareqmy/tap
brew install sipr
```

The formula lives in the [tareqmy/homebrew-tap](https://github.com/tareqmy/homebrew-tap)
repository and is updated by CI on every release. If Homebrew reports
"No available formula", run `brew tap tareqmy/tap` first.

## Shell script (macOS, Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.sh | sh
```

The script detects the platform, downloads the matching release archive, and
installs `sipr` into `/usr/local/bin` when that is writable, otherwise into
`~/.local/bin`. Set `VERSION=v0.27.1` in the environment to pin a release.
Read the script before piping it to a shell; its checksum is in
`scripts/install.sh.sha256`.

Uninstall the same way:

```sh
curl -fsSL https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/uninstall.sh | sh
```

## PowerShell (Windows)

```powershell
irm https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.ps1 | iex
```

Installs `sipr.exe` into `%USERPROFILE%\.sipr\bin` and adds that directory to
the user PATH; no administrator rights are needed. `scripts/uninstall.ps1`
reverses it.

## Chocolatey (Windows)

Not published yet. The package definition is in `dist/chocolatey/` and the
release workflow pushes it once a `CHOCO_API_KEY` secret is set; until then,
use the PowerShell installer above.

## Cargo

```sh
cargo install sipr
```

Builds from the crates.io sources with a stock Rust toolchain (1.85 or newer).
No system libraries are needed: TLS is pure-Rust `rustls`, SRTP and AKA are
in-tree, and pcap files are read without libpcap.

## Nix (flake)

```sh
nix run github:tareqmy/sipr -- -sn uac -r 10 -m 100 127.0.0.1:5060
nix profile install github:tareqmy/sipr
```

In a flake-based NixOS or home-manager configuration:

```nix
inputs.sipr.url = "github:tareqmy/sipr";
# ...
environment.systemPackages = [ inputs.sipr.packages.${pkgs.system}.default ];
```

`nix develop` gives a shell with the Rust toolchain and `cargo-deny`.

## Release archives

Every release on the
[releases page](https://github.com/tareqmy/sipr/releases) carries one archive
per target, named `sipr-vX.Y.Z-<target>.tar.gz` (`.zip` on Windows), holding
the single `sipr` binary. Download, extract, and put it on your PATH.

## From source

```sh
git clone https://github.com/tareqmy/sipr && cd sipr
cargo build --release        # binary at target/release/sipr
cargo install --path .       # or install it onto your PATH
```

SCTP transport (`-t s1|sn`) is a Linux-only cargo feature and is not in the
prebuilt binaries: `cargo build --release --features sctp`.

## Verifying

```sh
sipr --version
sipr -sn uas -p 5060                          # answer calls
sipr -sn uac -r 10 -m 100 127.0.0.1:5060      # place 100 calls at 10 cps
```
