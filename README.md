# ttp: TOTP Codes in the Shell

Generate two factor authentication codes that are compatible with
Google Authenticator (a.k.a. RFC6238 TOTP) from the shell.

## References

[RFC6238](https://tools.ietf.org/html/rfc6238)

## Installing

Download `ttp` and its checksum from the
[latest release](https://github.com/dterei/ttp/releases/latest), check
them, and install `ttp` somewhere on your path (e.g., `$HOME/bin`):

    curl -fsSLO https://github.com/dterei/ttp/releases/latest/download/ttp
    curl -fsSLO https://github.com/dterei/ttp/releases/latest/download/SHA256SUMS
    sha256sum -c SHA256SUMS       # on macOS: shasum -a 256 -c SHA256SUMS
    gh attestation verify ttp --repo dterei/ttp
    chmod +x ttp && mv ttp ~/bin/

The checksum catches a damaged download. The
[build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations),
checked with the [GitHub CLI](https://cli.github.com/), proves the file
was built from this repository by its release workflow and not changed
since. Skip that step if you don't have `gh`.

`ttp` is a self-contained bash script; the TOTP code calculation
(base32 decoding, and HMAC with SHA-1, SHA-256 or SHA-512) is
implemented in bash itself.

### Required dependencies

| Dependency | Used for |
| --- | --- |
| bash | Running `ttp`. |
| [GnuPG](https://gnupg.org/) (`gpg`) | Encrypting the stored keys with a passphrase. |
| `mkdir` | Creating the key directory. |
| `mv` | Replacing a key file when re-encrypting it. |
| `date` | Reading the current time, on bash older than 5.0 only. |

`mkdir`, `mv` and `date` come with every Linux distribution and macOS.

### Optional dependencies

`ttp` uses these if they are installed and works without them.

| Dependency | Used for | Without it |
| --- | --- | --- |
| `wl-copy` (from [wl-clipboard](https://github.com/bugaevc/wl-clipboard); Linux, Wayland) | Copying the code to the clipboard. | The code is printed, or copied with `xclip`/`xsel` if available. |
| `xclip` or `xsel` (Linux, X11) | Copying the code to the clipboard. | The code is printed. |
| `pbcopy` (built into macOS) | Copying the code to the clipboard. | The code is printed. |
| `zbarimg` (from [zbar](https://github.com/mchehab/zbar)) | `-c`: reading a QR code from the screen (X11 only). | You type in the key. |
| [`qrencode`](https://fukuchi.org/works/qrencode/) | `-v`: showing a key as a QR code. | `-v` doesn't work. |
| `display` (from [ImageMagick](https://imagemagick.org/)), `xv` or `xloadimage` | `-v`: showing the QR code in a window (X11 only). | The QR code is drawn in the terminal. |
| `gsettings` (GNOME) | Warning you if GNOME is set to cache your GPG passphrase indefinitely. | The check is skipped. |

## Using

* `ttp [-x]` _service_ - get token for _service_
* `ttp -[x]c` _service_ - record seed for new _service_
* `ttp -[x]v` _service_ - view qrcode for _service_
* `ttp -[x]r` _service_ - re-encrypt _service_'s key with current settings
* `ttp -[x]R` - re-encrypt all keys with current settings and one new passphrase
* `ttp -[x]C` - import all keys from a Google Authenticator export
* `ttp -l` - list services setup
* `ttp --version` - print the version of `ttp`
* `ttp --completion bash|zsh` - print a tab completion script for your shell

Codes are copied to the clipboard you paste from with Ctrl-V (or
Cmd-V on macOS) when a clipboard tool is available. Adding `x` to a flag
(`-x`, `-xc`, `-xv`, `-xr`, `-xR`, `-xC`) disables use of X11 and
Wayland even when they are available: codes are printed, keys are typed
or pasted in, and QR codes are drawn in the terminal.

If a code has 5 seconds or less left, `ttp` says so, since a code
pasted that late can arrive after it has expired. Many sites accept a
code for a little while after that, but if one is rejected, run `ttp`
again for the next code.

All your keys share one passphrase. The first key you add asks for it
twice; after that, `ttp -c` and `ttp -C` ask once and check it opens
your newest key, so a typo can't save a key you can't open.

Keys are encrypted with AES-256, and your passphrase is hashed with
SHA-512 as many times as gpg allows. Keys saved by older versions of
`ttp`, or with older gpg, may use weaker settings: `ttp -l`, and getting
a code, warn about these. `ttp -r` _service_ re-encrypts one with the
current settings, keeping its passphrase, and only replaces the key file
once the new one is written.

`ttp -R` re-encrypts every key at once, and is how to change your
passphrase. Keys saved by older versions of `ttp` may each have their
own passphrase; `ttp -R` gives them all the same one. It asks for your current
passphrase and a new one (which can be the same), then tries each key
with every passphrase that has worked so far. It only asks about a key
that none of them open, so you type each old passphrase once; leave the
answer empty to skip that key. Keys that are skipped, or can't be
re-encrypted, are left as they were and listed at the end, and running
`ttp -R` again is safe.

Service names are used as file names, so they can't contain `/` or
start with `-` or `.`.

A key can be a base32 secret or an `otpauth://totp/` URI, such as the
ones in QR codes. URIs may set `digits` (1 to 10), `period`, and
`algorithm`: `SHA1` (the default), `SHA256` or `SHA512`.

### Tab completion

`ttp` can complete service names and flags when you press Tab. Add one
line to your shell's startup file:

    # ~/.bashrc
    eval "$(ttp --completion bash)"

    # ~/.zshrc, after compinit
    source <(ttp --completion zsh)

Completion lists the files in your key directory; it doesn't decrypt
anything or ask for your passphrase.

### Importing from Google Authenticator

In Google Authenticator, choose "Transfer accounts", then "Export
accounts". The app shows one or more QR codes, each holding several
accounts. Run `ttp -C` with the QR codes on screen (this needs X11 and
`zbarimg`), or paste their `otpauth-migration://` URIs when asked. For
each account, `ttp` suggests a name made from its issuer, such as
`github`: press Enter to use it, type another name, or answer `n` to
skip the account. It then asks for your keys' passphrase, once.

To import a single account, run `ttp -c` _service_ with the QR code on
screen, and answer `y` when `ttp` asks about that account, or paste the
code's URI at the key prompt.

Counter-based (HOTP) accounts are skipped, and accounts using MD5 are
rejected.

## OS X and GPG Tools

Mac OS X users may be using the [GPG Tools](https://gpgtools.org/)
distribution. For some strange reason, this package doesn't detect
when you are running in a terminal session without a display (e.g.,
SSH), so by default, it always launches a GUI for key entry. Which
makes `ttp` impossible to use over SSH on OS X.

To fix this, you'll want to tell it to uses a curses display for
passpharse entry:

    export PINENTRY_USER_DATA="USE_CURSES=1"

A good way to decide when to export this variable is by detecting it
`SSH_CONNECTION` is a non-empty string.

## Get involved!

We are happy to receive bug reports, fixes, documentation enhancements,
and other improvements.

Please report bugs via the
[github issue tracker](https://github.com/dterei/ttp/issues).

Master [git repository](https://github.com/dterei/ttp):

* `git clone https://github.com/dterei/ttp.git`

### Running the tests

    bash test/run-tests.sh

The tests need only bash and gpg, and leave your keys alone: they use a
temporary directory and their own GnuPG home. If
[`oathtool`](https://www.nongnu.org/oath-toolkit/) is installed, they
also check `ttp`'s codes against it, and if zsh is, its tab completion.
They run `ttp` with whichever bash runs the test script, so
`/bin/bash test/run-tests.sh` on macOS tests the system's bash 3.2.

For every pull request, GitHub Actions runs the tests on Linux and macOS
and with each bash release from 3.2 to 5.3, and runs
[ShellCheck](https://www.shellcheck.net/) on the scripts.

## Authors

David Terei.

## Acknowledgments

`ttp` is a fork of [`ga`](https://github.com/scslab/ga), written by
David Mazières.

## License

Copyright 2014-2015 David Mazières.
Copyright 2026 David Terei.

`ttp` is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your
option) any later version. See [COPYING](COPYING) for the full text.

This program comes with ABSOLUTELY NO WARRANTY. This program REDUCES
YOUR SECURITY by making two-factor authentication not really two
factor. You may decide using this program is useful where the
alternative is only one factor authentication, but that is your
decision alone. The author DOES NOT REPRESENT THIS SOFTWARE AS MORE
SECURE THAN ANY ALTERNATIVE; it most likely is less secure.
