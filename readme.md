# PyZTrust.sh

A macOS shell script that merges your corporate Zscaler root certificate with your Python CA bundle, so that Python tools (`pip`, `requests`, etc.) can verify HTTPS connections without SSL errors when traffic is being intercepted by Zscaler.

## What it does

If your company uses Zscaler, it intercepts and re-signs HTTPS traffic with its own root certificate. Most apps trust this automatically because Zscaler is installed in the macOS system keychain, but Python's own certificate store (used by `pip`, `requests`, `urllib`, etc.) doesn't read from the keychain, so Python tools start failing with SSL verification errors.

This script fixes that by:

1. Exports the **Zscaler Root CA** certificate from your macOS keychain
2. Locates all installed Python versions on your machine (including their associated CA bundles). You will be asked to confirm which version will serve as the master export for the next step (note the CA bundle will vary, depending on if python was installed via homebrew [ssl module] or manually from python.org [certifi module])
3. Merges the Zscaler certificate (from step-1) into the nominated CA bundle (from step-2).
4. In your shell startup file(s) (~/.zshrc and/or ~/.bash_profile), points well-known environment variables (SSL_CERT_FILE + REQUESTS_CA_BUNDLE + PIP_CERT) at the merged bundle from step-3.

The script is interactive: it will ask for confirmation before deleting any pre-existing setup, before installing `certifi`, and before using a given Python installation. Every shell profile it touches is backed up first, and any failure during the shell-profile update triggers an automatic rollback (see [Rollback](#rollback) below).

## Requirements

- macOS (the script checks for this and exits if not).
- The **Zscaler Root CA** certificate already installed in your macOS keychain under that exact name (this is usually pushed to your machine by IT).
- At least one Python 3 installation on your `PATH`.
- `openssl` (ships with macOS).

## Usage

```bash
chmod +x PyZTrust.sh
./PyZTrust.sh
```

Run it from a normal Terminal window (not piped from another process), since it needs to prompt you for input. Walk through the prompts:

- If `~/corp_cert` already exists from a previous run, you'll be asked whether it's OK to delete and regenerate it.
- For each Python installation found, you'll see its version and path, and you'll be asked whether to use it.
- If a Python installation doesn't have `certifi` and no usable bundle is found via the `ssl` module, you'll be asked whether to install `certifi` for it.

The script stops at the **first** Python installation you accept and that successfully produces a valid merged bundle — it does not process every Python version it finds.

Each prompt has a 60-second timeout. If you don't respond in time, the script aborts without making further changes.

### After it finishes

Restart your terminal, or run:

```bash
source ~/.zshrc
source ~/.bash_profile
```

to pick up the new environment variables in your current session.

## If you don't have a `~/.zshrc` or `~/.bash_profile`

The script only edits `~/.zshrc` and `~/.bash_profile`, and only if they already exist. If neither file is present, it will still generate the merged certificate bundle, but it will print a warning at the end telling you that no shell profile was updated, since there's nothing for it to safely edit.

In that case, create one of those files yourself and add the source line it gives you, for example:

```bash
touch ~/.zshrc
{ echo "# >>> Zscaler combined CA (managed by PyZTrust.sh) >>>"
echo "export SSL_CERT_FILE="~/corp_cert/combined-ca.pem""
echo "export REQUESTS_CA_BUNDLE="~/corp_cert/combined-ca.pem""
echo "export PIP_CERT="~/corp_cert/combined-ca.pem""
echo "# <<< Zscaler combined CA (managed by PyZTrust.sh) <<<" } >> ~/.zshrc
```

(`zsh` is the default shell on modern macOS, so `~/.zshrc` is usually the right choice unless you specifically use `bash`.)

## If you use Fish

The script does not modify Fish's configuration, since Fish doesn't use the same `export VAR=value` syntax as `zsh`/`bash`. It will print the equivalent commands at the end of a successful run. Add them to `~/.config/fish/config.fish` manually:

```fish
set -x SSL_CERT_FILE "~/corp_cert/combined-ca.pem"
set -x REQUESTS_CA_BUNDLE "~/corp_cert/combined-ca.pem"
set -x PIP_CERT "~/corp_cert/combined-ca.pem"
```

Then restart your terminal, or run `source ~/.config/fish/config.fish`.

## Rollback

**Automatic rollback during a run:** while updating `~/.zshrc` and `~/.bash_profile`, the script backs up each file before touching it. If any file fails to update correctly, the script automatically restores every shell profile it had already modified during that run from its backup, so you're never left with a partially-updated set of profiles. You don't need to do anything in this case — just re-run the script once the underlying problem (e.g. a permissions issue) is resolved.

**Manually reverting after a successful run:** to undo the changes entirely, remove the source line from your shell profile(s) and delete the generated files. The script prints the exact commands for this at the end of every successful run, in the form:

```bash
perl -i -ne 'print unless /^# >>> Zscaler combined CA.*>>>$/ .. /^# <<< Zscaler combined CA.*<<<$/' "~/.zshrc"
perl -i -ne 'print unless /^# >>> Zscaler combined CA.*>>>$/ .. /^# <<< Zscaler combined CA.*<<<$/' "~/.bash_profile"
```

(one line per profile file that was actually updated). After running the relevant line(s), also remove the generated directory if you want a completely clean slate:

```bash
rm -rf ~/corp_cert
```

If you added a Fish snippet manually, remove those three `set -x` lines from `~/.config/fish/config.fish` as well.

## Notes

- The script uses a lock file (`/tmp/combine_zscaler_cert.lock`) to prevent two copies from running at the same time.
- All files it creates are restricted to owner-only permissions (`umask 077`).
- Re-running the script is safe: it detects and offers to replace a previous `~/corp_cert` setup, and removes any old source line from your shell profiles before adding the current one, so you won't end up with duplicates.
