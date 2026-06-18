#!/usr/bin/env bash
set -e
umask 077

# Restrict all file creation to owner-only from the start,
# eliminating the window between write and chmod.

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "✘ This script requires macOS — $(uname -s) is not supported."
    exit 1
fi

# ---------------------------------------------------------------------------
# combine_zscaler_cert.sh
#
# Exports the corporate Zscaler root certificate from the macOS keychain,
# merges it with a selected Python CA bundle, and configures shell
# environments to use the combined trust store.
# ---------------------------------------------------------------------------

if [[ -z "$HOME" || "$HOME" != /* ]]; then
    echo "✘ \$HOME is not set to an absolute path — aborting."
    exit 1
fi

# Lock file lives under a per-user directory (not shared /tmp) so a
# malicious local user can't pre-create a directory at a predictable
# shared path and permanently deny this script to other users.
LOCK_DIR="${TMPDIR:-/tmp}"
LOCK_DIR="${LOCK_DIR%/}/combine_zscaler_cert.$(id -u)"
mkdir -p -m 700 "$LOCK_DIR" 2>/dev/null || true
LOCK_FILE="$LOCK_DIR/lock"
if ! mkdir "$LOCK_FILE" 2>/dev/null; then
    echo "✘ Another instance of this script is already running. Aborting."
    exit 1
fi

# Set traps immediately after acquiring the lock — no other code may run
# between lock acquisition and trap registration, or a kill in that window
# would leave a stale lock behind forever.
TMP_FILES=()
rc_update_failed="false"
UPDATED_RC_BACKUPS=()
CERT_FILE_NEEDS_CLEANUP="false"
EXIT_CODE=0
COMBINED_CERT=""

cleanup() {
    for f in "${TMP_FILES[@]}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
    if [[ "$CERT_FILE_NEEDS_CLEANUP" == "true" && "${EXIT_CODE}" != "0" && -n "$COMBINED_CERT" && -f "$COMBINED_CERT" ]]; then
        rm -f "$COMBINED_CERT"
    fi
}

on_interrupt() {
    trap - INT TERM EXIT
    EXIT_CODE=1
    cleanup
    rm -rf "$LOCK_FILE"
    echo -e "\n✘ Script interrupted."
    exit 1
}

trap 'EXIT_CODE=$?; cleanup; rm -rf "$LOCK_FILE"' EXIT
trap on_interrupt INT TERM

prune_tmp_file_record_only() {
    local target="$1" new_list=()
    for f in "${TMP_FILES[@]}"; do
        [[ "$f" != "$target" ]] && new_list+=("$f")
    done
    TMP_FILES=("${new_list[@]}")
}

prune_tmp_file() {
    local target="$1" new_list=()
    for f in "${TMP_FILES[@]}"; do
        if [[ "$f" == "$target" ]]; then
            [[ -f "$f" ]] && rm -f "$f"
        else
            new_list+=("$f")
        fi
    done
    TMP_FILES=("${new_list[@]}")
}

CERT_DIR="$HOME/corp_cert"
ZSCALER_CERT="$CERT_DIR/zscaler.pem"
COMBINED_CERT="$CERT_DIR/combined-ca.pem"
CORP_SSL_ENV="$CERT_DIR/.corp_ssl_env.sh"
SOURCE_LINE="source \"$CORP_SSL_ENV\""

[[ "$CERT_DIR" == "$HOME/corp_cert" && "$CERT_DIR" != "/" ]] || {
    echo "✘ Unexpected CERT_DIR value — aborting."
    exit 1
}

INTERACTIVE=false
if [[ -t 0 ]]; then
    INTERACTIVE=true
fi

if [[ -d "$CERT_DIR" ]]; then
    echo "⚠ The directory $CERT_DIR already exists."
    echo "  Re-generating the certificates will briefly disrupt active Python sessions."
    echo "" 

    confirm_delete="n"
    if [[ "$INTERACTIVE" == "true" ]]; then
        set +e
        read -r -t 60 -p "👉 Is it OK to delete the existing directory...? [y/n]: " confirm_delete
        read_status=$?
        set -e

        if (( read_status > 128 )); then
            echo -e "\n✘ Confirmation timed out. Aborting to protect current configuration."
            exit 1
        fi
        # If the user pressed Enter, assign your intended default
        [[ -z "$confirm_delete" ]] && confirm_delete="n"
    fi

    case "$confirm_delete" in
        [Yy])
            echo "Proceeding with directory recreation..."
            echo ""
            rm -rf "$CERT_DIR"
            ;;
        *)
            echo "✘ Operation cancelled. No files were modified."
            echo ""
            exit 0
            ;;
    esac
fi

if ! mkdir -m 700 -p "$CERT_DIR"; then
    echo "✘ Could not create $CERT_DIR — check permissions on $HOME"
    exit 1
fi

RC_FILES=()
[[ -f "$HOME/.zshrc" ]] && RC_FILES+=("$HOME/.zshrc")
[[ -f "$HOME/.bash_profile" ]] && RC_FILES+=("$HOME/.bash_profile")

if ! security find-certificate -c "Zscaler Root CA" -p > "$ZSCALER_CERT" 2>/dev/null; then
    echo "✘ Could not find 'Zscaler Root CA' in the macOS keychain."
    echo "Make sure that the Zscaler certificate is installed and has the right name"
    exit 1
fi

if [[ ! -s "$ZSCALER_CERT" ]]; then
    echo "✘ Zscaler cert file is empty — certificate export may have failed silently."
    exit 1
fi
echo "✔ Zscaler cert written to $ZSCALER_CERT"
echo ""

available_versions=()
broken_versions=()
skipped_versions=()
selected_python_env=""

python_candidates=("3")
for version in 3.14 3.13 3.12 3.11 3.10 3.9; do
    python_candidates+=("$version")
done

# ---------------------------------------------------------------------------
# Phase 1: Discover a usable Python installation and CA bundle.
#
# Preference order:
#   1. ssl.get_default_verify_paths().openssl_cafile
#   2. certifi.where()
#
# Once a valid CA bundle is found, append the Zscaler certificate,
# validate the resulting bundle, and generate the shell environment file.
# ---------------------------------------------------------------------------
for version in "${python_candidates[@]}"; do
    cmd="python$version"

    if ! command -v "$cmd" >/dev/null 2>&1; then
        continue
    fi

    actual_version=$("$cmd" --version 2>&1) || { echo "   ✘ $cmd --version failed — skipping"; broken_versions+=("$cmd"); echo ""; continue; }
    path_python=$(command -v "$cmd")
    available_versions+=("$cmd")

    echo "✔ $cmd found"
    echo "   Version: $actual_version"
    echo "   Path:    $path_python"
    echo ""

    cert_local=""

    ssl_cafile=$(
        env -u SSL_CERT_FILE \
            -u REQUESTS_CA_BUNDLE \
            -u PIP_CERT \
            "$cmd" -c 'import ssl; p=ssl.get_default_verify_paths().openssl_cafile; print(p if p else "")'
    ) || ssl_cafile=""

    # Resolve symlinks so the script works consistently with Homebrew,
    # python.org, and other Python distributions that expose CA bundles
    # through symbolic links.
    if [[ -f "$ssl_cafile" ]]; then
        REALPATH_ERR=$(mktemp "$CERT_DIR/_zscaler_realpath_err.XXXXXX")
        TMP_FILES+=("$REALPATH_ERR")
        resolved=$(SSL_CAFILE="$ssl_cafile" "$cmd" -c "
import os, sys
p = os.environ['SSL_CAFILE']
try:
    print(os.path.realpath(p))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>"$REALPATH_ERR") || {
            echo "   ✘ Could not resolve symlink for $ssl_cafile:"
            cat "$REALPATH_ERR"
            prune_tmp_file "$REALPATH_ERR"
            echo ""
            continue
        }
        prune_tmp_file "$REALPATH_ERR"
        ssl_cafile="$resolved"
    fi

    if [[ -f "$ssl_cafile" && "$ssl_cafile" == *.pem ]]; then
        if [[ ! -r "$ssl_cafile" ]]; then
            echo "   ✘ CA bundle exists but is not readable: $ssl_cafile"
            broken_versions+=("$cmd")
            echo ""
            continue
        fi
        cert_local="$ssl_cafile"
        echo "   CA bundle found via ssl module: $cert_local"
        echo ""
    else
        certifi_path=$("$cmd" -c "import certifi; print(certifi.where())" 2>/dev/null || true)
        if [[ -z "$certifi_path" ]]; then
            install_certifi="n"
            if [[ "$INTERACTIVE" == "true" ]]; then
                set +e
                read -r -t 60 -p "   certifi is not installed for $cmd. Install it now? [y/n]: " install_certifi
                read_status=$?
                set -e

                # Detect timeout (read returns >128 on timeout in bash)
                if (( read_status > 128 )); then
                    echo -e "\n✘ Confirmation timed out. Aborting script to safeguard state."
                    exit 1
                fi

                # If user just pressed Enter, apply explicit default
                [[ -z "$install_certifi" ]] && install_certifi="n"
            fi

            case "$install_certifi" in
                [Yy])
                    echo "=== Installing certifi on $cmd ==="

                    if ! "$cmd" -m pip install certifi; then
                        echo -e "\n=== Failed to install certifi ==="
                        broken_versions+=("$cmd")
                        echo ""
                        continue
                    fi

                    certifi_path=$("$cmd" -c "import certifi; print(certifi.where())" 2>/dev/null || true)

                    if [[ -z "$certifi_path" ]]; then
                        echo "✘ pip install succeeded but certifi.where() returned empty"
                        broken_versions+=("$cmd")
                        echo ""
                        continue
                    fi
                    ;;

                [Nn])
                    echo "   Skipping certifi install for $cmd — moving to next Python version"
                    skipped_versions+=("$cmd")
                    echo ""
                    continue
                    ;;

                *)
                    echo "   Invalid input — skipping certifi install for $cmd"
                    skipped_versions+=("$cmd")
                    echo ""
                    continue
                    ;;
            esac
        fi

        if [[ -f "$certifi_path" && "$certifi_path" == *.pem ]]; then
            if [[ ! -r "$certifi_path" ]]; then
                echo "   ✘ CA bundle exists but is not readable: $certifi_path"
                broken_versions+=("$cmd")
                echo ""
                continue
            fi
            cert_local="$certifi_path"
            echo "   CA bundle found via certifi: $cert_local"
            echo ""
        else
            echo "✘ Could not locate a valid PEM bundle for $cmd — skipping"
            echo ""
            continue
        fi
    fi

    use_this_python="n"

    if [[ "$INTERACTIVE" == "true" ]]; then
        set +e
        read -r -t 60 -p "   Use this Python installation...? [y/n]: " use_this_python
        read_status=$?
        set -e

        # Timeout detection
        if (( read_status > 128 )); then
            echo -e "\n   ✘ Confirmation timed out. Aborting script to safeguard state."
            exit 1
        fi

        # Enter key default
        [[ -z "$use_this_python" ]] && use_this_python="n"
    fi

    case "$use_this_python" in
        [Yy])
            :  # proceed
            ;;

        [Nn])
            echo "   Skipping $cmd — moving to next Python version"
            skipped_versions+=("$cmd")
            echo ""
            continue
            ;;

        *)
            echo "   Invalid input — skipping $cmd"
            skipped_versions+=("$cmd")
            echo ""
            continue
            ;;
    esac

    # Basic sanity check that both inputs appear to be PEM certificate bundles
    # before attempting the merge.
    if ! grep -q "^-----BEGIN CERTIFICATE-----" "$cert_local"; then
        echo "✘ CA bundle does not appear to be valid PEM: $cert_local"
        exit 1
    fi
    if ! grep -q "^-----END CERTIFICATE-----" "$cert_local"; then
        echo "✘ CA bundle appears malformed: missing certificate terminators."
        exit 1
    fi
    if ! grep -q "^-----BEGIN CERTIFICATE-----" "$ZSCALER_CERT"; then
        echo "✘ Zscaler cert does not appear to be valid PEM: $ZSCALER_CERT"
        exit 1
    fi
    if ! openssl x509 -in "$ZSCALER_CERT" -noout >/dev/null 2>&1; then
        echo "✘ Zscaler certificate is not a valid X.509 PEM certificate."
        exit 1
    fi

    source_cert_count=$(grep -c "^-----BEGIN CERTIFICATE-----" "$cert_local" || true)
    zscaler_cert_count=$(grep -c "^-----BEGIN CERTIFICATE-----" "$ZSCALER_CERT" || true)
    [[ "$source_cert_count"  =~ ^[0-9]+$ ]] || { echo "✘ Could not read cert count from CA bundle: '$source_cert_count'";  exit 1; }
    [[ "$zscaler_cert_count" =~ ^[0-9]+$ ]] || { echo "✘ Could not read cert count from Zscaler cert: '$zscaler_cert_count'"; exit 1; }

    if (( zscaler_cert_count != 1 )); then
        echo "✘ Expected exactly 1 Zscaler certificate, found $zscaler_cert_count — aborting."
        exit 1
    fi

    if (( source_cert_count == 0 )); then
        echo "✘ Source CA bundle contains no certificates: $cert_local"
        exit 1
    fi

    if [[ "$cert_local" == "$COMBINED_CERT" ]]; then
        echo "✘ Refusing to use the generated combined bundle as input."
        exit 1
    fi

    # Build the merged bundle in a temporary file and atomically replace
    # the target bundle after validation succeeds.
    COMBINED_TMP=$(mktemp "$CERT_DIR/.combined-ca.tmp.XXXXXX")
    TMP_FILES+=("$COMBINED_TMP")

    (
        cat "$cert_local"
        printf '\n'
        cat "$ZSCALER_CERT"
    ) > "$COMBINED_TMP" || {
        echo "✘ Failed to build combined certificate bundle."
        exit 1
    }

    mv "$COMBINED_TMP" "$COMBINED_CERT" || { echo "✘ Failed to write $COMBINED_CERT"; exit 1; }
    CERT_FILE_NEEDS_CLEANUP="true"
    prune_tmp_file "$COMBINED_TMP"

    if [[ ! -f "$COMBINED_CERT" || ! -r "$COMBINED_CERT" || ! -s "$COMBINED_CERT" ]]; then
        echo "✘ Combined cert file validation failed after write operation."
        exit 1
    fi

    GREP_ERR_BUF=$(mktemp "$CERT_DIR/_zscaler_grep_err.XXXXXX")
    TMP_FILES+=("$GREP_ERR_BUF")
    combined_cert_count=$(grep -c "^-----BEGIN CERTIFICATE-----" "$COMBINED_CERT" 2>"$GREP_ERR_BUF" || true)

    if [[ ! "$combined_cert_count" =~ ^[0-9]+$ ]]; then
        echo "✘ Could not read cert count from combined bundle."
        prune_tmp_file "$GREP_ERR_BUF"
        exit 1
    fi
    prune_tmp_file "$GREP_ERR_BUF"

    # Confirm that the merged bundle contains all source certificates plus
    # the exported Zscaler certificate. This helps detect truncation or
    # incomplete writes.
    expected_total=$(( source_cert_count + 1 ))
    if (( combined_cert_count != expected_total )); then
        echo "✘ Post-merge validation failed: expected exactly $expected_total certificates, found $combined_cert_count"
        exit 1
    fi
    echo "   ✔ Post-merge validation passed ($source_cert_count source + 1 Zscaler = $combined_cert_count certificates)"

    # Generate a shell snippet that exports the combined certificate bundle
    # for Python, requests, and pip.
    ENV_TMP=$(mktemp "$CERT_DIR/.corp_ssl_env.tmp.XXXXXX")
    TMP_FILES+=("$ENV_TMP")
    {
        echo "# Auto-generated by combine_zscaler_cert.sh — safe to re-generate"
        echo "export SSL_CERT_FILE=\"$COMBINED_CERT\""
        echo "export REQUESTS_CA_BUNDLE=\"$COMBINED_CERT\""
        echo "export PIP_CERT=\"$COMBINED_CERT\""
    } > "$ENV_TMP"

    mv "$ENV_TMP" "$CORP_SSL_ENV" || { echo "✘ Failed to write $CORP_SSL_ENV"; exit 1; }
    prune_tmp_file "$ENV_TMP"

    [[ -s "$CORP_SSL_ENV" ]] || {
        echo "✘ Env file validation failed"
        exit 1
    }

    echo ""
    echo "   Env file written: $CORP_SSL_ENV"
    echo "   Source line: $SOURCE_LINE"
    echo ""

    selected_python_env="$cmd"
    CERT_FILE_NEEDS_CLEANUP="false"
    break
done

# ---------------------------------------------------------------------------
# Phase 2: Update shell startup files.
#
# Existing corp_ssl_env.sh source lines are removed before the current
# source line is appended. Each file is backed up before modification,
# allowing rollback if any update fails.
# ---------------------------------------------------------------------------
if [[ -n "$selected_python_env" ]]; then
    rc_update_failed="false"
    UPDATED_RC_FILES=()
    UPDATED_RC_MODES=()

    for RC_FILE in "${RC_FILES[@]}"; do
        rc_dir=$(dirname "$RC_FILE")
        rc_base=$(basename "$RC_FILE")
        RC_BACKUP=$(mktemp "$rc_dir/${rc_base}.zscaler_bak.XXXXXX")
        RC_TMP=$(mktemp "$CERT_DIR/.rc_update.XXXXXX")
        TMP_FILES+=("$RC_TMP")

        original_mode=$(stat -f "%04Lp" "$RC_FILE" 2>/dev/null || echo "0644")

        if ! cp "$RC_FILE" "$RC_BACKUP"; then
            echo "   ✘ Could not back up $RC_FILE — skipping to avoid data loss."
            echo "     Add this line manually:  $SOURCE_LINE"
            rm -f "$RC_BACKUP"
            prune_tmp_file "$RC_TMP"
            rc_update_failed="true"
            break
        fi

        TMP_FILES+=("$RC_BACKUP")

        chmod "$original_mode" "$RC_BACKUP" 2>/dev/null || true

        set +e
        grep -Ev '\.corp_ssl_env\.sh' "$RC_FILE" > "$RC_TMP"
        grep_exit=$?
        set -e
        if (( grep_exit > 1 )); then
            echo "   ✘ grep failed reading $RC_FILE (exit $grep_exit) — restoring backup."
            if mv "$RC_BACKUP" "$RC_FILE"; then
                prune_tmp_file_record_only "$RC_BACKUP"
                chmod "$original_mode" "$RC_FILE" 2>/dev/null || true
                echo "   ✔ Backup restored successfully: $RC_FILE"
            else
                echo "   ✘ CRITICAL: Could not restore $RC_FILE from backup ($RC_BACKUP)."
                exit 1
            fi
            prune_tmp_file "$RC_TMP"
            rc_update_failed="true"
            break
        fi

        if grep -q '\.corp_ssl_env\.sh' "$RC_TMP" 2>/dev/null; then
            echo "   ✘ Old corp_ssl_env.sh source line was not removed from $RC_FILE."
            prune_tmp_file "$RC_TMP"
            rc_update_failed="true"
            break
        fi

        {
            echo ""
            echo "$SOURCE_LINE"
        } >> "$RC_TMP"

        chmod "$original_mode" "$RC_TMP" || { 
            echo "   ✘ Could not set permissions on $RC_TMP — aborting."
            rc_update_failed="true"
            break
        }

        Determine the actual file path using Python (which is guaranteed to be available by Phase 2)
        REAL_DEST=$("$selected_python_env" -c "
        import os, sys
        try:
            print(os.path.realpath(sys.argv[1]))
        except Exception:
            print(sys.argv[1])
        " "$RC_FILE" 2>/dev/null)
        
        # Fallback just in case the python execution fails entirely
        if [[ -z "$REAL_DEST" ]]; then
            REAL_DEST="$RC_FILE"
        fi

        if ! mv "$RC_TMP" "$REAL_DEST"; then
            echo "   ✘ Could not update $RC_FILE — attempting to restore backup."
            if mv "$RC_BACKUP" "$RC_FILE"; then
                prune_tmp_file_record_only "$RC_BACKUP"
                chmod "$original_mode" "$RC_FILE" 2>/dev/null || true
                echo "   ✔ Backup restored successfully: $RC_FILE"
            else
                echo "   ✘ CRITICAL: Could not restore $RC_FILE from backup ($RC_BACKUP)."
                exit 1
            fi
            rc_update_failed="true"
            break
        else
            echo "   Source line written to $RC_FILE (backup at $RC_BACKUP)"
            UPDATED_RC_FILES+=("$RC_FILE")
            UPDATED_RC_MODES+=("$original_mode")
            UPDATED_RC_BACKUPS+=("$RC_BACKUP")
            prune_tmp_file "$RC_TMP"
        fi
    done

    # If any shell profile update fails, restore all previously modified
    # profile files from their backups to keep configuration consistent.
    if [[ "$rc_update_failed" == "true" ]]; then
        echo -e "\n⚠ Triage: Shell profile updates failed. Initiating global rollback..."
        for i in "${!UPDATED_RC_FILES[@]}"; do
            F="${UPDATED_RC_FILES[$i]}"
            M="${UPDATED_RC_MODES[$i]}"
            B="${UPDATED_RC_BACKUPS[$i]}"

            if [[ ! -f "$B" ]]; then
                echo "   ✘ CRITICAL: Backup missing for $F"
                continue
            fi

            if mv "$B" "$F"; then
                prune_tmp_file_record_only "$B"
                chmod "$M" "$F" 2>/dev/null || true
                echo "   ✔ Reverted changes and restored permissions to $F ($M)"
            else
                echo "   ✘ CRITICAL: Failed to restore $F"
            fi
        done
        exit 1
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Final status reporting and backup cleanup.
#
# At this point all modifications have succeeded. Temporary backups that
# are no longer needed are removed before presenting next-step guidance.
# ---------------------------------------------------------------------------
if [[ -n "$selected_python_env" ]]; then
    echo "✔ Zscaler certificate has been combined with the Python CA bundle via $selected_python_env."

    for backup in "${UPDATED_RC_BACKUPS[@]}"; do
        [[ -f "$backup" ]] && rm -f "$backup"
        prune_tmp_file_record_only "$backup"
    done

    if [[ ${#RC_FILES[@]} -eq 0 ]]; then
        echo -e "\n⚠ No shell profile was updated: neither ~/.zshrc nor ~/.bash_profile exists."
        echo ""
        echo "  The combined certificate bundle was created, but nothing will load it automatically."
        echo "  Add this line to whichever shell startup file you use:"
        echo "    $SOURCE_LINE"
    fi

    if [[ ${#skipped_versions[@]} -gt 0 ]]; then
        echo -e "\n  Note: the following Python versions were skipped:\n    ${skipped_versions[*]}"
    fi

    echo -e "\n  No changes were made to your Fish config. If you use Fish:"
    echo "  Add the following to ~/.config/fish/config.fish manually:"
    echo ""
    echo "    set -x SSL_CERT_FILE \"$COMBINED_CERT\""
    echo "    set -x REQUESTS_CA_BUNDLE \"$COMBINED_CERT\""
    echo "    set -x PIP_CERT \"$COMBINED_CERT\""
    echo ""
    echo "  Restart your terminal, or run:"
    echo "    source \"$CORP_SSL_ENV\""
    echo ""
    echo "  Run these commands to completely revert changes made by this script:"
    for RC_FILE in "${RC_FILES[@]}"; do
        echo "    perl -i -ne 'print unless /corp_cert\/\.corp_ssl_env\.sh/' \"$RC_FILE\""
    done
    echo ""
    exit 0
else
    echo -e "✘ Unable to locate a valid Python certificate bundle.\n"
    if [[ ${#available_versions[@]} -gt 0 ]]; then
        no_bundle=()
        for v in "${available_versions[@]}"; do
            [[ " ${skipped_versions[*]} " == *" $v "* ]] && continue
            [[ " ${broken_versions[*]} " == *" $v "* ]] && continue
            no_bundle+=("$v")
        done
        [[ ${#no_bundle[@]} -gt 0 ]] && echo "  Python versions found but no usable bundle: ${no_bundle[*]}"
        [[ ${#broken_versions[@]} -gt 0 ]] && echo "  Python versions with environment issues: ${broken_versions[*]}"
        [[ ${#skipped_versions[@]} -gt 0 ]] && echo "  Python versions skipped by user: ${skipped_versions[*]}"
        echo ""
    else
        echo -e "  No Python installation was found.\n  Install Python via Homebrew (brew install python)\n"
    fi
    exit 1
fi
