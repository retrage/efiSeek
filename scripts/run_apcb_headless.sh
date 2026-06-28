#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/snap/ghidra/current/ghidra_12.1_PUBLIC}"
JAVA_HOME="${JAVA_HOME:-/tmp/efiseek-java-home.0TGprz}"
DEFAULT_EXTENSION_ZIP="$(ls -t "$REPO_ROOT"/dist/ghidra_*_efiSeek.zip 2>/dev/null | head -n 1 || true)"
EXTENSION_ZIP="${EXTENSION_ZIP:-$DEFAULT_EXTENSION_ZIP}"
APCB_BINARY="${APCB_BINARY:-$REPO_ROOT/extracted/uefi_pe/pe/1027_fv008120E8_B1BAC051-D5C2-4AC1-AC7D-9D2F518A1E7B_AmdApcbSmmV_Pe32.efi}"
LOG_FILE="${LOG_FILE:-/tmp/efiseek-apcb-headless.log}"
PROJECT_DIR="${PROJECT_DIR:-$(mktemp -d /tmp/efiseek-ghidra-project.apcb.XXXXXX)}"
PROJECT_NAME="${PROJECT_NAME:-efiSeekApcb}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$(mktemp -d /tmp/efiseek-ghidra-config.apcb.XXXXXX)}"

if [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]]; then
	echo "analyzeHeadless not found: $GHIDRA_INSTALL_DIR/support/analyzeHeadless" >&2
	exit 1
fi

if [[ ! -d "$JAVA_HOME" ]]; then
	echo "JAVA_HOME not found: $JAVA_HOME" >&2
	exit 1
fi

if [[ -z "$EXTENSION_ZIP" || ! -f "$EXTENSION_ZIP" ]]; then
	echo "efiSeek extension zip not found: $EXTENSION_ZIP" >&2
	echo "Build it first, for example:" >&2
	echo "  $GHIDRA_INSTALL_DIR/support/gradle/gradlew --no-daemon -p '$REPO_ROOT' -PGHIDRA_INSTALL_DIR='$GHIDRA_INSTALL_DIR' build buildExtension" >&2
	exit 1
fi

if [[ ! -f "$APCB_BINARY" ]]; then
	echo "AmdApcbSmmV binary not found: $APCB_BINARY" >&2
	exit 1
fi

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"
export XDG_CONFIG_HOME

EXTENSION_DIR="$XDG_CONFIG_HOME/retrage-ghidra/ghidra_12.1_PUBLIC/Extensions"
mkdir -p "$EXTENSION_DIR"
unzip -q -o "$EXTENSION_ZIP" -d "$EXTENSION_DIR"

"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
	-import "$APCB_BINARY" \
	-overwrite \
	-analysisTimeoutPerFile 300 \
	-log "$LOG_FILE"

echo
echo "Log: $LOG_FILE"
echo "Project: $PROJECT_DIR/$PROJECT_NAME"
echo

if grep -E -q "(ERROR |Exception)" "$LOG_FILE"; then
	echo "Errors/exceptions were found in the log:" >&2
	grep -E -n "(ERROR |Exception)" "$LOG_FILE" >&2
	exit 1
fi

echo "Detected SMM callouts:"
grep -n "Potential SMM callout detected" "$LOG_FILE"
