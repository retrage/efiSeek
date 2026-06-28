#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/run_corpus_headless.sh [options] [file-or-directory ...]

Options:
  --out DIR              Output directory. Default: /tmp/efiseek-corpus.<timestamp>
  --project-dir DIR      Ghidra project directory. Default: a temp directory
  --project-name NAME    Ghidra project name. Default: efiSeekCorpus
  --timeout SECONDS      Per-file analysis timeout. Default: 300
  --limit N              Analyze at most N inputs.
  --all-files            Import all regular files under directories.
  --build-extension      Build the efiSeek extension before running.
  -h, --help             Show this help.

Environment:
  GHIDRA_INSTALL_DIR     Default: /snap/ghidra/current/ghidra_12.1_PUBLIC
  JAVA_HOME              Default: /tmp/efiseek-java-home.0TGprz
  EXTENSION_ZIP          Default: newest dist/ghidra_*_efiSeek.zip
  XDG_CONFIG_HOME        Default: an isolated temp directory

Default corpus path is samples/.
EOF
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/snap/ghidra/current/ghidra_12.1_PUBLIC}"
JAVA_HOME="${JAVA_HOME:-/tmp/efiseek-java-home.0TGprz}"
ANALYSIS_TIMEOUT_PER_FILE=300
PROJECT_DIR=""
PROJECT_NAME="efiSeekCorpus"
OUT_DIR=""
LIMIT=""
ALL_FILES=0
BUILD_EXTENSION=0
CORPUS_PATHS=()

while [[ $# -gt 0 ]]; do
	case "$1" in
		--out)
			OUT_DIR="$2"
			shift 2
			;;
		--project-dir)
			PROJECT_DIR="$2"
			shift 2
			;;
		--project-name)
			PROJECT_NAME="$2"
			shift 2
			;;
		--timeout)
			ANALYSIS_TIMEOUT_PER_FILE="$2"
			shift 2
			;;
		--limit)
			LIMIT="$2"
			shift 2
			;;
		--all-files)
			ALL_FILES=1
			shift
			;;
		--build-extension)
			BUILD_EXTENSION=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			while [[ $# -gt 0 ]]; do
				CORPUS_PATHS+=("$1")
				shift
			done
			;;
		-*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 2
			;;
		*)
			CORPUS_PATHS+=("$1")
			shift
			;;
	esac
done

if [[ ${#CORPUS_PATHS[@]} -eq 0 ]]; then
	CORPUS_PATHS=("$REPO_ROOT/samples")
fi

if [[ -z "$OUT_DIR" ]]; then
	OUT_DIR="/tmp/efiseek-corpus.$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ -z "$PROJECT_DIR" ]]; then
	PROJECT_DIR="$(mktemp -d /tmp/efiseek-ghidra-project.corpus.XXXXXX)"
fi
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$(mktemp -d /tmp/efiseek-ghidra-config.corpus.XXXXXX)}"

if [[ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]]; then
	echo "analyzeHeadless not found: $GHIDRA_INSTALL_DIR/support/analyzeHeadless" >&2
	exit 1
fi
if [[ ! -d "$JAVA_HOME" ]]; then
	echo "JAVA_HOME not found: $JAVA_HOME" >&2
	exit 1
fi

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"
export XDG_CONFIG_HOME

if [[ "$BUILD_EXTENSION" -eq 1 ]]; then
	"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" --no-daemon \
		-p "$REPO_ROOT" \
		-PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" \
		build buildExtension
fi

DEFAULT_EXTENSION_ZIP="$(ls -t "$REPO_ROOT"/dist/ghidra_*_efiSeek.zip 2>/dev/null | head -n 1 || true)"
EXTENSION_ZIP="${EXTENSION_ZIP:-$DEFAULT_EXTENSION_ZIP}"
if [[ -z "$EXTENSION_ZIP" || ! -f "$EXTENSION_ZIP" ]]; then
	echo "efiSeek extension zip not found." >&2
	echo "Run with --build-extension or set EXTENSION_ZIP." >&2
	exit 1
fi

mkdir -p "$OUT_DIR/logs" "$OUT_DIR/console"
MANIFEST="$OUT_DIR/inputs.txt"
META_JSONL="$OUT_DIR/meta.jsonl"
STATUS_TSV="$OUT_DIR/status.tsv"
: > "$MANIFEST"
: > "$META_JSONL"
printf 'input_path\texit_code\tlog\tconsole\n' > "$STATUS_TSV"

find_inputs() {
	local input="$1"
	if [[ -f "$input" ]]; then
		realpath "$input"
	elif [[ -d "$input" ]]; then
		if [[ "$ALL_FILES" -eq 1 ]]; then
			find "$input" -type f -print
		else
			find "$input" -type f \( \
				-iname '*.efi' -o \
				-iname '*.te' -o \
				-iname '*.pe' -o \
				-iname '*.pe32' -o \
				-iname '*.pei' \
			\) -print
		fi | while IFS= read -r path; do realpath "$path"; done
	else
		echo "Input path not found: $input" >&2
	fi
}

for corpus_path in "${CORPUS_PATHS[@]}"; do
	find_inputs "$corpus_path"
done | sort -u > "$MANIFEST"

if [[ -n "$LIMIT" ]]; then
	limited_manifest="$OUT_DIR/inputs.limited.txt"
	sed -n "1,${LIMIT}p" "$MANIFEST" > "$limited_manifest"
	mv "$limited_manifest" "$MANIFEST"
fi

INPUT_COUNT="$(wc -l < "$MANIFEST" | tr -d ' ')"
if [[ "$INPUT_COUNT" -eq 0 ]]; then
	echo "No input files found." >&2
	exit 1
fi

EXTENSION_DIR="$XDG_CONFIG_HOME/retrage-ghidra/ghidra_12.1_PUBLIC/Extensions"
mkdir -p "$EXTENSION_DIR"
unzip -q -o "$EXTENSION_ZIP" -d "$EXTENSION_DIR"

echo "Corpus inputs: $INPUT_COUNT"
echo "Output: $OUT_DIR"
echo "Project: $PROJECT_DIR/$PROJECT_NAME"
echo "Extension: $EXTENSION_ZIP"

index=0
while IFS= read -r input_path; do
	index=$((index + 1))
	base="$(basename "$input_path")"
	safe_base="$(printf '%s' "$base" | tr -c 'A-Za-z0-9_.-' '_')"
	log_path="$OUT_DIR/logs/$(printf '%04d' "$index")_${safe_base}.log"
	console_path="$OUT_DIR/console/$(printf '%04d' "$index")_${safe_base}.console.log"

	echo "[$index/$INPUT_COUNT] $input_path"
	set +e
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
		-import "$input_path" \
		-overwrite \
		-analysisTimeoutPerFile "$ANALYSIS_TIMEOUT_PER_FILE" \
		-scriptPath "$REPO_ROOT/ghidra_scripts" \
		-postScript DumpEfiSeekMetaJson.java "$META_JSONL" "$input_path" \
		-log "$log_path" \
		>"$console_path" 2>&1
	exit_code=$?
	set -e

	printf '%s\t%s\t%s\t%s\n' "$input_path" "$exit_code" "$log_path" "$console_path" >> "$STATUS_TSV"
	if [[ "$exit_code" -ne 0 ]]; then
		echo "  analyzeHeadless failed with exit code $exit_code"
	fi
done < "$MANIFEST"

python3 "$REPO_ROOT/scripts/summarize_efiseek_corpus.py" "$META_JSONL" "$OUT_DIR" --status "$STATUS_TSV"

echo
echo "Detection rows:"
if [[ -s "$OUT_DIR/detections.csv" ]]; then
	sed -n '1,20p' "$OUT_DIR/detections.csv"
else
	echo "No detections CSV was produced."
fi
