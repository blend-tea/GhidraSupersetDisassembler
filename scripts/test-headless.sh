#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to the Ghidra 12.2 installation}"
headless="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
[[ -x "$headless" ]] || { echo "analyzeHeadless was not found: $headless" >&2; exit 1; }

extension_zip="${AMACE_EXTENSION_ZIP:-}"
if [[ -z "$extension_zip" ]]; then
    extension_zip="$(python3 - "$project_dir/dist" <<'PY'
from pathlib import Path
import sys
files = sorted(Path(sys.argv[1]).glob('*.zip'), key=lambda f: f.stat().st_mtime)
if not files:
    raise SystemExit('Build the extension first: ./gradlew buildExtension')
print(files[-1])
PY
)"
fi
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/amace-headless.XXXXXX")"
cleanup() {
    if [[ "${AMACE_KEEP_TEST_OUTPUT:-0}" == 1 ]]; then
        echo "Headless test output: $test_dir"
    else
        rm -rf -- "$test_dir"
    fi
}
trap cleanup EXIT

# Load the packaged extension as an external module. This neither installs into
# Ghidra nor changes an existing user's settings or projects.
python3 - "$extension_zip" "$test_dir/modules" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
PY
module_dir="$(find "$test_dir/modules" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$module_dir" ]] || { echo "Extension ZIP has no module directory" >&2; exit 1; }
mkdir -p "$test_dir/home"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Dghidra.external.modules=\"$module_dir\" -Duser.home=\"$test_dir/home\" -Dapplication.settingsdir=\"$test_dir/settings\" -Dapplication.cachedir=\"$test_dir/cache\""
python3 "$project_dir/tests/fixtures/generate.py" --output "$test_dir/fixtures"
mkdir -p "$test_dir/projects"
python3 - "$project_dir/ghidra_scripts" "$test_dir/scripts" <<'PY'
from pathlib import Path
import sys
destination = Path(sys.argv[2])
destination.mkdir()
# Extension script directories are always searched too. Give the current test
# source a unique name so an older packaged copy cannot shadow it.
for original, renamed in [('AmaceIntegrationTest', 'AmacePackagedFixtureTest'),
                          ('AmaceLifterTest', 'AmacePackagedLifterTest')]:
    source = (Path(sys.argv[1]) / (original + '.java')).read_text().replace(original, renamed)
    (destination / (renamed + '.java')).write_text(source)
PY

if [[ "${AMACE_HEADLESS_CLI_ONLY:-0}" != 1 ]]; then
for bits in 32 64; do
    for kind in raw elf pe; do
        abi="SYSV_X86"
        entry="0x1000"
        import_options=()
        if [[ "$bits" == 64 ]]; then
            abi="SYSV_X64"
            entry="0x100000000"
        fi
        case "$kind:$bits" in
            elf:32) entry="0x8049000" ;;
            elf:64) entry="0x401000" ;;
            pe:32) abi="WINDOWS_X86"; entry="0x401000" ;;
            pe:64) abi="WINDOWS_X64"; entry="0x140001000" ;;
        esac
        if [[ "$kind" == raw ]]; then
            import_options=(-loader BinaryLoader -processor "x86:LE:$bits:default" -cspec gcc -loader-baseAddr "$entry")
        fi
        name="fixture$bits.$kind"
        log="$test_dir/$name.log"
        echo "Checking $name ($abi, entry $entry)"
        "$headless" "$test_dir/projects" "amace_${bits}_${kind}" \
            -import "$test_dir/fixtures/$name" "${import_options[@]}" \
            -noanalysis -scriptPath "$test_dir/scripts" \
            -postScript AmacePackagedFixtureTest.java "$abi" "$entry" "$kind" "$test_dir/$name.pass" \
            -deleteProject -log "$log" -scriptlog "$test_dir/$name-script.log" \
            >"$test_dir/$name-console.log" 2>&1 || {
                cat "$test_dir/$name-console.log" >&2
                exit 1
            }
        if ! python3 - "$test_dir/$name.pass" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
raise SystemExit(0 if p.exists() and p.read_text().startswith('PASS\n') else 1)
PY
        then
            cat "$test_dir/$name-console.log" >&2
            echo "Integration script did not report success" >&2
            exit 1
        fi
    done
done
echo "All six Ghidra headless integration fixtures passed."
fi

echo "Checking packaged RunAmace CLI/JSONL and real SLEIGH lifter examples"
"$headless" "$test_dir/projects" amace_cli \
    -import "$test_dir/fixtures/fixture64.raw" -loader BinaryLoader \
    -processor x86:LE:64:default -cspec gcc -loader-baseAddr 0x100000000 \
    -noanalysis -scriptPath "$test_dir/scripts" \
    -postScript RunAmace.java --abi SYSV_X64 --entry 0x100000000 \
        --start 0x100000000 --end 0x100000019 --report "$test_dir/cli-report.jsonl" \
    -postScript AmacePackagedLifterTest.java "$test_dir/lifter.pass" \
    -deleteProject -log "$test_dir/cli.log" -scriptlog "$test_dir/cli-script.log" \
    >"$test_dir/cli-console.log" 2>&1 || {
        cat "$test_dir/cli-console.log" >&2
        exit 1
    }
if ! python3 - "$test_dir/cli-report.jsonl" "$test_dir/lifter.pass" <<'PY'
from pathlib import Path
import json, sys

report_path, lifter_path = map(Path, sys.argv[1:])
assert report_path.exists(), 'Packaged CLI did not produce its JSONL report'
rows = [json.loads(line) for line in report_path.read_text().splitlines()]
header = rows[0]
assert header['kind'] == 'amace-report' and header['schemaVersion'] == 1, header
assert header['applied'] is True and header['attempted'] == 26, header
assert not header['conflicts'], header
candidates = {int(row['offset'], 16): row for row in rows if row['kind'] == 'candidate'}
base = 0x100000000
assert base + 2 in candidates, 'JSONL omitted the overlapping interior instruction'
expected = {base + offset for offset in [0, 1, 4, 9, 11, 12, 20, 21, 23, 24]}
accepted = {address for address, row in candidates.items() if row['decision']['accepted']}
assert accepted == expected, (accepted, expected)
assert lifter_path.exists() and lifter_path.read_text().startswith('PASS\n'), 'Lifter assertions did not finish'
print('Packaged CLI schema v1, all overlapping candidates, exact selected set, and SLEIGH lifter assertions passed.')
PY
then
    cat "$test_dir/cli-console.log" >&2
    exit 1
fi
