#!/usr/bin/env python3
"""Validate exact reviewed source; generated outputs never enter approved scope."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

if not __debug__:
    raise SystemExit("Optimized Python must not disable validation assertions")
root = pathlib.Path(sys.argv[1]).resolve()
expected_sha = sys.argv[2]
manifest = json.loads(pathlib.Path(sys.argv[3]).read_text())
output = pathlib.Path(sys.argv[4])
phase = sys.argv[5]
assert phase in {"initial", "final"}
assert re.fullmatch(r"[0-9a-f]{40}", expected_sha), "An exact source SHA is required"
assert expected_sha == manifest["remote_source_sha"], "Source SHA is not the approved remote commit"

def git(*args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert git("rev-parse", "HEAD") == expected_sha, "Wrong checked-out source SHA"
assert git("rev-parse", "HEAD^{tree}") == manifest["remote_source_tree"], "Wrong source tree"
base = manifest["base_sha"]
assert re.fullmatch(r"[0-9a-f]{40}", base)
git("cat-file", "-e", f"{base}^{{commit}}")
assert git("rev-list", "--parents", "-n", "1", "HEAD").split() == [expected_sha, base], "Unexpected direct parent"
canonical_diff = subprocess.check_output(["git", "-C", str(root), "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "--no-color", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/", base, expected_sha])
canonical_hash = hashlib.sha256(canonical_diff).hexdigest()
assert canonical_hash == manifest["canonical_diff_sha256"], "Unexpected canonical source diff or file modes"
expected = manifest["approved_files"]
assert len(expected) == manifest["expected_file_count"] == 11
actual_paths = set(git("diff", "--name-only", base, expected_sha).splitlines())
assert actual_paths == set(expected), {"extra_paths": sorted(actual_paths - set(expected)), "missing_paths": sorted(set(expected) - actual_paths)}
verified = {}
for name, expected_hash in expected.items():
    path = root / name
    assert not path.is_symlink() and path.is_file(), name
    assert path.resolve().is_relative_to(root), name
    verified[name] = sha(path)
    assert verified[name] == expected_hash, f"Unreviewed bytes: {name}"
assert git("diff", "--name-only", "HEAD") == "", "Tracked source changed during validation"
assert git("diff", "--cached", "--name-only") == "", "Unexpected staged files"
untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
generated = {}
if phase == "initial":
    assert not untracked, f"Untracked files before validation: {untracked}"
else:
    for name in untracked:
        assert name.startswith("libs/langchain-core/src/") and name.endswith(".d.ts.map"), f"Unexpected generated output: {name}"
        path = root / name
        assert not path.is_symlink(), name
        data = json.loads(path.read_text())
        assert data["version"] == 3 and data["file"] == path.name.removesuffix(".map"), name
        assert data["sources"] and all(str(s).endswith(".ts") for s in data["sources"]), name
        assert (root / (name.removesuffix(".d.ts.map") + ".ts")).is_file(), name
        generated[name] = sha(path)
record = {"phase": phase, "source_sha": expected_sha, "tree": git("rev-parse", "HEAD^{tree}"), "base_sha": base, "canonical_diff_sha256": canonical_hash, "approved_file_count": 11, "approved_file_hashes": verified, "tracked_source_unchanged": True, "generated_untracked_declaration_maps": generated, "generated_map_count": len(generated), "passed": True}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({key: value for key, value in record.items() if key not in {"approved_file_hashes", "generated_untracked_declaration_maps"}}, indent=2))
