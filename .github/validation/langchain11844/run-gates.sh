#!/usr/bin/env bash
set -euo pipefail
SOURCE=$(cd "$1" && pwd)
OUT=$(cd "$2" && pwd)
HARNESS=$(cd "$(dirname "$0")" && pwd)
export OUT
mkdir -p "$OUT"
printf '[]\n' > "$OUT/gates.json"

finish() {
  original=$?
  trap - EXIT
  set +e
  python3 -I "$HARNESS/verify-source.py" "$SOURCE" "$SOURCE_SHA" \
    "$HARNESS/approved-source.json" "$OUT/source-after.json" final > "$OUT/source-after.log" 2>&1
  source_rc=$?
  python3 -I - "$OUT" "$original" "$source_rc" <<'PY'
import json, pathlib, sys
out=pathlib.Path(sys.argv[1]); original=int(sys.argv[2]); source_rc=int(sys.argv[3])
gates=json.loads((out/'gates.json').read_text())
required=['guard-selftest','build-core','build-anthropic','build-openai','build-aws','build-fireworks','build-langchain','native-package-tests-types','root-lint','root-format','circular','built-module-smoke']
audit=out/'network-audit.jsonl'
events=[json.loads(s) for s in audit.read_text().splitlines() if s.strip()] if audit.exists() else []
blocked=sum(e.get('event')=='network-blocked' for e in events)
passed=original==0 and source_rc==0 and [g['name'] for g in gates]==required and all(g['exit_code']==0 for g in gates) and blocked==0 and bool(events)
result={'passed':passed,'original_exit_code':original,'source_verification_exit_code':source_rc,'completed_gates':gates,'required_gates':required,'node_guard_blocked_attempts':blocked,'network_guard_events':len(events),'runtime_scope':'Complete langchain native package tests/types with fake/offline unit tests; no provider/integration calls; not full monorepo or Docker export matrix.'}
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
sys.exit(0 if passed else 1)
PY
  summary_rc=$?
  if [[ "$original" -ne 0 ]]; then exit "$original"; fi
  if [[ "$source_rc" -ne 0 ]]; then exit "$source_rc"; fi
  exit "$summary_rc"
}
trap finish EXIT

# Diagnostic-only revision: collect fixed, read-only process/network metadata
# before any isolation assertion. This does not establish isolation success.
printf '%s\n' 'DIAGNOSTIC ONLY: native gates will not run in this revision.'
python3 -I - "$OUT" <<'PYDIAGNOSTICS'
import json, os, pathlib, sys
out=pathlib.Path(sys.argv[1])
paths={'process_status':'/proc/self/status','network_devices':'/proc/net/dev','ipv4_routes':'/proc/net/route','ipv6_routes':'/proc/net/ipv6_route'}
raw={};errors={}
for label,path in paths.items():
    try:
        raw[label]=pathlib.Path(path).read_text()
        (out/f'preflight-{label}.txt').write_text(raw[label])
    except OSError as error:
        errors[label]=str(error)
record={'stage':'before_isolation_assertions','diagnostic_only':True,'isolation_accepted':False,'host_namespace':os.environ.get('HOST_NETWORK_NAMESPACE'),'runtime_namespace':os.readlink('/proc/self/ns/net'),'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'raw':raw,'read_errors':errors}
if 'ipv4_routes' in raw:
    record['ipv4_splitlines']=raw['ipv4_routes'].splitlines()
    record['ipv4_line_count']=len(record['ipv4_splitlines'])
    record['ipv4_nonblank_line_count']=sum(bool(line.strip()) for line in record['ipv4_splitlines'])
(out/'preflight-diagnostics.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
PYDIAGNOSTICS

# The workflow must establish a new kernel network namespace before this script.
[[ -n "${HOST_NETWORK_NAMESPACE:-}" ]]
CURRENT_NAMESPACE=$(readlink /proc/self/ns/net)
[[ "$CURRENT_NAMESPACE" != "$HOST_NETWORK_NAMESPACE" ]]
printf 'host=%s\nruntime=%s\n' "$HOST_NETWORK_NAMESPACE" "$CURRENT_NAMESPACE" > "$OUT/network-namespace.txt"
python3 -I - "$OUT" <<'PYSECURITY'
import json, os, pathlib, sys
out=pathlib.Path(sys.argv[1])
status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line}
assert os.getuid()==int(os.environ['EXPECTED_RUNTIME_UID']) and os.getuid()!=0
assert os.getgid()==65534 and os.getgroups()==[], 'Unexpected supplementary/privileged groups'
assert status['NoNewPrivs']=='1'
assert all(int(status[key],16)==0 for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
interfaces=[line.split(':',1)[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in line]
assert interfaces==['lo'], interfaces
assert len(pathlib.Path('/proc/net/route').read_text().splitlines())==1, 'IPv4 routes are present'
ipv6=pathlib.Path('/proc/net/ipv6_route')
assert not ipv6.exists() or all(line.split()[-1]=='lo' for line in ipv6.read_text().splitlines()), 'Non-loopback IPv6 route'
for sock in ['/var/run/docker.sock','/run/containerd/containerd.sock','/run/podman/podman.sock',f'/run/user/{os.getuid()}/docker.sock',f'/run/user/{os.getuid()}/podman/podman.sock']:
    assert not os.access(sock,os.W_OK), f'Privileged daemon socket accessible: {sock}'
record={'uid':os.getuid(),'gid':os.getgid(),'supplementary_groups':os.getgroups(),'no_new_privs':1,'capabilities':{key:status[key] for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']},'interfaces':interfaces,'ipv4_routes':0,'ipv6_external_routes':0}
(out/'runtime-isolation.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
PYSECURITY
# Even if isolation passes in this diagnostic run, stop before product commands.
printf '%s\n' 'Diagnostic preflight completed; native gates intentionally not executed.'
exit 78
python3 -I "$HARNESS/verify-source.py" "$SOURCE" "$SOURCE_SHA" "$HARNESS/approved-source.json" "$OUT/source-offline-start.json" initial
node --version > "$OUT/node-version.txt"
pnpm --version > "$OUT/pnpm-version.txt"
[[ "$(cat "$OUT/pnpm-version.txt")" == 10.14.0 ]]

run_gate() {
  local name=$1 directory=$2
  shift 2
  printf 'COMMAND:' > "$OUT/$name.log"
  printf ' %q' "$@" >> "$OUT/$name.log"
  printf '\n' >> "$OUT/$name.log"
  set +e
  (cd "$directory" && "$@") >> "$OUT/$name.log" 2>&1
  local code=$?
  set -e
  printf '\nEXIT_CODE=%s\n' "$code" >> "$OUT/$name.log"
  tail -35 "$OUT/$name.log"
  python3 -I - "$OUT/gates.json" "$name" "$code" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]);data=json.loads(path.read_text());data.append({'name':sys.argv[2],'exit_code':int(sys.argv[3])});path.write_text(json.dumps(data,indent=2)+'\n')
PY
  return "$code"
}

run_gate guard-selftest "$SOURCE" env NETWORK_AUDIT_LOG="$OUT/guard-selftest-audit.jsonl" node "$HARNESS/check-network-guard.cjs"
run_gate build-core "$SOURCE/libs/langchain-core" pnpm run build:compile
run_gate build-anthropic "$SOURCE/libs/providers/langchain-anthropic" pnpm run build:compile
run_gate build-openai "$SOURCE/libs/providers/langchain-openai" pnpm run build:compile
run_gate build-aws "$SOURCE/libs/providers/langchain-aws" pnpm run build:compile
run_gate build-fireworks "$SOURCE/libs/providers/langchain-fireworks" pnpm run build:compile
run_gate build-langchain "$SOURCE/libs/langchain" pnpm run build:compile
run_gate native-package-tests-types "$SOURCE/libs/langchain" pnpm test --maxWorkers=2
run_gate root-lint "$SOURCE" pnpm lint
run_gate root-format "$SOURCE" pnpm format:check
run_gate circular "$SOURCE/libs/langchain" pnpm exec dpdm src/agents/index.ts --transform --no-tree --exit-code circular:1
run_gate built-module-smoke "$SOURCE" node "$HARNESS/check-built-exports.mjs" "$SOURCE" "$OUT"
