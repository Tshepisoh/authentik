#!/usr/bin/env bash
# Watches one EAS build; on ERRORED prints the compiler/Gradle error lines from its log.
# Usage: eas-watch.sh <build-id> <scratch-dir>
id="$1"; dir="$2"
cd /c/Users/TshepisoHlahla/authentik/mobile || exit 1
view() { EAS_NO_VCS=1 npx --yes eas-cli@latest build:view "$id" --json 2>/dev/null > "$dir/view-$id.txt"; }
prev=""; fails=0
while true; do
  view
  s=$(python -c "import sys,json; t=open(sys.argv[1],encoding='utf-8',errors='replace').read(); print(json.loads(t[t.index('{'):]).get('status'))" "$dir/view-$id.txt" 2>/dev/null || echo unknown)
  if [ "$s" = unknown ]; then
    fails=$((fails+1)); [ $fails -ge 5 ] && { echo "build status: unknown (5 failed checks in a row)"; fails=0; }
  else
    fails=0
    [ "$s" != "$prev" ] && { echo "build status: $s"; prev=$s; }
  fi
  case "$s" in
    FINISHED|CANCELED) break ;;
    ERRORED)
      python - "$dir/view-$id.txt" "$dir/raw-$id.bin" <<'EOF'
import sys,json,urllib.request
t=open(sys.argv[1],encoding='utf-8',errors='replace').read(); d=json.loads(t[t.index('{'):])
print('error:', (d.get('error') or {}).get('message'))
open(sys.argv[2],'wb').write(urllib.request.urlopen(d['logFiles'][0],timeout=60).read())
EOF
      node -e "
const zlib=require('zlib'),fs=require('fs');let raw=fs.readFileSync(process.argv[1]);
try{raw=zlib.brotliDecompressSync(raw)}catch{try{raw=zlib.gunzipSync(raw)}catch{}}
const lines=raw.toString('utf8').split('\n').map(l=>{try{const o=JSON.parse(l);return '['+(o.phase||'')+'] '+(o.msg||'')}catch{return l}});
fs.writeFileSync(process.argv[2],lines.join('\n'));
lines.filter(l=>/\] e: |error:|What went wrong|Execution failed|FAILED|Unresolved reference|ERROR/.test(l)&&!/warning/i.test(l)).slice(0,25).forEach(l=>console.log(l.slice(0,400)));
" "$dir/raw-$id.bin" "$dir/log-$id.txt"
      break ;;
  esac
  sleep 60
done
