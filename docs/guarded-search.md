# Guarded decoder checks on Java 27 and Elasticsearch 8/9

These optional checks measure the decoder overwrite within a deliberately
oversized destination. They do not execute supplied bytecode or an OS command.
For the Elasticsearch 7.17 command PoC, start with the [README](../README.md).

Run the examples from the repository root. Use genuine runtimes and owned
local nodes, and retain downloads and raw results under `.validation-local/`.
The [hardware guide](hardware-validation.md) covers Java 17/21 and platform
eligibility; [VALIDATION.md](../VALIDATION.md) distinguishes these bounded
results from the separate Elasticsearch 8 command lab proof.

## Java 27 guarded comparison

The official [Elasticsearch 8.19.25 Linux archive](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.19.25-linux-x86_64.tar.gz)
contains the affected Oracle `27.0.1.0.3+1-2` JDK. Its archive is
authenticated by Elastic's [published SHA-512](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.19.25-linux-x86_64.tar.gz.sha512).
The genuine fixed control is [Temurin 27.0.1.1+4](https://github.com/adoptium/temurin27-binaries/releases/tag/jdk-27.0.1.1%2B4),
with an Adoptium [published SHA-256](https://github.com/adoptium/temurin27-binaries/releases/download/jdk-27.0.1.1%2B4/OpenJDK27U-jdk_x64_linux_hotspot_27.0.1.1_4.tar.gz.sha256.txt).
The commands below download and verify those exact archives before extraction.
They use the bundled JDK without starting Elasticsearch.

```bash
(
set -eu
downloads=.validation-local/downloads
runtimes=.validation-local/runtimes/java27-guarded
mkdir -p "$downloads" .validation-local/runtimes
mkdir "$runtimes"

curl -fL -o "$downloads/elasticsearch-8.19.25-linux-x86_64.tar.gz" \
  https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.19.25-linux-x86_64.tar.gz
printf '%s  %s\n' \
  8608f80d03729631b1276ed2f0e7fe6a76bf8c603c6cd033fb531214ce4eeaac203114e4f03a232d606c248c4650aa71edebbc66fd3aa83b4aeffd503848ca34 \
  "$downloads/elasticsearch-8.19.25-linux-x86_64.tar.gz" | sha512sum --check -

curl -fL -o "$downloads/OpenJDK27U-jdk_x64_linux_hotspot_27.0.1.1_4.tar.gz" \
  'https://github.com/adoptium/temurin27-binaries/releases/download/jdk-27.0.1.1%2B4/OpenJDK27U-jdk_x64_linux_hotspot_27.0.1.1_4.tar.gz'
printf '%s  %s\n' \
  005e57ee860978acfeeff1be2b30f770664fe2b941e9b803c61c76992086d107 \
  "$downloads/OpenJDK27U-jdk_x64_linux_hotspot_27.0.1.1_4.tar.gz" | sha256sum --check -

tar -xzf "$downloads/elasticsearch-8.19.25-linux-x86_64.tar.gz" -C "$runtimes"
tar -xzf "$downloads/OpenJDK27U-jdk_x64_linux_hotspot_27.0.1.1_4.tar.gz" -C "$runtimes"

sde=/absolute/path/to/sde64
python3 -B run_probe.py \
  --affected-jdk "$runtimes/elasticsearch-8.19.25/jdk" \
  --fixed-jdk "$runtimes/jdk-27.0.1.1+4" \
  --sde "$sde" \
  --output .validation-local/java27-guarded.json
)
```

Use the verified Intel SDE 10.13.1 installation from the
[setup guide](setup.md), or omit `--sde` on eligible physical Linux x86-64
hardware. The executed SDE comparison returned `GUARD_OVERWRITE` with 62
changed bytes at offsets 98–159 on the affected runtime, and
`NO_GUARD_OVERWRITE` on both controls. A complete runner pass exits 0;
exit 77 records an unavailable prerequisite. No physical Java 27 result
is claimed.

The Java 27 procedure tests the bounded decoder witness only. It does not
extend the public Elasticsearch command client to a newer version.

## Guarded Elasticsearch search

The [guarded Painless source](../elasticsearch/guarded-decoder.painless)
reproduces the contained decoder overwrite observed on Elasticsearch 8.19.25
and 9.5.6. Use an owned, single-node Linux x86-64 installation with an
eligible JVM, verified HTTPS, transport TLS, and the stock Painless and
Entitlements settings. The Java 27 runtimes and SDE configuration are
described above. This procedure does not run the command-execution chain.

An administrator must first create a fresh test index and one visible
document, then give the test account only `read` on that index. These are
the index and document requests used in the controlled comparison:

```http
PUT /java4shell-recent-proof
{"settings":{"number_of_shards":1,"number_of_replicas":0}}

PUT /java4shell-recent-proof/_doc/owned-decoder-document?refresh=true
{"owned_decoder_document":true}
```

Set the URL to that node's loopback HTTPS listener and use its trusted CA.
`curl` prompts for the reader's password. The request selects only the known
document and uses the same [Search API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search)
`script_fields` body as the exercised comparison:

```bash
(
set -eu
mkdir -p .validation-local
ES_URL=https://127.0.0.1:9200
ES_CA=/path/to/http-ca.crt
ES_READER=java4shell_reader

python3 - <<'PY' > .validation-local/guarded-search-request.json
import json, sys
from pathlib import Path

source = Path("elasticsearch/guarded-decoder.painless").read_text()
json.dump({
    "size": 1, "_source": False,
    "query": {"ids": {"values": ["owned-decoder-document"]}},
    "script_fields": {"decoder_guard": {
        "script": {"lang": "painless", "source": source}}}
}, sys.stdout)
PY

curl --fail-with-body --cacert "$ES_CA" --user "$ES_READER" \
  -H 'Content-Type: application/json' \
  --data-binary @.validation-local/guarded-search-request.json \
  "$ES_URL/java4shell-recent-proof/_search" \
  --output .validation-local/guarded-search-response.json

python3 - <<'PY'
import base64, json
from pathlib import Path

reply = json.loads(Path(".validation-local/guarded-search-response.json").read_text())
if reply.get("timed_out") is not False or reply.get("_shards", {}).get("failed") != 0:
    raise SystemExit("Search timed out or a shard failed")
hits = reply.get("hits", {}).get("hits", [])
if not hits:
    raise SystemExit("No matching document: the guarded script did not run")
hit, = hits
if (hit.get("_index") != "java4shell-recent-proof"
        or hit.get("_id") != "owned-decoder-document"):
    raise SystemExit("Search returned a different document")
value, = hit["fields"]["decoder_guard"]
source = base64.b64decode(value["input_base64"], validate=True)
witness = base64.b64decode(value["witness_base64"], validate=True)
if source != b"A" * 128 + b"=" or len(witness) != 226:
    raise SystemExit("Unexpected input or destination")
changed = [i for i in range(98, 226) if witness[i] != 90]
if value.get("stage") == "guard-overwrite" and changed == list(range(98, 160)):
    print("guard-overwrite: 62 changed bytes at offsets 98-159")
elif (value.get("stage") == "unchanged" and not changed
        and value.get("attempts") == value.get("exceptions") == 2000):
    print("unchanged: guard intact after 2000 decoder exceptions")
else:
    raise SystemExit("Unexpected guarded result")
PY
)
```

The physical destination is 226 bytes, so the measured write beyond the
decoder's nominal 98-byte capacity stays inside the real allocation.
The affected SDE runs produced the 62-byte witness above. The same runtime
with `-XX:-UseBASE64Intrinsics` and the genuine fixed Temurin runtime each
produced an unchanged guard. Repeat the request against both separate controls;
one unchanged result or an exception alone is not a complete comparison.
