# Earlier Java-bytecode demonstration

For the current executable-and-output interface, see the
[command-execution demo](demo.md). This page records the earlier proof that
the Painless chain can define and invoke request-supplied Java bytecode.

On 18 November 2026, the public runner executed request-supplied Java
bytecode inside genuine Elasticsearch 7.17.29 using Temurin 21.0.13+9 and
Intel SDE 10.13.1's ICX CPU model. It also repeated the request in the same
JVM, and sent the same class sequence to an intrinsic-disabled JVM and a
genuine fixed Corretto JVM. All six requests passed their required checks.
The Java 17 comparison passed the same profile separately.

## What executes

The HTTP request contains the [Painless exploit](../elasticsearch/payload-java21.painless)
and the bytes of [this Java class](../elasticsearch/marker/org/elasticsearch/painless/OwnedBase64Marker.java).
The exploit defines the class inside the server and invokes its `run()`
method. The method creates a previously absent file with `CREATE_NEW`,
writes the supplied text, and returns a compiled-in string. Repeated
requests use distinct class names and return strings, so an earlier
execution cannot satisfy a later request.

The runner requires the exact class name and return value in the HTTP
response, then reads the file independently and checks its exact contents.
The payload reports denial of the same file operation before it clears
the original SecurityManager and again after it restores that manager.

## Reproduce it

Use the [setup guide](setup.md) to obtain the genuine pinned releases.
From the repository root, run with a new output directory:

```bash
python3 -B run_es7.py \
  --affected-jdk .validation-local/runtimes/temurin21 \
  --fixed-jdk .validation-local/runtimes/corretto21 \
  --elasticsearch .validation-local/runtimes/elasticsearch-7.17.29 \
  --sde .validation-local/runtimes/sde-external-10.13.1-2026-07-28-lin/sde64 \
  --enabled-runs 1 --requests-per-node 2 --gc-stress \
  --output .validation-local/demo-java21
```

This starts three fresh local nodes in sequence: disabled intrinsic,
fixed runtime, then affected runtime. Each receives two requests. The
second request also triggers concurrent G1 collection. SDE startup can
take several minutes per node; the final `status=passed` requires every
proof, control and cleanup check to pass.

## Recorded result

The Java 21 console output included:

```text
Checking pinned Java and Elasticsearch releases...
Checking effective JVM settings...
Starting 01-disabled
01-disabled: request 1 passed
01-disabled: request 2 passed
01-disabled: passed
Starting 02-fixed
02-fixed: request 1 passed
02-fixed: request 2 passed
02-fixed: passed
Starting 03-affected
03-affected: request 1 passed
03-affected: request 2 passed
03-affected: passed
```

The final summary reported `status=passed`. Its local report-path line is
omitted here.

Selected fields from the first affected request's actual HTTP response
are shown below, reordered for readability:

```text
HTTP 200
stage=bytecode-marker
success=true
marker_class=class org.elasticsearch.painless.OwnedBase64M00001
bytecode_result=owned-bytecode-00000001
file_denied=true
security_restored=true
security_readback=true
post_restore_denied=true
last_success_transaction=24
```

The independently read file contained exactly:

```text
genuine-base64-es7-decoder-bytecode
```

That includes one trailing newline. Request 2 executed
`org.elasticsearch.painless.OwnedBase64M00002`, returned
`owned-bytecode-00000002`, and created its own marker file. Both disabled
and fixed requests returned `stage=unchanged`, with witness length `20`,
zero completed transactions and no marker file.

After reproducing the demo, inspect your own response fields and file:

```bash
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps(r["proof"]["fields"], indent=2))' \
  .validation-local/demo-java21/03-affected/request-001/request.json
cat .validation-local/demo-java21/03-affected/request-001/execution-marker
```

The original `trigger.json` alongside that file contains the complete
HTTP response. `request-002/` contains the second request's separate
response and marker. The [chain walkthrough](../elasticsearch/README.md)
explains the request parameters and repair checks.

## Scope

Across the Java 17/21 comparisons, all six nodes completed ordinary
cleanup, with no surviving recorded server identities or fatal JVM logs.
These results establish the pinned
Linux/SDE configurations with the default Basic-license security setting.
They do not establish security-enabled execution, native-hardware results,
other JVM layouts, complete restoration of the JVM's prior state, or
general concurrent-client reliability. The test summary and
remaining gaps are in [VALIDATION.md](../VALIDATION.md).
