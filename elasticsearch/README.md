# Elasticsearch 7 chain

The public client uses the tested Elasticsearch 7.17.28 and 7.17.29
[`POST /_scripts/painless/_execute` API](https://www.elastic.co/guide/en/elasticsearch/painless/7.17/painless-execute-api.html).
The recorded application runs used fresh Basic-license nodes with
`xpack.security.enabled=false`, the [documented 7.17 default](https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-settings.html).
Those nodes accepted the requests without credentials. When security is
enabled, the client must satisfy authentication and authorization for its
Nodes Info and Painless requests; execution in that configuration remains
untested. The local comparison runner never
changes the Painless allowlist, installs a plugin, or adds a permissive
security policy.

The request supplies the Painless source and a compiled Java class as
ordinary parameters. The exploit uses the original malformed-tail Base64
decoder defect as its initial corruption primitive. The public
[`exploit.py`](../exploit.py) client generates its command class through
[`java4shell/command.py`](../java4shell/command.py); that class calls the
[native bridge](../native/README.md) and returns the selected executable's
stdout, stderr and exit status. The older bytecode-validation runner uses
a small file-writing marker class through the same Painless chain.

```mermaid
flowchart LR
    A[Malformed Base64 tail] --> B[Adjacent char array length]
    B --> C[Temporary heap access]
    C --> D[Painless method metadata]
    D --> E[Define request-supplied class]
    E --> F[Invoke supplied class]
    F --> G[Command result or exact marker]
    G --> H[Apply recorded repairs]
    H --> I[Check SecurityManager and fresh scripts]
```

## Source map

| Source element | Purpose |
|---|---|
| `decoderContext`, `warmDecoder`, `invokeDecoder` | Exercise the released Basic decoder through valid warmup calls and the 129-byte malformed input |
| `readPathOnce`, `editRefsOnce` | Check the expected adjacent-object layout, obtain temporary heap access, perform one operation, and repair the affected objects |
| `layoutDiagnostic` | Report transaction count, layout witnesses, decoder exception, and completed repairs |
| Remaining top-level Painless code | Obtain and temporarily change method metadata, define the supplied class, exercise the real SecurityManager, and write back the saved values |
| `marker/.../OwnedBase64Marker.java` | Original bytecode-validation class: write one exact marker using `CREATE_NEW` and return a known string |

The release manifest pins both complete Painless sources. Their formatting
exposes each transaction without changing the original decoder sequence. Java 17 and Java 21 use different offsets for
`System.security`; the three clear/restore/read-back accesses are the
only source differences. Other object offsets are also specific to the
pinned compressed-reference layouts, even where their values coincide.

To follow a command through the code, start at `main()` in
[`exploit.py`](../exploit.py), then `render_request_class()` in
[`java4shell/command.py`](../java4shell/command.py). The
[code guide](../docs/code-guide.md) explains the sequence and ownership rules.
Read the selected Painless file from
`decoderContext()` through its top-level class-definition and invocation
steps. The supplied class calls
[`OwnedNativeCommand.run()`](../native/java/org/elasticsearch/painless/OwnedNativeCommand.java),
which loads the anonymous library and reaches the JNI adapter in
[`native_command.c`](../native/native_command.c), then `execute()` in
[`process_supervisor.c`](../native/process_supervisor.c). Comments in those files
explain the layout assumptions, temporary changes, command deadline and
ownership checks.

## Request contract

The defaults below describe the original `run_es7.py` bytecode comparison.
`exploit.py` and `validate_command.py` supply a generated command class and
request-specific return token through the same parameters.

The script object contains `lang: painless`, the complete selected source,
and these parameters:

| Parameter | Default value (`--requests-per-node 1`) |
|---|---|
| `marker_class` | Base64-encoded `OwnedBase64Marker.class`, compiled for the selected Java major |
| `marker_path` | A previously absent path in that run's working directory |
| `marker_text` | `genuine-base64-es7-decoder-bytecode\n` |
| `marker_return` | `owned-bytecode-executed` |

With `--requests-per-node N` greater than 1, the runner derives a unique class name and
return literal from the hash-verified compiled marker for each ordinal.
Only those two equal-length constant-pool strings change. The disabled,
fixed, and affected nodes receive the same sequence of class bytes, and
each request uses its own previously absent marker path. This lets the
runner distinguish a new execution from a cached method or an earlier
marker without changing the audited Painless sources.
The runner also prefixes each retained request with a distinct line
comment. Elasticsearch's [script cache uses the complete source text](https://github.com/elastic/elasticsearch/blob/580aff1a0064ce4c93293aaab6fcc55e22c10d1c/server/src/main/java/org/elasticsearch/script/ScriptCache.java#L197-L223),
so each request receives fresh compiled Painless method-reference call
sites. This is necessary because an existing call site can retain the
first marker method it resolved. The canonical payload hash and exact
sent-source hash are both recorded.

The successful result must have `stage=bytecode-marker`, the exact return
value, all security and heap restoration flags, and
`last_success_transaction=24`. The server must create the exact marker
bytes itself. The initial and post-restoration attempts to write the
`.denied` marker must fail.

The disabled and fixed controls use the same script and marker class.
They must report `stage=unchanged` on transaction 1, preserve the original
witness length, and leave both marker paths absent.

The 24-transaction counter records operations that passed the payload's
local repair checks, including array-length checks. The runner requires
the payload's reported SecurityManager read-back and renewed file denial.
It independently checks the marker files and runs fresh allowed and
forbidden Painless scripts. It does not audit every changed metadata field.
Defined classes and compiled call sites can remain in the JVM, so the
runner treats the node as disposable and shuts it down after the requested
comparison.

## Repeated requests and GC testing

The default comparison starts four fresh nodes in sequence: one with the
intrinsic disabled, one using the fixed JVM, and two using the affected
JVM. `--enabled-runs 1` selects one affected node. Add
`--requests-per-node 3` to send three sequential requests to every node.
Each request gets its own marker class, return token, file path and script
cache entry. The runner repeats the execution, restoration, process and
sandbox checks after each request.

Add `--gc-stress` to the repeated-request comparison to test concurrent
G1 marking. It enables `ExplicitGCInvokesConcurrent` and invokes the
selected JDK's verified `jcmd <PID> GC.run` during each request after the
first. Each affected request after the first must overlap a completed,
non-aborted mark cycle in the JVM's GC log. This establishes overlap with
the HTTP request, not collection during every temporary corruption window.

The JVM uses a 512 MiB heap and ordinary G1, TLAB and tiered-compilation
settings. No compiler-threshold override is used. The runner checks that
the connected socket belongs to the Elasticsearch JVM it started before
sending HTTP data. It requires Linux pidfd process handles so that process
ownership remains tied to the captured process identity. It does not
accept an existing target URL.

`--startup-timeout` defaults to 1,800 seconds and separately limits JVM
listener discovery and fresh-cluster readiness. `--request-timeout`
defaults to 600 seconds, and `--gc-timeout` to 120 seconds. A custom
`--output` must name a new directory below `.validation-local/`.

SIGINT and SIGTERM are recorded as cancellation requests and handled at
cleanup checkpoints. This keeps process launch, ownership recording and
required finalizers protected. Cancellation waits for an in-flight HTTP
call to finish or raise a socket timeout/error. Payload requests use
`--request-timeout` for blocking socket operations; it is not a total
request-duration limit.

## Exit codes

| Code | Application runner (`run_es7.py`) |
|---|---|
| `0` | The requested comparison passed, or `--preflight-only` succeeded |
| `1` | A required input is missing, execution failed, or a check failed |
| `2` | Invalid command-line arguments |
| `77` | Unsupported platform, release, JVM/CPU configuration, or unavailable Linux pidfd support |
| `130` | Cancelled by SIGINT |
| `143` | Cancelled by SIGTERM |

The smaller `run_probe.py` uses `0` for a complete decoder comparison,
`1` for a failed execution or control, `2` for invalid arguments, and
`77` for unavailable prerequisites.

Recorded results and limitations are in
[VALIDATION.md](../VALIDATION.md). Other Elasticsearch versions, JVM
layouts and concurrent-client reliability have not been established.
