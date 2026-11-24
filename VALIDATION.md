# Test results

The public command client covers the pinned Elasticsearch 7.17.28 and 7.17.29
profiles in the [README](README.md#tested-scope). Separate lab results cover
Elasticsearch 8.19.25; the 9.5.6 result establishes bounded decoder corruption.
The [demo](docs/demo.md) shows recorded command output under Intel SDE, and
[setup](docs/setup.md) explains how to run the comparison.

## Current source verification

The Python client and comparison now expose named preparation, execution and
verification steps. The generated Java class has a separate template, and the
native library has separate ELF-loading, supervision and JNI source files.
Painless formatting preserves the original tokens and transaction order; the
[release manifest](elasticsearch/releases.json) pins the reformatted sources.

- Linux Python 3.12.3: all 140 regressions passed with the genuine Java 21
  runtime and a fresh native build.
- All 15 focused generated-request/loader checks also passed on Java 17.
- All 13 native input/cleanup checks passed with that build.
- A clean export built the same native library and Java bridge. Its suite
  passed 125 tests and explicitly skipped 15 requiring local test prerequisites.

Fresh comparisons on 23 November used genuine Elasticsearch 7.17.29 with the
pinned Temurin 17/21 and fixed Corretto releases under Intel SDE 10.13.1 ICX.
Eight exploit-bearing requests across six JVMs produced four exact command
executions, two intrinsic-disabled controls and two fixed-runtime controls.
Each affected node ran one controlled request and the normal public client;
all four returned exactly `1000\n` from `/usr/bin/id -u`, empty target stderr
and exit status 0. The controls stopped at the unchanged first witness and
produced no command result or marker.

Raw-response checks verified the supplied class/token, all 24 reported repair
checks, exact marker bytes for the controlled requests, anonymous-library
descriptor closure, `NoNewPrivs=1` and `Seccomp=2`. Fresh allowed/forbidden
scripts passed. All six nodes shut down normally; recorded owned processes
were absent, and no fatal JVM logs were found. These results apply to the
reorganized sources and newly built bridge. The 7.17.28, native-hardware and
Elasticsearch 8/9 observations below were not repeated for this revision.

## Earlier Elasticsearch 7.17 results

These results predate the source reorganization above. Successful command
runs used fresh Basic-license nodes with the stock 7.17 default of X-Pack
security disabled. Execution with 7.17 authentication enabled remains untested.

| Comparison under Intel SDE 10.13.1 ICX | JVMs | Exact commands | Disabled controls | Fixed controls |
|---|---:|---:|---:|---:|
| 7.17.29, Java 17 and 21 | 6 | 4 | 2 | 2 |
| 7.17.28, Java 17 and 21 | 7 | 5 | 2 | 2 |

Both normal 7.17.29 public clients passed. The 7.17.28 count includes a
fresh-node test of the release-selecting public client on Java 21. The
7.17.29/Java 17 controlled command returned the expected `printf` bytes;
the other commands returned exactly `1000\n` from `/usr/bin/id -u`. All nine
commands had empty target stderr and exit status 0.

All nine recorded `NoNewPrivs=1` and `Seccomp=2`. Live descriptor audits passed,
all thirteen nodes shut down normally, recorded process identities were absent,
and no fatal JVM logs were found. A separate clean-export check on 19 November
also built the public sources and returned exact `1000\n`, empty target stderr
and exit 0 through the ordinary client on an owned Java 21/SDE node.

## Native public client tests

On 23 November, the same AMD EPYC 9845 KVM guest ran the 7.17 profiles
without SDE. Each trial used a separate loopback JVM with the default
Basic-license security configuration and the test runner's standard warmup.
The unmodified client also ran its own warmup.

| Elasticsearch and Java | Controlled affected request | Ordinary client |
|---|---|---|
| 7.17.29 / 21 | Exact command output | First witness unchanged in both attempts |
| 7.17.29 / 17 | First witness unchanged | First witness unchanged |
| 7.17.28 / 21 | First witness unchanged | Exact command output |
| 7.17.28 / 17 | Stopped at a metadata check | First witness unchanged |

Both exact command results were `1000\n` from `id -u`, with empty stderr
and exit 0. All eight intrinsic-disabled and fixed controls stopped at the
unchanged first witness. All 17 nodes shut down normally, with no fatal JVM
logs. These observations cover one guest. The cause of the native misses and
repeatability across deployments remain open.

## Separate Elasticsearch 8/9 lab results

These comparisons used security-enabled nodes with HTTPS and transport TLS.
The authenticated account had `read` on one test index; unrelated administrative
and write operations were denied. Stock Painless allowlists, Entitlements and
the Linux syscall filter remained active. The public command client does not
accept these releases.

| Target and JVM | Environment | Established result |
|---|---|---|
| 8.19.25 and 9.5.6, bundled Oracle Java 27 | SDE ICX | Bounded decoder overwrite on both affected nodes; four unchanged controls. |
| 8.19.25, separately supplied Temurin Java 21 | SDE ICX | Exact supplied Java class/token and independently checked 51-byte file; both controls stopped before execution. |
| 8.19.25, separately supplied Temurin Java 21 | SDE ICX | Preset `id -u`: exact `1000\n`, empty stderr, exit 0; both controls ran no command. |
| 8.19.25, separately supplied Temurin Java 21 | AMD EPYC 9845 KVM guest, without SDE | The same exact preset command result; both controls ran no command. |

The Java 27 search comparison comprised six requests across six JVMs. Both
affected cases changed 62 guard bytes at offsets 98–159; the four controls
completed 2,000 attempts with unchanged guards. Each separate Java 21 lab
comparison used three JVMs. All nodes in these comparisons recorded ordinary
cleanup. The native command proof also had separately checked raw responses,
marker bytes, descriptors and process cleanup.

These observations establish supplied bytecode and a preset command on the
tested 8.19.25/Java 21 combination. Bytecode and command execution on 9.x remain
unverified. The [guarded-search guide](docs/guarded-search.md) supplies the
bounded probe and authenticated publisher downloads for the
[8.19.25 archive](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.19.25-linux-x86_64.tar.gz)
and [9.5.6 archive](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.5.6-linux-x86_64.tar.gz).

## Earlier decoder and tooling checks

On 23 November, an Ubuntu 24.04.5 x86-64 KVM guest exposed AVX512F, AVX512BW
and AVX512VBMI on all four vCPUs of an AMD EPYC 9845. Both affected Temurin
17/21 decoders changed 62 guard bytes at offsets 98–159. For each major, the
intrinsic-disabled and fixed Corretto controls left the guard intact across
2,000 attempts. A local-machine native preflight had previously skipped with
exit 77 because those AVX-512/VBMI flags were absent.

The standalone Oracle `27.0.1.0.3+1-2` decoder bundled with Elasticsearch
8.19.25/9.5.6 produced the same bounded overwrite under SDE. Its disabled
control and genuine fixed Temurin `27.0.1.1+4` left the guard unchanged.

<details>
<summary>Regression and loader results from earlier source revisions</summary>

- The 140-test suite passed without skips on Linux Python 3.12.3 with the local
  Java 21/native prerequisites. A bare export passed 125 and skipped 15. All
  32 focused command/client checks passed.
- The earlier 137-test suite passed without skips on Python 3.10.19, 3.12.3
  and 3.14.3. Windows Python 3.10.11 and 3.14.10 under Wine 9 each passed 72
  tests and skipped 65. This does not establish native Windows behavior.
- Fifteen focused generated-request/loader checks passed on Java 17; the
  corresponding Java 21 checks passed in the complete Linux suites.
- Twenty-three native/SDE checks passed with 31 ordinary outer-process
  cleanup records. Descriptor checks distinguished the request's closed
  channel from SDE's separate retained read-only image handle. Native-mode
  checks retained no matching descriptors.

</details>

The manual Linux/Windows Python 3.10–3.15 Actions workflow is configured;
hosted results remain unverified. Failed, interrupted and skipped attempts
are excluded from successful comparison counts. Local build manifests retain
source/artifact hashes. The [older bytecode demo](docs/bytecode-demo.md) and
[hardware guide](docs/hardware-validation.md) cover the separate probe paths.

## What counts as a pass

The 7.17 command comparison sends the same Painless source and request-class
bytes to affected, intrinsic-disabled and genuine fixed JVMs. A positive
must return the expected class and request-specific token, exact stdout and
stderr, and the target exit status. It must also create the exact marker
bytes checked independently by the local runner. The normal public client
creates no marker file. Both controls must stop at the unchanged first
corruption witness and produce no command result or marker.

The command must retain the Linux syscall filter, finish its native cleanup,
reap its supervisor, and report anonymous-library creation and closure of
the request's descriptor. The payload must report all 24 repair checks, the
original SecurityManager read-back and denial of the same file operation
before and after restoration. Fresh allowed and forbidden Painless scripts
provide additional behavioral checks. A crash, HTTP failure, wrong output,
incomplete repair or unexpected control result fails the comparison.

These checks do not independently read back every modified metadata field.
Defined classes, compiled call sites and loaded native code can persist.
Intel SDE can also retain a separate read-only image handle. Every test node
is disposable. Earlier GC tests established overlap with the HTTP request,
not collection during each temporary corruption window.

## Remaining gaps

- Bare-metal application runs, native 7.17 client repeatability and other AVX-512/VBMI CPU models. See the [hardware procedure](docs/hardware-validation.md).
- Native Windows application targets and Windows 11 ARM environments.
- Command execution beyond the tested Elasticsearch releases, JVM layouts and commercial Java variants.
- Sustained repetition, concurrent clients, compiler-tier and deoptimization stress, and general GC safety.
- An isolated `noexec`-mount test; this environment rejected the required user namespace.
- Hosted CI, including Python 3.11, 3.13 and 3.15.

The results cover the pinned Linux x86-64 Elasticsearch and Java combinations
in the stated environments. Reliability on other configurations remains unverified.
