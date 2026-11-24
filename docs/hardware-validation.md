# Hardware validation

This optional guide covers the standalone Base64 decoder probe
(`run_probe.py`) and the Java-bytecode comparison (`run_es7.py`) using
genuine JDKs. For the command interface, use the
[README](../README.md#run-a-command) and [setup guide](setup.md).
`run_probe.py` starts local JVMs; `run_es7.py` starts owned test nodes.
The [guarded search](guarded-search.md#guarded-elasticsearch-search) sends HTTPS requests
to an existing node you own. Run the examples from this repository with
Python 3.10 or later. Keep downloads,
extracted runtimes, and raw reports in the ignored `.validation-local/`
directory, which must be a real directory rather than a symlink or Windows
reparse point. Each `--output` path must be new.

[VALIDATION.md](../VALIDATION.md) records the current command-interface tests.
The earlier Java 17 and 21 guarded comparisons used Intel SDE's ICX model:
both affected JVMs changed 62 guard bytes at offsets 98–159, while the
intrinsic-disabled and fixed controls left the guard intact. The Java 17
and 21 guarded comparisons and the Elasticsearch 8.19.25 command comparison
also passed in an AMD EPYC 9845 KVM guest without SDE. The [native 7.17 client
tests](../VALIDATION.md#native-public-client-tests) had mixed results.
Bare-metal application tests, native Windows x64 and Windows 11 ARM
remain unverified.

Choose the procedure for your environment:

- [Native Linux x86-64](#native-linux-x86-64)
- [Windows x64](#native-windows-11-or-later-x64)
- [Windows ARM with x64 Java](#windows-11-arm)
- [Java 27 and Elasticsearch 8/9](guarded-search.md)
- [Interpreting the result](#guarded-probe-result-interpretation)

## Genuine runtime pairs

Use a full HotSpot JDK, including `java` and `javac`, for each side. The
independently exercised Java 17/21 Linux x64 pairs are:

| Java major | Affected release | Fixed control |
|---|---|---|
| 17 | [Temurin 17.0.21+9](https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_linux_hotspot_17.0.21_9.tar.gz) | [Corretto 17.0.21.1.2](https://corretto.aws/downloads/resources/17.0.21.1.2/amazon-corretto-17.0.21.1.2-linux-x64.tar.gz) |
| 21 | [Temurin 21.0.13+9](https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz) | [Corretto 21.0.13.1.2](https://corretto.aws/downloads/resources/21.0.13.1.2/amazon-corretto-21.0.13.1.2-linux-x64.tar.gz) |

The links and Linux archive SHA-256 values are pinned in
[elasticsearch/releases.json](../elasticsearch/releases.json). Download from
those publisher URLs and verify the archive before extraction. For
example, after downloading a listed archive, this command checks the
selected manifest entry; change `21`, `affected`, and the archive path as
appropriate:

```bash
python3 -B - 21 affected /path/to/downloaded-archive.tar.gz <<'PY'
import hashlib, json, sys
from pathlib import Path

entry = json.loads(Path("elasticsearch/releases.json").read_text())["runtimes"][sys.argv[1]][sys.argv[2]]
archive = Path(sys.argv[3])
actual = hashlib.sha256()
with archive.open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        actual.update(block)
if actual.hexdigest() != entry["archive_sha256"]:
    raise SystemExit("Archive SHA-256 mismatch")
print(entry["name"], actual.hexdigest())
PY
```

For Windows, obtain the corresponding Windows x64 release from the same
publisher and verify its publisher-provided checksum. Record that exact
download URL and checksum privately. The Linux archive hashes do not
authenticate Windows binaries. No Windows artifact hashes or Windows
integration results are currently pinned here. If the exact release or a
genuine native ARM64 pair is unavailable from its publisher, record the
missing artifact and leave that matrix entry unexecuted.

The guarded runner also accepts the upstream Java 25 and 27 release
families. Java 25 remains unvalidated; the [Java 27 pair](guarded-search.md#java-27-guarded-comparison) has passed
the standalone guarded comparison. Its fixed-version floors are `17.0.21.1`, `21.0.13.1`,
`25.0.5.1`, and `27.0.1.1`; both inputs must be on one supported major.
Commercial version schemes and distribution backports need their own
vendor evidence. Do not relabel or modify a runtime to pass the checks.

## Java 27 and Elasticsearch 8/9

The [guarded-search guide](guarded-search.md) contains the authenticated
Java 27 downloads, standalone comparison and HTTPS Painless search request.
Those examples establish bounded corruption; they do not run a command.

## Native Linux x86-64

Use a Linux x86-64 machine that exposes AVX512F, AVX512BW, AVX512VBMI,
and BMI2 to both JVMs. A VM can run the instructions natively if it exposes
the required features. The pinned
[Java 17 build](https://github.com/openjdk/jdk17u/blob/jdk-17.0.21%2B9/src/hotspot/cpu/x86/vm_version_x86.cpp#L883)
also requires AVX512VL to enable Base64 intrinsics by default. Record the CPU model, Linux distribution/kernel,
and whether a hypervisor is present. Hypervisor feature masking can make
an otherwise capable processor ineligible. The runner checks the selected
JVM's own CPU diagnostic and effective intrinsic/compiler/AVX settings,
so `/proc/cpuinfo` alone is not a passed preflight.

Set the four paths to the extracted JDK homes, each containing `bin/java`
and `bin/javac`. Run without `--sde`:

```bash
affected17=/path/to/temurin-17.0.21+9
fixed17=/path/to/corretto-17.0.21.1.2
affected21=/path/to/temurin-21.0.13+9
fixed21=/path/to/corretto-21.0.13.1.2

python3 -B run_probe.py --affected-jdk "$affected17" --fixed-jdk "$fixed17" \
  --output .validation-local/native-linux-java17.json
probe_status=$?
printf 'Java 17 runner exit: %s\n' "$probe_status"

python3 -B run_probe.py --affected-jdk "$affected21" --fixed-jdk "$fixed21" \
  --output .validation-local/native-linux-java21.json
probe_status=$?
printf 'Java 21 runner exit: %s\n' "$probe_status"
```

The default input is 128 `A` bytes followed by `=`. Keep that default for
the first comparison. The test calls the public decoder with a larger
destination array, so the measured write beyond the calculated output
length remains inside the real allocation. The runner verifies the saved
guard witness independently.

After the guarded comparison passes, the application proof can be run on
this same native Linux x86-64 host as a non-root user. It requires the
exact Linux JDK archives above and the pinned
[Elasticsearch 7.17.29 Linux x86-64 archive](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.29-linux-x86_64.tar.gz).
Verify that archive against `elasticsearch/releases.json` and leave its
installation unchanged:

```bash
python3 -B run_es7.py --affected-jdk "$affected21" --fixed-jdk "$fixed21" \
  --elasticsearch /path/to/elasticsearch-7.17.29 --preflight-only \
  --output .validation-local/native-es7-java21-preflight

python3 -B run_es7.py --affected-jdk "$affected21" --fixed-jdk "$fixed21" \
  --elasticsearch /path/to/elasticsearch-7.17.29 \
  --output .validation-local/native-es7-java21
```

Repeat with the Java 17 paths to cover that pinned layout. A successful
application preflight returns `0` with `status=preflight-ok`; it is not an
application execution. The default full comparison returns `0` with
`status=passed` only after the intrinsic-disabled, fixed-runtime, and two
affected-runtime cases complete. Its report must show the exact bytecode
marker, all repair and post-request checks, and successful owned-process
cleanup. Application exit `77` means a skipped prerequisite, including
unavailable Linux pidfd support; `1` means a failed run/control, `130`
SIGINT cancellation, `143` SIGTERM cancellation, and `2` invalid arguments.
This application proof remains limited to Linux x86-64 with pidfd process
handles and the pinned Java 17/21 and Elasticsearch releases; a Windows
guarded-probe result does not extend those application claims.

Use separate output directories for retained-JVM and explicit concurrent-GC
comparisons:

```bash
python3 -B run_es7.py --affected-jdk "$affected21" --fixed-jdk "$fixed21" \
  --elasticsearch /path/to/elasticsearch-7.17.29 \
  --enabled-runs 1 --requests-per-node 3 \
  --output .validation-local/native-es7-java21-retained

python3 -B run_es7.py --affected-jdk "$affected21" --fixed-jdk "$fixed21" \
  --elasticsearch /path/to/elasticsearch-7.17.29 \
  --enabled-runs 1 --requests-per-node 3 --gc-stress \
  --output .validation-local/native-es7-java21-gc
```

Repeat with the Java 17 pair and new output directories. The first profile
keeps ordinary GC settings. The second enables concurrent explicit G1
collection and requires a completed, non-aborted mark-cycle interval to
overlap each affected HTTP request after the first. Preserve every
request's distinct marker-class identity, exact proof, GC evidence, and
post-request checks. This does not prove that collection happened during
every temporary corruption window.

## Native Windows 11 or later, x64

Use a native Windows x64 host and genuine Windows x64 JDKs from one of
the release pairs above. The fixed Corretto
[17.0.21.1.2](https://github.com/corretto/corretto-17/blob/17.0.21.1.2/CHANGELOG.md)
and [21.0.13.1.2](https://github.com/corretto/corretto-21/blob/21.0.13.1.2/CHANGELOG.md)
releases list Windows 11 or later as their Windows target platform.
Record the Windows edition/build, physical CPU
model, host architecture, and publisher archive checksums. Python's
architecture does not establish the selected Java architecture; the
runner checks the JDK metadata and the running JVM independently.

From PowerShell in the repository, set the two paths to the extracted
Windows JDK homes and run:

```powershell
$AffectedJdk = 'C:\path\to\temurin-21.0.13+9'
$FixedJdk = 'C:\path\to\corretto-21.0.13.1.2'
py -3 -B run_probe.py --affected-jdk $AffectedJdk --fixed-jdk $FixedJdk `
  --output .validation-local\native-windows-x64-java21.json
$ProbeExit = $LASTEXITCODE
Write-Output "Runner exit: $ProbeExit"
```

Repeat with the genuine Java 17 pair and a new output filename. Both JVMs
must expose the required CPU features and effective JVM settings described
above, and all three probe
cases must pass. A CPU-prerequisite exit `77` is an accurate unsupported
result for that execution environment, not a fixed-runtime result.
The public SDE option requires POSIX process-group cleanup; do not add
`--sde` to this Windows procedure.

## Windows 11 ARM

Record the physical host as ARM64 and keep native ARM64 Java and
x64-emulated Java in separate result rows. In particular,
`execution.kind=native` in the guarded report means that this runner did
not launch Intel SDE. It does not prove that an x64 Java process on an ARM
host executes without operating-system emulation.

If genuine native Windows ARM64 artifacts are available for a supported
same-major affected/fixed pair, select those JDK homes explicitly:

```powershell
$AffectedArm64Jdk = 'C:\path\to\genuine-affected-windows-arm64-jdk'
$FixedArm64Jdk = 'C:\path\to\genuine-fixed-windows-arm64-jdk'
py -3 -B run_probe.py --affected-jdk $AffectedArm64Jdk --fixed-jdk $FixedArm64Jdk `
  --output .validation-local\windows11-arm-native-java.json
$ProbeExit = $LASTEXITCODE
Write-Output "Native ARM64 Java runner exit: $ProbeExit"
```

The current runner intentionally requires an x86-64 Java image. For a
recognized native ARM64 JDK, the expected result is exit `77`,
`status=unavailable`, `success=false`, and reason
`Selected JDK must identify an x86-64 runtime`. The decoder cases are not
run. Record this as an architecture-guard check, not as evidence that an
affected or fixed decoder was exercised. A missing artifact or another
prerequisite failure does not establish that this architecture check ran.

For x64-emulated Java, use the genuine Windows x64 affected/fixed pair in
the native-Windows command above, but write to a distinct filename such
as `.validation-local\windows11-arm-emulated-x64-java21.json`. Let the
guest JVM diagnostics decide eligibility. Exit `77` with missing CPU
features is expected whenever the emulator does not expose the required
features; it is not a negative vulnerability result. If both preflights
are eligible, require the same complete three-case comparison as on
native x64. Report any successful result as Windows 11 ARM with
x64-emulated Java, rather than physical x86-64 validation.

## Guarded-probe result interpretation

The process exit code and the final JSON must agree:

| Runner exit | JSON result | Interpretation |
|---|---|---|
| `0` | `status=passed`, `success=true` | The affected case and both controls passed. |
| `77` | `status=unavailable`, `success=false` | A platform, runtime, CPU, or effective-JVM prerequisite was not established. No complete comparison is claimed. |
| `1` | `status=failed`, `success=false` | Execution, witness verification, or an expected control failed. Keep the evidence and investigate before making a claim. |
| `2` | Argument error, or result-output write failure | Correct the invocation or select a new output path. A final JSON report may not have been printed. |

For a completed comparison, `cpu.eligible` and `fixed_cpu.eligible` must
both be `true`. The `cases` entries must be:

| Case name | Child-JVM exit | Probe result | Required evidence |
|---|---|---|---|
| `affected` | `42` | `GUARD_OVERWRITE` | `status=passed` and an independently verified guard witness. |
| `disabled-intrinsic` | `0` | `NO_GUARD_OVERWRITE` | `status=passed`; Base64 intrinsics are disabled and no overwrite witness exists. |
| `fixed` | `0` | `NO_GUARD_OVERWRITE` | `status=passed`; the fixed build runs with the required effective intrinsic/compiler settings and no overwrite witness exists. |

The tested SDE Java 17/21 runs observed 62 changed guard bytes at offsets
98–159. Record the actual native witness values; do not substitute those
earlier measurements for a fresh run. A crash, a Java exception by
itself, an eligible CPU, or one intact control is not a complete pass.
The selected runtime version is a candidate classification; the positive
witness and fixed-runtime control establish the observed behavior.

## Recording a hardware result

Keep raw logs, runtime archives and witness files under `.validation-local/`.
A useful public result should identify:

- The date, OS, CPU, Java vendor/build and whether execution was native,
  virtualized, emulated or under SDE.
- The source hashes, authenticated affected/fixed releases, and whether both
  JVM preflights established eligibility.
- The affected witness offsets and changed-byte count, both control outcomes,
  process exit codes, and any failed or unavailable cases.

The runner records these details in its JSON. Remove private paths, usernames,
hostnames and raw host logs before sharing a summary. An absent field stays
absent; a skipped comparison is never a pass.
