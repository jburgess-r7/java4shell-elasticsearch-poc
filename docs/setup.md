# Setup

## Use an existing node

Use this route when you already have a disposable Elasticsearch node matching
the [tested scope](../README.md#tested-scope). The local client needs Linux
x86-64 with working pidfd process handles, Python 3.10 or later, a C compiler
and JDK 17 or later. Build on a system whose libc is compatible with the
target. Replace `/path/to/jdk-21` with your local JDK directory. The output
directory must be new.

```bash
python3 -B native/build.py \
  --jdk /path/to/jdk-21 \
  --output .validation-local/native-command

python3 -B exploit.py \
  --jdk /path/to/jdk-21 \
  --target http://127.0.0.1:9200 \
  -- /usr/bin/id -u
```

The client selects an exact Elasticsearch release/build and its tested Java
profile. Both 7.17.28 and 7.17.29 permit Java 17 or 21.
Use `--java 17` or `--java 21` to require one. The executable must already exist on the target
and its path must be absolute. The [native guide](../native/README.md)
lists the supported ELF formats, libc and kernel requirements. You need SDE,
Elasticsearch and both pinned JDKs locally only when following the complete
comparison below.

Connect directly to the selected node; a load balancer can route the checks
and exploit to different JVMs. When authentication is required, put the
complete Authorization header in an environment variable and pass its name
with `--auth-header-env`. The account must be allowed to call the
[Nodes Info API](https://www.elastic.co/guide/en/elasticsearch/reference/7.17/cluster-nodes-info.html)
with the `monitor` or `manage` cluster privilege and to execute Painless
scripts. HTTP 401/403 from these APIs is reported as an access failure.
Public client validation for Elasticsearch 7.17 covers the default
Basic-license configuration with X-Pack security disabled.

Use `--remote-dir PATH` to select a target directory whose filesystem
supports anonymous `O_TMPFILE` files and permits loading the native library.
A `noexec` mount can prevent the load. The directory must be outside
Elasticsearch's existing SecurityManager write grants; `/tmp` is the default.

The client prints the target's stdout and stderr and records the complete
response under `.validation-local/`. `--request-timeout` limits socket
operations; it is not a deadline for the whole HTTP request. A client
interruption or HTTP timeout does not independently prove that the remote
command stopped. The native timeout and cleanup run on the server.

| Client exit code | Meaning |
|---|---|
| `0` | Verified command result with target exit status zero |
| `1` | Nonzero target exit, failed check, missing local input or native-library loading error |
| `2` | Invalid command-line arguments |
| `77` | Unavailable local process support, rejected remote profile or explicit native unsupported result |
| `130` | Interrupted by SIGINT |

The saved record preserves the target's actual exit code.

## Reproduce the pinned local comparison

This controlled local comparison remains pinned to Elasticsearch 7.17.29.
Run these commands from the repository directory as a non-root user on
Linux x86-64 with pidfd process-handle support. The preflight checks that
the required operations work through Python or the host C library. Use a
checkout path without spaces. The downloads are the publisher releases recorded in
[elasticsearch/releases.json](../elasticsearch/releases.json); the
checksums below come from that manifest.

Create the local download directory first:

```bash
mkdir -p .validation-local/downloads
```

The completed integration runs used
[Intel SDE 10.13.1](https://www.intel.com/content/www/us/en/download/684897/intel-software-development-emulator.html).
Download `sde-external-10.13.1-2026-07-28-lin.tar.xz` from Intel and save it
under `.validation-local/downloads/`. Follow any download or license prompts
Intel presents. Verify and unpack the complete kit:

```bash
sha256sum --check <<'SHA256'
94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50  .validation-local/downloads/sde-external-10.13.1-2026-07-28-lin.tar.xz
SHA256
```

Continue only when that check says `OK`:

```bash
mkdir -p .validation-local/runtimes
tar -xJf .validation-local/downloads/sde-external-10.13.1-2026-07-28-lin.tar.xz \
  -C .validation-local/runtimes
```

Keep all kit files together. Its executable is
`.validation-local/runtimes/sde-external-10.13.1-2026-07-28-lin/sde64`.
The runner selects the ICX model. The native-hardware route remains
unvalidated here.

The commands use `curl`, `sha256sum` and `tar`. They keep the archives and
extracted releases in the ignored `.validation-local/` directory. Use
empty destination directories so an older installation cannot be mixed
with these files.

```bash
mkdir -p .validation-local/downloads

curl --fail --location \
  'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz' \
  --output .validation-local/downloads/temurin21.tar.gz

curl --fail --location \
  'https://corretto.aws/downloads/resources/21.0.13.1.2/amazon-corretto-21.0.13.1.2-linux-x64.tar.gz' \
  --output .validation-local/downloads/corretto21.tar.gz

curl --fail --location \
  'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.29-linux-x86_64.tar.gz' \
  --output .validation-local/downloads/elasticsearch-7.17.29.tar.gz

sha256sum --check <<'SHA256'
d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c  .validation-local/downloads/temurin21.tar.gz
2aaa2a9a43143b20ff0b28c8d0da27407b97dc40b160d9a2f60a26965815e948  .validation-local/downloads/corretto21.tar.gz
f7175de3ac8ca16326b9dbdff4ef70bc3da6405efe624655444ba2464073ea8e  .validation-local/downloads/elasticsearch-7.17.29.tar.gz
SHA256
```

Continue only when all three checksum checks say `OK`:

```bash
mkdir -p .validation-local/runtimes/temurin21 \
  .validation-local/runtimes/corretto21 \
  .validation-local/runtimes/elasticsearch-7.17.29

tar -xzf .validation-local/downloads/temurin21.tar.gz \
  --strip-components=1 -C .validation-local/runtimes/temurin21
tar -xzf .validation-local/downloads/corretto21.tar.gz \
  --strip-components=1 -C .validation-local/runtimes/corretto21
tar -xzf .validation-local/downloads/elasticsearch-7.17.29.tar.gz \
  --strip-components=1 -C .validation-local/runtimes/elasticsearch-7.17.29
```

The selected JVM must expose AVX512F, AVX512BW, AVX512VBMI and BMI2 and
enable the required compiler and Base64 intrinsic. The Java 17 build also
requires AVX512VL for the default intrinsic setting. The runner checks
the effective JVM settings, so a CPU model name alone is insufficient.

Check the SDE installation and pinned releases without starting
Elasticsearch:

```bash
python3 -B run_es7.py \
  --affected-jdk .validation-local/runtimes/temurin21 \
  --fixed-jdk .validation-local/runtimes/corretto21 \
  --elasticsearch .validation-local/runtimes/elasticsearch-7.17.29 \
  --sde /path/to/sde64 \
  --preflight-only
```

Replace the SDE path with the executable from the unpacked kit. A
successful preflight ends with `status` set to `preflight-ok`; it is not an
exploit result. Remove `--preflight-only` to run the full comparison. On an
eligible native host, omit `--sde`; the
[hardware procedure](hardware-validation.md) describes how to record a
native result. Missing input paths return `1`; an unsupported release,
platform, effective JVM/CPU configuration or unavailable pidfd support
returns `77`. SIGINT and SIGTERM are recorded as cancellation requests and
handled at cleanup checkpoints. An in-flight HTTP call must finish or
raise a socket timeout/error first; the timeout is not a total
request-duration limit. The exit codes are `130` and `143` respectively.

Java 17 uses the same commands with the affected/fixed URLs and archive
hashes from the `runtimes.17` entries in
[releases.json](../elasticsearch/releases.json). Keep the affected and
fixed JDKs on the same Java major.

## Build and test the command interface

Use a Linux x86-64 C compiler and the downloaded JDK to build the native
command bridge. Build on a system whose libc is compatible with the target.
Both output directories below must be new.

```bash
python3 -B native/build.py \
  --jdk .validation-local/runtimes/temurin21 \
  --output .validation-local/native-command

python3 -B validate_command.py \
  --major 21 \
  --build .validation-local/native-command \
  --output .validation-local/command-demo-java21 \
  --expect-stdout-base64 "$(id -u | base64 -w0)" \
  -- /usr/bin/id -u
```

The comparison uses the pinned runtime/SDE directories above. It starts
its own disabled-intrinsic, fixed-runtime and affected nodes, checks the
exact command output, then shuts down its owned processes. The expected
value is the account running these local nodes. See the
[test results](../VALIDATION.md) for completed comparisons
and the [native bridge guide](../native/README.md) for executable and kernel
requirements.
