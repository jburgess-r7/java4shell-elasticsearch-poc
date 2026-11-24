# Java4Shell Elasticsearch PoC

This [Rapid7](https://www.rapid7.com/) research PoC uses CVE-2026-114938 to
run a selected Linux executable through Elasticsearch 7.17.28 or 7.17.29 in a
supervised child and return its stdout, stderr and exit status. An HTTP request to
`POST /_scripts/painless/_execute` supplies the exploit and Java bytecode.
The original Base64 decoder flaw provides the initial memory corruption.

The exploit sources are [Java 17](elasticsearch/payload-java17.painless)
and [Java 21](elasticsearch/payload-java21.painless). See
[Rapid7's ETR analysis](https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17/)
for background, mitigations and vendor updates.
To understand the implementation, follow the [code guide](docs/code-guide.md)
from the HTTP client through the Painless payload and native bridge.

On an AMD EPYC 9845 KVM guest, the public client returned exact command
output in one of five attempts, on 7.17.28 with Java 21. See the
[native test matrix](VALIDATION.md#native-public-client-tests).

## Run a command

[`exploit.py`](exploit.py) is the public command-line client. For an existing
node matching the [tested scope](#tested-scope), build the command bridge
once, then pass an executable and its arguments. The local machine needs
Linux x86-64, working pidfd process handles, Python 3.10+, a C compiler and
JDK 17+. Replace `/path/to/jdk-21` with your local JDK directory; the build
output directory must be new.

```bash
python3 -B native/build.py \
  --jdk /path/to/jdk-21 \
  --output .validation-local/native-command

python3 -B exploit.py \
  --jdk /path/to/jdk-21 \
  --target http://127.0.0.1:9200 \
  -- /usr/bin/id -u
```

Recorded `/usr/bin/id -u` commands under Intel SDE on both tested
Elasticsearch releases with Java 17 and 21 returned:

```text
1000
```

Their stderr reported `Target exit status: 0`. See the
[recorded demo](docs/demo.md) for the actual commands, output and controls.
To reproduce the entire comparison with affected and fixed JVMs, follow the
[local setup guide](docs/setup.md#reproduce-the-pinned-local-comparison).

The executable must already exist on the Elasticsearch host and have an
absolute path. Connect directly to the selected node. Use
`--auth-header-env NAME` when authentication is required; the account needs
Nodes Info access and Painless script execution. `--remote-dir` defaults to
`/tmp`; its filesystem must support anonymous `O_TMPFILE` files and native
library loading, and the directory must be outside Elasticsearch's normal
SecurityManager write grants. The [client guide](docs/setup.md#use-an-existing-node)
covers these requirements, timeouts and exit codes.

## Which files matter?

| File or directory | Purpose |
|---|---|
| [exploit.py](exploit.py) | Run a command against a selected Elasticsearch node. Start here. |
| [elasticsearch/](elasticsearch/README.md) | The actual Java 17/21 Painless exploit chains and pinned release details. |
| [native/](native/README.md) | Build and inspect the command bridge needed by Elasticsearch's Linux syscall filter. |
| [java4shell/](java4shell/) | Shared request construction, result verification, process supervision and optional GC helpers. |
| [run_es7.py](run_es7.py) | Start disposable nodes for the original bytecode comparison and provide the node lifecycle used by `validate_command.py`. |
| [validate_command.py](validate_command.py) | Start owned local nodes and compare affected, intrinsic-disabled and fixed JVMs. |
| [run_probe.py](run_probe.py), [poc/](poc/Base64TailProbe.java) | Reproduce the underlying Base64 corruption independently of Elasticsearch. |
| [docs/](docs/setup.md), [VALIDATION.md](VALIDATION.md) | Setup, recorded demos, evidence, the [code guide](docs/code-guide.md), and [guarded-search procedure](docs/guarded-search.md). |
| [tests/](tests/), [native/tests/](native/tests/README.md) | Maintainer regression tests. |

The shared modules are imported by the client and runners. Keep the checkout
together; `exploit.py` is the only entry point needed to use an existing node.

## Tested scope

| Component | Release |
|---|---|
| Elasticsearch | [7.17.29](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.29-linux-x86_64.tar.gz) and [7.17.28](https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.28-linux-x86_64.tar.gz), each with Java 17 or 21. Linux x86-64. |
| Java 17 affected / fixed | [Temurin 17.0.21+9](https://github.com/adoptium/temurin17-binaries/releases/tag/jdk-17.0.21%2B9) / [Corretto 17.0.21.1.2](https://corretto.aws/downloads/resources/17.0.21.1.2/amazon-corretto-17.0.21.1.2-linux-x64.tar.gz) |
| Java 21 affected / fixed | [Temurin 21.0.13+9](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.13%2B9) / [Corretto 21.0.13.1.2](https://corretto.aws/downloads/resources/21.0.13.1.2/amazon-corretto-21.0.13.1.2-linux-x64.tar.gz) |

The successful 7.17 command-execution tests used fresh Basic-license nodes with
`xpack.security.enabled=false`, the [documented 7.17 default](https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-settings.html).
Those requests needed no credentials. The client accepts an Authorization
header, but its 7.17 command interface has not been tested with X-Pack security enabled.
[Elastic's advisory](https://www.elastic.co/blog/java4shell-remote-code-execution-rce-vulnerability)
describes authenticated RCE and unauthenticated denial of service.

A separate [guarded search](docs/guarded-search.md#guarded-elasticsearch-search)
reproduces the bounded decoder overwrite on security-enabled Elasticsearch
8.19.25 and 9.5.6. On security-enabled 8.19.25 with Java 21, separate lab
comparisons demonstrated request-supplied Java bytecode and one preset OS
command, with intrinsic-disabled and fixed-runtime controls. The command
comparison passed under SDE and without SDE in an AMD EPYC 9845 KVM guest.
The public command client accepts the exact 7.17 profiles above. Bytecode
and OS-command execution on 9.x remain unverified. See the [test summary](VALIDATION.md).

The client checks the server's reported release, JVM vendor/build and
compressed-reference metadata. Those API fields do not attest the binaries
or verify every JVM flag, layout or CPU prerequisite. The payload depends
on the pinned JVM layouts and an eligible AVX-512/VBMI decoder. The 7.17
client passed on the listed profiles under Intel SDE 10.13.1 ICX.
Bare-metal application tests, other JVM layouts and native Windows targets
remain unverified.

Stock Linux Elasticsearch blocks ordinary process execution through its
syscall filter. The bridge loads a dynamically linked x86-64 PIE ELF
executable and its linker into a child without `execve` or `execveat`;
the filter remains active. Programs that launch other executables still
encounter it. Standard input is `/dev/null`, each output stream is capped
at 64 KiB, and the interface has no interactive shell. See the
[native guide](native/README.md) for libc, kernel and executable requirements.

Defined classes, compiled call sites and loaded native code can remain
until Elasticsearch exits. Treat the node as disposable. The
[validation record](VALIDATION.md) and
[original bytecode demo](docs/bytecode-demo.md) describe the checks and
remaining limits.

## Credits and development

[Calif disclosed Java4Shell](https://calif.io/java4shell/) and reported
Elasticsearch code execution. Related work includes
[ikow's toolkit](https://github.com/ikow/java4shell-poc),
[zejunyang's local JVM lab](https://github.com/zejunyang/java4shell-rce)
and [chjwoo7's Spring Boot demonstration](https://github.com/chjwoo7/java4shell).
This project contributes an Elasticsearch 7.17 command execution PoC with
affected, intrinsic-disabled and fixed-runtime comparisons. The upstream repair is
[OpenJDK JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b).
The native entry handoff uses a small part of
[Rapid7 libreflect](https://github.com/rapid7/mettle/blob/98c61149d1e2ca769f7d27f96960c42633548903/libreflect/arch/linux/x86_64/arch_jump.h),
with its BSD notice retained.

Run regressions with `python3 -B -m unittest discover -s tests -v`.
The [manual Actions workflow](.github/workflows/tests.yml) covers Linux and
Windows with Python 3.10–3.15; hosted results remain unverified.
No license has been selected.
