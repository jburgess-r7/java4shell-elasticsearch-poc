# Recorded command-execution demo

On 19–20 November 2026, this PoC ran Linux commands through the original
CVE-2026-114938 decoder flaw in genuine Elasticsearch 7.17.28 and 7.17.29,
each with Java 17 and 21. The runs used Temurin 17.0.21+9 and 21.0.13+9
under Intel SDE 10.13.1 ICX. The command tests, including the public client
runs, used fresh 7.17 Basic-license nodes with X-Pack security disabled by
default.

## Run it

Build the command bridge using the [README quick start](../README.md#run-a-command).
For an existing disposable node with a tested profile, use the same local
JDK path when running the client:

```bash
python3 -B exploit.py \
  --jdk /path/to/jdk-21 \
  --target http://127.0.0.1:9200 \
  -- /usr/bin/id -u
```

Replace `/path/to/jdk-21` with the JDK directory used for the build. The
[setup guide](setup.md#build-and-test-the-command-interface) also starts a
complete comparison on owned affected, intrinsic-disabled and fixed-runtime
nodes. The [native guide](../native/README.md) covers executable, libc and
kernel requirements.

## Actual recorded output

The public-client runs executed `/usr/bin/id -u` and returned:

```text
1000
```

The Java 21 client's stderr included:

```text
Checking the selected Elasticsearch/JVM profile...
Warming the decoder...
Sending the request-supplied command class...

Target exit status: 0
```

The local report-path line is omitted from this excerpt. The target command
itself produced no stderr. The numeric UID is the account that ran the
recorded node; it can differ on another host.

The controlled comparisons also checked exact output:

| Elasticsearch / Java | Command | Actual stdout |
|---|---|---|
| 7.17.29 / Java 17 | `/usr/bin/printf 'java4shell-command:%s\n' verified-output` | `java4shell-command:verified-output\n` |
| 7.17.29 / Java 21 | `/usr/bin/id -u` | `1000\n` |
| 7.17.28 / Java 17 | `/usr/bin/id -u` | `1000\n` |
| 7.17.28 / Java 21 | `/usr/bin/id -u` | `1000\n` |

All had empty target stderr and exit status 0. For each tested profile, the
intrinsic-disabled and genuine fixed-runtime controls stopped at the
unchanged first corruption witness and produced no command result.

The 7.17.29 comparisons covered eight requests across six JVMs; the 7.17.28
comparisons and fresh Java 21 client check covered nine requests across seven JVMs.
Together they produced nine exact command results and eight clean controls.
The Linux syscall filter remained active. All thirteen nodes shut down normally,
every recorded owned process identity was absent afterward, and no fatal JVM
logs were found.

The [test results](../VALIDATION.md) describe the pass criteria and remaining
gaps. The [earlier Java-bytecode demonstration](bytecode-demo.md) explains
the separate marker-class proof. These recorded runs used Linux and SDE.
The [native client tests](../VALIDATION.md#native-public-client-tests)
produced one exact command result in five attempts in a KVM guest.
