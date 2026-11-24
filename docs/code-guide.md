# Reading the code

Start with `main()` in [exploit.py](../exploit.py). It checks the selected
Elasticsearch/JVM profile, compiles a request-specific Java class, warms the
decoder, sends the Painless payload, verifies the response and prints the
command's streams. The client does not start or shut down the target node.

## Source map

| File | Responsibility |
|---|---|
| [exploit.py](../exploit.py) | Existing-target HTTP client, authentication, profile selection and CLI output. |
| [java4shell/command.py](../java4shell/command.py) | Generate the supplied Java class and decode its strict command-result envelope. The [Java template](../java4shell/templates/OwnedCommand.java.template) contains the target-side class. |
| [java4shell/es7.py](../java4shell/es7.py) | Shared Painless scripts and result parsing, plus local release verification and HTTP connections bound to an owned lab node. |
| [java4shell/processes.py](../java4shell/processes.py) | Signals, pidfds, subprocess ownership, timeouts and descendant cleanup. The client uses it for its local compiler. |
| [java4shell/common.py](../java4shell/common.py) | Repository paths, hashes, JSON records and the shared unavailable-prerequisite exception. |
| [java4shell/bytecode.py](../java4shell/bytecode.py) | Read class identity and derive distinct file-marker classes for repeated bytecode tests. |
| [java4shell/gc.py](../java4shell/gc.py) | Optional `jcmd GC.run` worker and parsing of completed G1 cycles. |
| [run_es7.py](../run_es7.py) | Start disposable nodes and compare the original file-marker proof on affected, disabled-intrinsic and fixed runtimes. |
| [validate_command.py](../validate_command.py) | Use the same node lifecycle for exact command-output comparisons. |
| [run_probe.py](../run_probe.py), [Base64TailProbe.java](../poc/Base64TailProbe.java) | Standalone guarded decoder comparison, including platforms outside the Linux application client's scope. |

The GC worker and local node lifecycle are separate from the public client's
execution path. The standalone probe has its own portable launcher because
the application's pidfd-based ownership checks require Linux.

## Follow one command

1. `parse_arguments()` checks paths and credentials; `target_profile()` checks the node's reported release/build and JVM metadata.
   These checks select a known layout. They do not attest remote binaries or
   prove that the vulnerable intrinsic will execute.
2. `prepare_request()` verifies the native build, then `render_request_class()` embeds the executable, arguments, bridge class and
   native library into a fresh Java class. Its name and compiled-in token share
   a random nonce. Arguments are length-prefixed UTF-8 strings, with no shell
   parsing. `javac` runs as an owned local subprocess.
3. `checked_payload()` checks the selected Painless source hash and changes its
   return contract to carry the command result. It also adds a fresh source key
   to prevent a prior compiled Painless call site from satisfying this request.
4. The Painless chain must first observe the original decoder corruption.
   Only then can it reach the supplied class. The intrinsic-disabled and fixed
   controls stop at that first witness.
5. The supplied class verifies and loads the bridge through an anonymous inode,
   executes the command and closes its own library descriptor. The normal
   client creates no named marker. The controlled comparison additionally
   creates an exact file that the local runner can inspect independently.
6. `remote_proof()` checks the class, token, repair sequence and permission
   probes. `decode_result()` validates the nested JSON, exact types, output
   bounds and native cleanup fields. Fresh allowed/forbidden scripts check the
   observed post-request behavior before the client prints command output.

The saved JSON still uses names such as `marker` and `marker_return` for the
request-class identity. Those are also used by the older file-marker proof;
they do not mean that the public command client writes a marker file.

## Understand the Painless chain

Read the [Java 21 payload](../elasticsearch/payload-java21.painless) in this order.
The [Java 17 payload](../elasticsearch/payload-java17.painless) has the same
structure, with its pinned `System.security` offset changed.

- **`decoderContext()` and `warmDecoder()`** create the malformed input and
  exercise the decoder call site. The trigger is 128 `A` bytes followed by `=`.
- **`readPathOnce()`** allocates a 98-byte destination beside a `char[]` witness,
  guard and reference array. It requires the expected corrupted witness and
  intact neighboring layout. An unchanged witness returns immediately.
- **`heapInt()` and `heapWriteInt()`** interpret the temporary array as heap
  access. Offsets are bytes, reference words are 32-bit compressed oops, and
  `shift` converts those words into byte distances. The negative-index
  expressions in `rawRead()`/`rawWrite()` are intentional parts of this sequence.
- **`readPath()` and `editRefs()`** perform one transaction, repair the temporary
  array header and return captured values. Higher-level edits save previous
  metadata and write those values back after linking each callable.
- **The top-level chain** follows pinned object fields to Painless's lookup
  tables. It temporarily redirects existing method metadata to obtain a lookup,
  define the supplied class and link its `run` method. It then exercises a real
  file-permission denial, temporarily changes the SecurityManager reference,
  invokes the class, restores that reference and repeats the denied operation.

For example, `new int[]{16,24,16,52,88,16}` is a sequence of object-field byte
offsets, not a list of arbitrary constants or array indices. `new int[]{12,16,20}`
selects the reference fields to copy from the object reached by that path.
These values belong to the pinned layouts. Formatting changes preserve the
original tokens and transaction order. The release manifest pins the complete
source, including comments and whitespace, so a changed file requires a new pin
and a new application comparison.

A successful response establishes the recorded repair and permission checks.
Defined classes, linked call sites and native code can remain. It does not
establish complete restoration or concurrent-client safety.

## Native execution and ownership

The Java bridge's `openAnonymous()` returns a caller-owned channel to an
`O_TMPFILE|O_EXCL` inode. The supplied class writes and hashes that same inode.
`OwnedNativeCommand.run()` verifies its identity and loads it using a distinct
JNI registration name. Closing the request channel does not unload the library.

In [native_command.c](../native/native_command.c), `invoke0()` validates JNI
arguments and builds the response. It calls `execute()` in
[process_supervisor.c](../native/process_supervisor.c), which prepares the
program through `program_prepare()` in [elf_loader.c](../native/elf_loader.c).
The loader calls `file_read()`, `load_elf()` and `prepare_stack()`. These validate the executable/interpreter, map their ELF
segments and construct the initial stack. The loader enters the dynamic linker
in a supervised child without `execve` or `execveat`. Elasticsearch's existing
syscall filter remains active. `supervisor_start()` owns that child and reaps
descendants; `execute()` collects bounded stdout/stderr and waits for the
supervisor. The [native guide](../native/README.md) specifies supported formats,
deadlines, descriptor behavior and remaining limitations.

Local Python supervision has a separate job. `run_case()` protects every
successful node launch with cleanup, and `run_bounded_command()` does the same
for compiler/preflight helpers. They record cancellation until cleanup can
run safely. A PID alone is insufficient ownership: start time, process group
and stable pidfd handles prevent signaling an unrelated reused PID. Unknown
process state fails verification. An original request error and a cleanup
error are retained separately.

If GC stress is enabled, `exercise_request()` must finalize `GCInvocation`
whenever worker startup was attempted, including timestamp and HTTP failures.
The resulting GC evidence establishes request overlap only.

## Local comparison flow

In [validate_command.py](../validate_command.py), `prepare_comparison()`
authenticates the local releases and compiles one request class.
`run_comparison()` passes those same bytes to the disabled, fixed and affected
nodes in order. `check_case_result()` requires exact command output for the
positive and absence of command execution for both controls. Node ownership
and shutdown remain in `run_es7.run_case()`.

## Where to test changes

The tests mirror these boundaries: command/protocol tests, real owned-process
failure tests, GC parsing/lifecycle tests, and optional genuine-JVM request and
loader tests. [Native fixtures](../native/tests/README.md) exercise timeouts,
FIFO/replacement races and descendant cleanup in disposable helper processes.
Their modified test libraries are never part of the Elasticsearch proof.

Use the [test summary](../VALIDATION.md) to distinguish regression checks from
the recorded genuine application comparisons. Passing the Python suite alone
does not establish that a changed payload executes in Elasticsearch.
