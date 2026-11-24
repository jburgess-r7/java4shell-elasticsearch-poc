# Manual native cleanup regression

Run this from the repository root after building the native bridge. It
requires Linux x86-64, the same genuine JDK used for the build, and the C
compiler recorded in that build's manifest. It does not start Elasticsearch
or exercise the CVE.

```bash
python3 -B native/tests/test_cleanup.py \
  --build .validation-local/native-command \
  --jdk .validation-local/runtimes/temurin21 \
  --sde .validation-local/runtimes/sde-external-10.13.1-2026-07-28-lin/sde64 \
  --output .validation-local/native-cleanup-test
```

Omit `--sde` to run only the native cases. The output directory must be new.
The runner checks the build/source hashes and records compiler commands,
test-library hashes, command results and process-cleanup evidence.

The ordinary bridge is checked with `id`, a real timeout, and five harmless
paused children. Separate test builds set the child batch size to two,
select an absent child-enumeration path, or select an unsupported pidfd wait
type. These prove that enumeration spans multiple batches and that missing
prerequisites stop before command launch. A direct helper test supplies one
real child identity followed by a malformed token and verifies that cleanup
still signals/reaps the valid child while preserving the error status.

The same selected bridge rejects an owned FIFO without a writer, a symlink
to that FIFO, a directory, and an ELF fixture whose interpreter is that
FIFO. No supervisor or command may launch in these cases. A direct helper
replaces a previously selected regular file's pathname with a FIFO during
the descriptor reopen. Another fixture delays one real ELF read in an owned
standalone JVM, proving that preparation consumes the command deadline and
returns timeout metadata before any supervisor starts.

The variants and fixture programs remain below the ignored output directory.
They are test artifacts and are not used by the public command client. This
manual test is separate from the Python-only GitHub Actions suite.

The optional Python tests in
[test_es7_command_java.py](../../tests/test_es7_command_java.py) and
[test_es7_native_library.py](../../tests/test_es7_native_library.py) also
exercise the generated request and anonymous JNI loader using the genuine
local runtimes. They cover pathname replacement, partial writes, descriptor
closure, JNI cache reuse and failed loads. Set `JAVA4SHELL_TEST_PROFILE=17`
before running the normal unittest command to use Java 17; Java 21 is the
default. They skip when the required local JDK or native build is absent.

An actual noexec mount was unavailable in the recorded environment because
user-namespace setup returned `EPERM`. On a host that permits isolated
[user and mount namespaces](https://man7.org/linux/man-pages/man1/unshare.1.html),
the following creates an owned noexec tmpfs and attempts a standalone load.
The expected outcome is a library-loading error before any command starts;
Linux disallows executable file mappings on a
[noexec filesystem](https://man7.org/linux/man-pages/man2/mmap.2.html).

```bash
mkdir .validation-local/noexec-check
unshare --user --map-root-user --mount --fork bash -s -- \
  "$PWD/.validation-local/noexec-check" \
  "$PWD/.validation-local/native-command" \
  "$PWD/.validation-local/runtimes/temurin21" <<'SH'
set -eu
mount -t tmpfs -o noexec,size=16m tmpfs "$1"
trap 'umount "$1"' EXIT
cp "$2/libowned-native-command.so" "$1/library.so"
"$3/bin/java" -cp "$2/classes" \
  org.elasticsearch.painless.OwnedNativeCommand \
  "$1/library.so" --unfiltered 1 /usr/bin/true
SH
```
