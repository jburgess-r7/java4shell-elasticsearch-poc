"""Own, cancel and reap local subprocesses on Linux.

Every launcher starts a new session. Descendants are identified by PID, start
time and process group, then held by pidfd where possible. An unreadable live
identity is an error, never evidence that cleanup succeeded. Signal handlers
record cancellation until a protected checkpoint can finish resource cleanup.

The public client uses run_bounded_command() for javac. The lab runners also
use the lower-level ownership primitives for Elasticsearch and jcmd.
"""
from contextlib import contextmanager
import ctypes
import errno
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import time

from . import common


class StopRequested(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum
        super().__init__("Interrupted by " + signal.Signals(signum).name)


class Cancellation:
    """Record signals without injecting exceptions into resource handoffs."""
    def __init__(self):
        self.first_signum = None
        self.count = 0

    def record(self, signum, _frame):
        if self.first_signum is None:
            self.first_signum = signum
        self.count += 1


_cancellation = None


@contextmanager
def managed_signals():
    """Defer SIGINT/SIGTERM exceptions until a protected cancellation checkpoint.

    Nested callers share the outer state. Handlers are restored on exit; every
    successful Popen must enter its cleanup scope before checking cancellation."""
    # Popen may have created a child before returning its handle. Defer SIGINT
    # and SIGTERM until a checkpoint after ownership has been recorded, so an
    # interruption cannot skip the finally block responsible for that child.
    global _cancellation
    if _cancellation is not None:
        yield _cancellation
        return
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Owned application sessions must start on the main thread")
    state = Cancellation()
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    _cancellation = state
    try:
        for sig in previous:
            signal.signal(sig, state.record)
        yield state
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        _cancellation = None


def cancellation_pending():
    return _cancellation.first_signum if _cancellation is not None else None


def cancellation_checkpoint():
    signum = cancellation_pending()
    if signum is not None:
        raise StopRequested(signum)


def interruption_details(error):
    signum = getattr(error, "signum", signal.SIGINT)
    return {"signal": int(signum), "name": signal.Signals(signum).name,
            "count": _cancellation.count if _cancellation is not None else 1}


def descendant_pids(root_pid):
    """Read only the process tree started by this runner."""
    pending, found = [root_pid], set()
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        found.add(pid)
        tasks = Path("/proc") / str(pid) / "task"
        try:
            task_dirs = list(tasks.iterdir())
        except (FileNotFoundError, ProcessLookupError) as error:
            try:
                os.getpgid(pid)
            except ProcessLookupError:
                continue
            raise RuntimeError("Process task tree is unavailable for live PID " + str(pid)) from error
        for task in task_dirs:
            if not task.name.isdecimal():
                continue
            children = task / "children"
            try:
                values = children.read_text().split()
            except (FileNotFoundError, ProcessLookupError) as error:
                try:
                    task.stat()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                raise RuntimeError("Process children record is unavailable: " + str(children)) from error
            if any(not value.isascii() or not value.isdecimal() or int(value) <= 0
                   for value in values):
                raise RuntimeError("Malformed process children record: " + str(children))
            pending.extend(int(value) for value in values)
    return found


def sandbox_status(proc):
    wanted = {"NoNewPrivs", "Seccomp", "Seccomp_filters"}
    return {key: value.strip() for line in (proc / "status").read_text().splitlines()
            if ":" in line for key, value in [line.split(":", 1)] if key in wanted}


def process_start_ticks(pid):
    """Return the Linux process start time, or None after confirmed disappearance.

    Permission errors and unreadable live records propagate. A numeric PID can
    be reused, so ownership checks must also compare this recorded start time."""
    # None means confirmed disappearance. Permission errors and unreadable live
    # records must propagate; treating them as exit would hide a leaked node.
    try:
        text = (Path("/proc") / str(pid) / "stat").read_text()
    except (FileNotFoundError, ProcessLookupError) as error:
        try:
            os.getpgid(pid)
        except ProcessLookupError:
            return None
        raise RuntimeError("Process stat is unavailable for live PID " + str(pid)) from error
    try:
        value = text.rsplit(")", 1)[1].split()[19]
    except IndexError as error:
        raise RuntimeError("Malformed process stat record for PID " + str(pid)) from error
    if not value.isascii() or not value.isdecimal():
        raise RuntimeError("Malformed process start time for PID " + str(pid))
    return value


def _libc_pidfd_call(name, argument_types, *arguments):
    """Use named Linux libc pidfd functions when Python omits the wrappers."""
    if sys.platform != "linux":
        raise OSError(errno.ENOSYS, "Linux pidfd functions are unavailable")
    try:
        function = getattr(ctypes.CDLL(None, use_errno=True), name)
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "libc does not provide " + name) from error
    function.argtypes = argument_types
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(*arguments)
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def pidfd_open(pid):
    native = getattr(os, "pidfd_open", None)
    if native is not None:
        return native(pid, 0)
    return _libc_pidfd_call("pidfd_open", (ctypes.c_int, ctypes.c_uint), pid, 0)


def pidfd_send_signal(descriptor, sig):
    native = getattr(signal, "pidfd_send_signal", None)
    if native is not None:
        return native(descriptor, sig, None, 0)
    return _libc_pidfd_call("pidfd_send_signal",
                           (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint),
                           descriptor, sig, None, 0)


def pidfd_waitid_type():
    native = getattr(os, "P_PIDFD", None)
    # Linux UAPI has assigned waitid's P_PIDFD idtype the stable value 3.
    return 3 if native is None else native


def pidfd_alive(descriptor, pid):
    """Check a stable process handle without consulting a reusable PID."""
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    events = poller.poll(0)
    if any(flags & (select.POLLERR | select.POLLNVAL) for _, flags in events):
        raise RuntimeError("Cannot inspect owned pidfd for PID " + str(pid))
    return not any(flags & (select.POLLIN | select.POLLHUP) for _, flags in events)


class OwnedProcesses(dict):
    """Attested process identities with PID-reuse-safe Linux handles."""

    def __init__(self):
        super().__init__()
        self._pidfds = {}
        self._closed = False
        self._lock = threading.RLock()

    def _state(self, pid, start_ticks, group, *, reap=False):
        """Return alive/exited for this captured identity, or None if untracked."""
        with self._lock:
            common.require(not self._closed, "Owned process handles are closed")
            entry = self._pidfds.get(pid)
            if entry is None or entry[:2] != (start_ticks, group):
                return None
            fd = entry[2]
            if reap:
                try:
                    os.waitid(pidfd_waitid_type(), fd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    # The process can still be a grandchild while its launcher
                    # lives. Its pidfd remains valid; the subreaper will reap it.
                    pass
            return pidfd_alive(fd, pid)

    def remember(self, pid, start_ticks, group):
        """Capture a pidfd only while PID, start time and group all match."""
        common.require(start_ticks is not None, "Cannot capture an unknown process identity")
        with self._lock:
            common.require(not self._closed, "Owned process handles are closed")
            previous = self._pidfds.get(pid)
            if previous is not None and previous[:2] == (start_ticks, group):
                if self._state(pid, start_ticks, group) is True:
                    super().__setitem__(pid, start_ticks)
                    return
            fd = pidfd_open(pid)
            retained = False
            try:
                current = process_start_ticks(pid)
                if current is None:
                    # A launcher can reap its child between pidfd_open and
                    # this check. Only a signalled pidfd establishes that
                    # the opened process has exited; absence alone does not.
                    common.require(not pidfd_alive(fd, pid),
                            "The process disappeared with a live capture handle")
                    return
                common.require(current == start_ticks,
                        "The process identity changed before capture")
                try:
                    current_group = os.getpgid(pid)
                except ProcessLookupError:
                    common.require(not pidfd_alive(fd, pid),
                            "The process disappeared with a live capture handle")
                    return
                common.require(current_group == group, "The process identity changed before capture")
                if previous is not None:
                    common.require(self._state(pid, previous[0], previous[1]) is False,
                            "A live captured PID has conflicting identity metadata")
                    os.close(previous[2])
                self._pidfds[pid] = (start_ticks, group, fd)
                super().__setitem__(pid, start_ticks)
                retained = True
            finally:
                if not retained:
                    os.close(fd)

    def signal(self, sig):
        """Signal only the exact processes captured by this collection."""
        sent = False
        with self._lock:
            common.require(not self._closed, "Owned process handles are closed")
            for _, _, fd in self._pidfds.values():
                try:
                    pidfd_send_signal(fd, sig)
                    sent = True
                except ProcessLookupError:
                    pass
        return sent

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            entries, self._pidfds = self._pidfds, {}
            for _, _, fd in entries.values():
                try:
                    os.close(fd)
                except OSError:
                    pass


def same_owned_process(pid, start_ticks, group):
    try:
        current = process_start_ticks(pid)
        if current is None:
            return False
        if start_ticks is None:
            raise RuntimeError("No recorded start time for live PID " + str(pid))
        return current == start_ticks and os.getpgid(pid) == group
    except ProcessLookupError:
        return False


def signal_owned_group(group, identities, sig):
    first_error = None
    for pid, ticks in identities.items():
        try:
            if same_owned_process(pid, ticks, group):
                break
        except (OSError, RuntimeError) as error:
            if first_error is None:
                first_error = error
    else:
        if first_error is not None:
            raise first_error
        return False
    try:
        os.killpg(group, sig)
        return True
    except ProcessLookupError:
        return False


def set_subreaper(enabled):
    """Set Linux orphan adoption and return its previous value for the caller to restore."""
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
        raise common.Unavailable("Cannot read Linux child-subreaper state")
    if libc.prctl(36, int(bool(enabled)), 0, 0, 0) != 0:
        raise common.Unavailable("Cannot establish Linux child-subreaper state")
    return previous.value


def refresh_owned(group, identities):
    # As a subreaper, this runner also retains children whose launcher exited.
    for pid in descendant_pids(os.getpid()):
        try:
            if os.getpgid(pid) != group:
                continue
            ticks = process_start_ticks(pid)
            if ticks is not None and os.getpgid(pid) == group:
                if isinstance(identities, OwnedProcesses):
                    identities.remember(pid, ticks, group)
                else:
                    identities[pid] = ticks
        except ProcessLookupError:
            pass
        except (OSError, RuntimeError):
            if (isinstance(identities, OwnedProcesses) and
                    identities._state(pid, identities.get(pid), group) is True):
                # This exact live process was attested before its proc record
                # became unreadable. Its pidfd still permits safe cleanup.
                continue
            raise


def remaining_owned(group, identities, launcher_pid):
    """Reap known descendants and return the identities still alive.

    The caller reaps the Popen launcher. Unverifiable live state raises instead
    of returning an empty set and falsely certifying cleanup."""
    if isinstance(identities, OwnedProcesses):
        # Reap exact captured children before enumerating their proc records.
        # A dead child can retain an unreadable stat file until it is reaped.
        for pid, ticks in list(identities.items()):
            if pid != launcher_pid:
                identities._state(pid, ticks, group, reap=True)
    refresh_owned(group, identities)
    remaining = {}
    for pid, ticks in list(identities.items()):
        if isinstance(identities, OwnedProcesses):
            state = identities._state(pid, ticks, group, reap=pid != launcher_pid)
            if state is not None:
                if state:
                    remaining[pid] = ticks
                continue
        current = process_start_ticks(pid)
        if current is None:
            continue
        if ticks is None:
            raise RuntimeError("No recorded start time for live PID " + str(pid))
        if current != ticks:
            continue
        if pid != launcher_pid:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        try:
            current = process_start_ticks(pid)
            if current is None or current != ticks:
                continue
            if os.getpgid(pid) != group:
                raise RuntimeError("Owned PID changed process group: " + str(pid))
            remaining[pid] = ticks
        except ProcessLookupError:
            continue
    return remaining


def signal_owned_or_child(process, identities, sig, cleanup_errors):
    """Signal an attested group, or only the direct child if discovery failed."""
    sent = False
    try:
        refresh_owned(process.pid, identities)
    except Exception as error:
        cleanup_errors.append("Process discovery: " + type(error).__name__ + ": " + str(error))
    try:
        sent = signal_owned_group(process.pid, identities, sig)
    except Exception as error:
        cleanup_errors.append("Process-group signal: " + type(error).__name__ + ": " + str(error))
    if isinstance(identities, OwnedProcesses):
        try:
            # A previously attested descendant may since have changed groups.
            # Its pidfd still identifies only that owned process.
            sent = identities.signal(sig) or sent
        except Exception as error:
            cleanup_errors.append("Owned-handle signal: " + type(error).__name__ + ": " + str(error))
    if sent:
        return
    # Popen tracks this direct child and checks whether it has already exited.
    # Never replace this fallback with killpg on an unverified numeric PID.
    try:
        process.send_signal(sig)
    except ProcessLookupError:
        pass
    except Exception as error:
        cleanup_errors.append("Child signal: " + type(error).__name__ + ": " + str(error))


def remaining_owned_or_unknown(process, identities, cleanup_errors):
    try:
        return remaining_owned(process.pid, identities, process.pid)
    except Exception as error:
        cleanup_errors.append("Remaining-process check: " + type(error).__name__ + ": " + str(error))
        return None


def wait_remaining_owned(process, identities, cleanup_errors, timeout):
    deadline = time.monotonic() + timeout
    remaining = remaining_owned_or_unknown(process, identities, cleanup_errors)
    while (remaining is None or remaining) and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = remaining_owned_or_unknown(process, identities, cleanup_errors)
    return remaining


def shutdown_case(process, identities, report, cleanup_errors):
    """Reap the launcher and its attested descendants, even after interruption."""
    def record_remaining(remaining):
        report["owned_processes_exited"] = (remaining is not None and not remaining
                                             and process.poll() is not None)
        report["remaining_owned_pids"] = sorted(remaining) if remaining is not None else None

    try:
        report["returncode_before_shutdown"] = process.poll()
        signal_owned_or_child(process, identities, signal.SIGTERM, cleanup_errors)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            report["forced_cleanup"] = True
            signal_owned_or_child(process, identities, signal.SIGKILL, cleanup_errors)
            process.wait(timeout=30)
        remaining = wait_remaining_owned(process, identities, cleanup_errors, 5)
        if remaining is None or remaining:
            report["forced_cleanup"] = True
            signal_owned_or_child(process, identities, signal.SIGKILL, cleanup_errors)
            remaining = wait_remaining_owned(process, identities, cleanup_errors, 10)
        record_remaining(remaining)
    except BaseException:
        # The launcher may already have exited while a descendant retains its
        # listening socket. Protect the whole shutdown, not just launcher.wait.
        report["forced_cleanup"] = True
        try:
            signal_owned_or_child(process, identities, signal.SIGKILL, cleanup_errors)
            process.wait(timeout=30)
        finally:
            record_remaining(wait_remaining_owned(process, identities, cleanup_errors, 10))
        raise
    finally:
        report["returncode"] = process.returncode
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors


def require_pidfd_support():
    """Probe open, signal and wait support before any application/helper launch."""
    if not (sys.platform == "linux" and hasattr(os, "waitid") and
            hasattr(select, "poll")):
        raise common.Unavailable("The application proof requires Linux pidfd process handles")
    try:
        descriptor = pidfd_open(os.getpid())
    except OSError as error:
        raise common.Unavailable("Linux pidfd process handles are unavailable: " + str(error)) from error
    else:
        try:
            try:
                pidfd_send_signal(descriptor, 0)
            except OSError as error:
                raise common.Unavailable("Linux pidfd signal support is unavailable: " + str(error)) from error
            try:
                os.waitid(pidfd_waitid_type(), descriptor, os.WEXITED | os.WNOHANG)
            except ChildProcessError:
                pass  # Our own pidfd is deliberately not a child to reap.
            except OSError as error:
                raise common.Unavailable("Linux pidfd wait support is unavailable: " + str(error)) from error
        finally:
            os.close(descriptor)


def run_bounded_command(command, out, timeout, report_path):
    """Run a short owned compiler/preflight command with cancellable waits."""
    # Compiler and preflight helpers can fork too. Give them the same pidfd and
    # descendant-cleanup guarantees as the longer-lived Elasticsearch node.
    with managed_signals():
        require_pidfd_support()
        previous = set_subreaper(True)
        process = None
        identities, cleanup_errors = OwnedProcesses(), []
        report = {"command": command, "status": "running", "forced_cleanup": False,
                  "owned_processes_exited": True, "remaining_owned_pids": []}
        primary = cleanup_error = None
        completed = None
        try:
            cancellation_checkpoint()
            process = subprocess.Popen(command, cwd=out, env=common.clean_environment(),
                                       text=True, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            report.update(launcher_pid=process.pid, owned_processes_exited=False,
                          remaining_owned_pids=None)
            identities.remember(process.pid, process_start_ticks(process.pid), process.pid)
            cancellation_checkpoint()
            deadline = time.monotonic() + timeout
            while True:
                cancellation_checkpoint()
                refresh_owned(process.pid, identities)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    stdout, stderr = process.communicate(timeout=min(0.25, remaining))
                    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    break
                except subprocess.TimeoutExpired:
                    continue
        except BaseException as error:
            primary = error
        finally:
            try:
                if process is not None:
                    try:
                        shutdown_case(process, identities, report, cleanup_errors)
                    except BaseException as error:
                        cleanup_error = error
                        report["cleanup_error"] = type(error).__name__ + ": " + str(error)
                    finally:
                        for pipe in (process.stdout, process.stderr):
                            if pipe is not None:
                                pipe.close()
            finally:
                identities.close()
                set_subreaper(previous)
        if primary is None and cleanup_error is not None:
            primary = cleanup_error
        if primary is None and (cleanup_errors or report["forced_cleanup"] or
                                not report["owned_processes_exited"]):
            primary = RuntimeError("The owned command did not finish through verified cleanup")
        if primary is None and cancellation_pending() is not None:
            primary = StopRequested(cancellation_pending())
        report["status"] = "failed" if primary is not None else "passed"
        if primary is not None:
            report["error"] = type(primary).__name__ + ": " + str(primary)
        try:
            common.write_json(report_path, report)
        except Exception as error:
            if primary is not None:
                raise primary from error
            raise
        if primary is not None:
            raise primary
        return completed
