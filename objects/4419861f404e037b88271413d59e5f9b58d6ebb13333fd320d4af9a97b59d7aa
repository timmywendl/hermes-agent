"""Kernel-bound local process identity for native plugin IPC (macOS qualified)."""
from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import sys
from pathlib import Path

import psutil


def _boot_identity():
    if sys.platform != 'darwin':
        raise PermissionError('native peer platform unqualified')
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    boot = ctypes.create_string_buffer(128)
    length = ctypes.c_size_t(len(boot))
    libc.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    if libc.sysctlbyname(b'kern.bootsessionuuid', boot, ctypes.byref(length), None, 0):
        raise PermissionError('native boot identity unavailable')
    return boot.value.decode('ascii')


def process_snapshot(pid):
    try:
        process = psutil.Process(pid)
        executable = str(Path(process.exe()).resolve())
        with open(executable, 'rb') as source:
            executable_digest = hashlib.file_digest(source, 'sha256').hexdigest()
        return {'pid': pid, 'uid': process.uids().effective, 'birth': process.create_time(),
                'boot': _boot_identity(), 'executable': executable,
                'executable_digest': executable_digest}
    except (psutil.Error, OSError):
        # Peer death during final release is a normal identity denial. Preserve
        # every successful identity pin; never let a missing peer kill Control.
        raise PermissionError('native peer identity unavailable') from None


def _process_instance_snapshot(pid):
    """Fresh kernel metadata only; never read executable content in a poll."""
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            if process.status() in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD):
                raise PermissionError('native owner exited')
            return {'pid': pid, 'uid': process.uids().effective,
                    'birth': process.create_time(), 'boot': _boot_identity(),
                    'executable': str(Path(process.exe()).resolve())}
    except (psutil.Error, OSError):
        raise PermissionError('native owner identity unavailable') from None


def _stat_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


def _executable_identity(path):
    return _stat_identity(os.stat(path))


class ProcessLivenessPin:
    """Full verification once, conservative metadata fencing on subsequent polls.

    Metadata changes require a fresh approved bootstrap, never implicit re-pinning.
    Same-interpreter re-exec with unchanged instance/file metadata is not detected.
    This private monitor does not establish a Supervisor trust root by itself.
    """

    def __init__(self, pid, approved):
        instance = _process_instance_snapshot(pid)
        try:
            with open(instance['executable'], 'rb') as source:
                before = _stat_identity(os.fstat(source.fileno()))
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
                after = _stat_identity(os.fstat(source.fileno()))
            # Bind metadata to the descriptor actually hashed, not a separately
            # sampled path that could name another file during verification.
            stable = (before == after == _executable_identity(instance['executable'])
                      and instance == _process_instance_snapshot(pid))
        except OSError:
            raise PermissionError('native owner artifact unavailable') from None
        if not stable or dict(instance, executable_digest=digest) != approved:
            raise PermissionError('native owner pin mismatch')
        self.__instance, self.__executable = instance, after

    def is_alive(self):
        try:
            actual = _process_instance_snapshot(self.__instance['pid'])
            return (actual == self.__instance
                    and _executable_identity(actual['executable']) == self.__executable)
        except (PermissionError, OSError):
            return False


def kernel_peer(connection):
    if sys.platform != 'darwin':
        raise PermissionError('native peer platform unqualified')
    # macOS SDK: SOL_LOCAL=0, LOCAL_PEERPID=2. Never take identity from JSON.
    pid = struct.unpack('i', connection.getsockopt(0, 2, 4))[0]
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                              ctypes.POINTER(ctypes.c_uint)]
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if libc.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        raise PermissionError('native peer credentials unavailable')
    actual = process_snapshot(pid)
    if actual['uid'] != uid.value or uid.value != os.geteuid():
        raise PermissionError('native peer UID mismatch')
    return actual


def verify_peer(connection, approved):
    actual = kernel_peer(connection)
    if actual != approved:
        raise PermissionError('native peer process mismatch')
    return actual
