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
    process = psutil.Process(pid)
    executable = str(Path(process.exe()).resolve())
    with open(executable, 'rb') as source:
        executable_digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'pid': pid, 'uid': process.uids().effective, 'birth': process.create_time(),
            'boot': _boot_identity(), 'executable': executable,
            'executable_digest': executable_digest}


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
