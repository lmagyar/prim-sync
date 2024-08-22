
import argparse
import hashlib
import logging
import os
import pickle
import shutil
import socket
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from itertools import chain
from pathlib import Path, PurePath, PurePosixPath
from typing import Dict, cast

import paramiko
from platformdirs import user_cache_dir
from zeroconf import Zeroconf

########

LOCK_FILE_NAME = '.prim-sync.lock'
STATE_DIR_NAME = '.prim-sync'
NEW_FILE_SUFFIX = '.prim-sync.new' # new, tmp and old suffixes have to be the same length
TMP_FILE_SUFFIX = '.prim-sync.tmp' # new, tmp and old suffixes have to be the same length
OLD_FILE_SUFFIX = '.prim-sync.old' # new, tmp and old suffixes have to be the same length

########

class LevelFormatter(logging.Formatter):
    logging.Formatter.default_msec_format = logging.Formatter.default_msec_format.replace(',', '.') if logging.Formatter.default_msec_format else None

    def __init__(self, fmts: Dict[int, str], fmt: str, **kwargs):
        super().__init__()
        self.formatters = dict({level: logging.Formatter(fmt, **kwargs) for level, fmt in fmts.items()})
        self.default_formatter = logging.Formatter(fmt, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters.get(record.levelno, self.default_formatter).format(record)

class Logger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        self.exitcode = 0

    def prepare(self, timestamp: bool, silent: bool, silent_scanning: bool, silent_headers: bool):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            LevelFormatter(
                {
                    logging.WARNING: '%(asctime)s %(message)s',
                    logging.INFO: '%(asctime)s %(message)s',
                    logging.DEBUG: '%(asctime)s %(levelname)s %(message)s',
                },
                '%(asctime)s %(name)s: %(levelname)s: %(message)s')
            if timestamp else
            LevelFormatter(
                {
                    logging.WARNING: '%(message)s',
                    logging.INFO: '%(message)s',
                    logging.DEBUG: '%(levelname)s %(message)s',
                },
                '%(name)s: %(levelname)s: %(message)s')
        )
        self.addHandler(handler)
        if self.level == logging.NOTSET:
            self.setLevel(logging.WARNING if silent else logging.INFO)
        self.silent_scanning = silent_scanning
        self.silent_headers = silent_headers

    def info_scanning(self, msg, *args, **kwargs):
        if not self.silent_scanning:
            super().info(msg, *args, **kwargs)

    def info_header(self, msg, *args, **kwargs):
        if not self.silent_headers:
            super().info(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.exitcode = 1
        super().error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.exitcode = 1
        super().critical(msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        if level >= logging.ERROR:
            self.exitcode = 1
        super().log(level, msg, *args, **kwargs)

class LazyStr:
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.result = None
    def __str__(self):
        if self.result is None:
            self.result = str(self.func(*self.args, **self.kwargs))
        return self.result

logger = Logger(Path(sys.argv[0]).name)

########

@dataclass
class Options():
    use_mtime_for_comparison: bool = True
    use_content_for_comparison: bool = True
    use_hash_for_content_comparison: bool = True
    newer_wins: bool = False
    older_wins: bool = False
    change_wins_over_deletion: bool = False
    deletion_wins_over_change: bool = False
    local_wins_patterns: set[str] = field(default_factory=set)
    remote_wins_patterns: set[str] = field(default_factory=set)
    valid_chars: dict = field(default_factory=dict)
    dry: bool = False
    dry_on_conflict: bool = False
    overwrite_destination: bool = False
    ignore_locks: bool = False

    def __post_init__(self):
        if self.newer_wins and self.older_wins:
            raise ValueError("Can't be both --newer-wins and --older-wins conflict resolution enabled")
        if self.change_wins_over_deletion and self.deletion_wins_over_change:
            raise ValueError("Can't be both --deletion-wins-over-change and --change-wins-over-deletion conflict resolution enabled")
        if "[" in self.valid_chars.values() or "]" in self.valid_chars.values():
            raise ValueError("Can't use [ or ] characters in --valid-chars-pattern")

    def valid_filename(self, filename: str):
        return ''.join([c if c not in self.valid_chars else self.valid_chars[c] for c in filename])

options: Options

########

# based on https://github.com/Delgan/win32-setctime
try:
    from ctypes import WinDLL, WinError, byref, wintypes

    kernel32 = WinDLL("kernel32", use_last_error=True)

    CreateFileW = kernel32.CreateFileW
    SetFileTime = kernel32.SetFileTime
    CloseHandle = kernel32.CloseHandle

    CreateFileW.argtypes = (
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    CreateFileW.restype = wintypes.HANDLE

    SetFileTime.argtypes = (
        wintypes.HANDLE,
        wintypes.PFILETIME,
        wintypes.PFILETIME,
        wintypes.PFILETIME,
    )
    SetFileTime.restype = wintypes.BOOL

    CloseHandle.argtypes = (wintypes.HANDLE,)
    CloseHandle.restype = wintypes.BOOL

    FILE_WRITE_ATTRIBUTES = 0x100
    FILE_SHARE_NONE = 0x00
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

except (ImportError, AttributeError, OSError, ValueError):
    SETFILETIME_SUPPORTED = False
else:
    SETFILETIME_SUPPORTED = os.name == "nt"

def set_file_time(full_path, btime: float | None, atime: float | None, mtime: float | None, follow_symlinks = True):
    def _convert_timestamp(timestamp, name: str):
        time = int(timestamp * 10000000) + 116444736000000000 if timestamp else 0
        if not 0 <= time < (1 << 64):
            raise ValueError(f"The value of the {name} exceeds u64 size: {time}")
        return wintypes.FILETIME(time & 0xFFFFFFFF, time >> 32)

    if not SETFILETIME_SUPPORTED:
        raise OSError("This function is only available for the Windows platform.")

    full_path = os.path.normpath(os.path.abspath(str(full_path)))
    creation_time = _convert_timestamp(btime, "btime")
    last_access_time = _convert_timestamp(atime, "atime")
    last_write_time = _convert_timestamp(mtime, "mtime")

    flags = (FILE_ATTRIBUTE_NORMAL 
        | FILE_FLAG_BACKUP_SEMANTICS) # You must set this flag to obtain a handle to a directory.
    if not follow_symlinks:
        flags |= FILE_FLAG_OPEN_REPARSE_POINT

    handle = wintypes.HANDLE(CreateFileW(full_path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_NONE, None, OPEN_EXISTING, flags, None))
    if handle.value == wintypes.HANDLE(-1).value:
        raise WinError()
    if not wintypes.BOOL(SetFileTime(handle, byref(creation_time), byref(last_access_time), byref(last_write_time))):
        raise WinError()
    if not wintypes.BOOL(CloseHandle(handle)):
        raise WinError()
    
########

class FileInfo:
    def __init__(self, size: int, mtime: datetime):
        self.size = size
        self.mtime = mtime
    def __repr__(self):
        return f'({self.size}, {self.mtime})'
    def __eq__(self, other):
        if not isinstance(other, FileInfo):
            return NotImplemented
        return self.size == other.size and self.mtime == other.mtime
    def __ne__(self, other):
        if not isinstance(other, FileInfo):
            return NotImplemented
        return self.size != other.size or self.mtime != other.mtime

class LocalFileInfo(FileInfo):
    def __init__(self, size: int, mtime: datetime, btime: datetime, symlink_target: str | None):
        super().__init__(size, mtime)
        self.btime = btime
        self.symlink_target = symlink_target
    def __getstate__(self):
        state = self.__dict__.copy()
        # we don't need to remember these
        del state['btime']
        del state['symlink_target']
        return state
    def __setstate__(self, state):
        self.__dict__.update(state)
        self.btime = datetime.fromtimestamp(0, timezone.utc)
        self.symlink_target = None

class Local:
    def __init__(self, local_path: str):
        self.local_path = PurePath(local_path)
        self.has_invalid_filename = False
        self.has_unsupported_hardlink = False

    def scandir(self):
        def _scandir(path: PurePosixPath):
            while True: # recovery
                entries = dict({e.name : e for e in os.scandir(self.local_path / path)})
                oldtmpnew_entries = list([e for e in entries.keys() if e.endswith(OLD_FILE_SUFFIX) or e.endswith(TMP_FILE_SUFFIX) or e.endswith(NEW_FILE_SUFFIX)])
                if not oldtmpnew_entries:
                    break
                oldtmpnew_entry = oldtmpnew_entries[0] # do it one-by-one (there shouldn't be more) and reread the real timestamps from the os
                entry_name = oldtmpnew_entry[:-len(OLD_FILE_SUFFIX)]
                logger.info("<<< RECOVER %s", str(path / entry_name))
                old_entry_name = entry_name + OLD_FILE_SUFFIX
                tmp_entry_name = entry_name + TMP_FILE_SUFFIX
                new_entry_name = entry_name + NEW_FILE_SUFFIX
                entry_exists = entry_name in entries
                old_entry_exists = old_entry_name in entries
                tmp_entry_exists = tmp_entry_name in entries
                new_entry_exists = new_entry_name in entries
                if tmp_entry_exists:
                    os.rename(self.local_path / path / tmp_entry_name, self.local_path / path / entry_name)
                if not old_entry_exists and new_entry_exists:
                    os.remove(self.local_path / path / new_entry_name)
                elif old_entry_exists:
                    if entry_exists == new_entry_exists:
                        raise RuntimeError(f"All 3 (old, new and normal) or only the old version of file {self.local_path / path / entry_name} exists, invalid situation")
                    if new_entry_exists:
                        os.rename(self.local_path / path / new_entry_name, self.local_path / path / entry_name)
                    os.remove(self.local_path / path / old_entry_name)
            for entry in entries.values():
                relative_path = path / entry.name
                relative_name = str(relative_path)
                if relative_name == STATE_DIR_NAME or relative_name == LOCK_FILE_NAME:
                    continue
                if entry.is_dir(follow_symlinks=True):
                    yield relative_name + '/', None
                    yield from _scandir(relative_path)
                else:
                    if any(c in '[]' for c in entry.name):
                        if options.valid_chars:
                            valid_relative_name = str(path / options.valid_filename(entry.name))
                            logger.info("<<< INVALID %s", relative_name)
                            logger.info("              renaming to: %s", valid_relative_name)
                            os.rename(self.local_path / relative_name, self.local_path / valid_relative_name)
                            relative_name = valid_relative_name
                        else:
                            logger.warning("<<< INVALID %s", relative_name)
                            self.has_invalid_filename = True
                    if not options.overwrite_destination:
                        stat = entry.stat(follow_symlinks=False)
                        if stat.st_nlink > 1:
                            logger.warning("<<< HARDLNK %s", relative_name)
                            self.has_unsupported_hardlink = True
                    stat = entry.stat(follow_symlinks=True)
                    yield relative_name, LocalFileInfo(size=stat.st_size, mtime=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                        btime=datetime.fromtimestamp(stat.st_birthtime if SETFILETIME_SUPPORTED else 0, timezone.utc),
                        symlink_target=str(Path(self.local_path / relative_path).resolve(strict=True)) if entry.is_symlink() else None)
        yield from _scandir(PurePosixPath(''))

    def remove(self, relative_path: str, fileinfo: FileInfo | None):
        def _rmdir(full_path: str):
            try:
                os.rmdir(full_path)
                return True
            except FileNotFoundError:
                return True # already deleted
            except IOError:
                return False # new file inside
        def _rename(from_full_path: str, to_full_path: str):
            try:
                os.rename(from_full_path, to_full_path)
                return True
            except FileNotFoundError:
                return True # already deleted
            except IOError:
                return False # locked by other process, or whatever
        def _remove(full_path: str):
            try:
                os.remove(full_path)
                return True
            except FileNotFoundError:
                return True # already deleted
            except IOError:
                return False # locked by other process, or whatever
        full_path = str(self.local_path / relative_path)
        success = False
        # on any error any intermediate/leftover files will be cleaned up by the recovery during scan
        if relative_path.endswith('/'):
            success = _rmdir(full_path)
        else:
            if not options.overwrite_destination:
                tmp_full_path = full_path + TMP_FILE_SUFFIX
                if _rename(full_path, tmp_full_path):
                    stat = os.stat(tmp_full_path, follow_symlinks=True)
                    fileinfo = cast(FileInfo, fileinfo)
                    if fileinfo.size == stat.st_size and fileinfo.mtime == datetime.fromtimestamp(stat.st_mtime, timezone.utc):
                        os.remove(tmp_full_path)
                        success = True
                    else:
                        os.rename(tmp_full_path, full_path)
            else:
                success = _remove(full_path)
        return success

    def open(self, relative_path: str):
        return open(self.local_path / relative_path, 'rb')

    def stat(self, relative_path: str):
        return os.stat(self.local_path / relative_path, follow_symlinks=True)

    def download(self, relative_path: str, remote_open_fn, remote_stat_fn, local_fileinfo: LocalFileInfo | None, remote_fileinfo: FileInfo):
        def _copy(to_full_path: str):
            try:
                with remote_open_fn(relative_path) as remote_file:
                    with open(to_full_path, "wb") as local_file:
                        shutil.copyfileobj(remote_file, local_file)
                return True
            except IOError:
                return False # any error on any side
        def _utime(full_path: str):
            os.utime(full_path, (remote_fileinfo.mtime.timestamp(), remote_fileinfo.mtime.timestamp()), follow_symlinks=True)
        def _set_file_time(full_path: str):
            set_file_time(full_path, cast(LocalFileInfo, local_fileinfo).btime.timestamp(), remote_fileinfo.mtime.timestamp(), remote_fileinfo.mtime.timestamp(), follow_symlinks=True)
        def _fileinfo(full_path: str):
            stat = os.stat(full_path, follow_symlinks=True)
            return LocalFileInfo(size=stat.st_size, mtime=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                btime=datetime.fromtimestamp(stat.st_birthtime if SETFILETIME_SUPPORTED else 0, timezone.utc),
                symlink_target=local_fileinfo.symlink_target if local_fileinfo else None)
        def _rename(from_full_path: str, to_full_path: str):
            try:
                os.rename(from_full_path, to_full_path)
                return True
            except IOError:
                return False # deleted, locked by other process, or whatever
        def _commitexisting(full_path: str, tmp_full_path: str, old_full_path: str):
            if _rename(full_path, tmp_full_path):
                local_stat = os.stat(tmp_full_path, follow_symlinks=True)
                remote_stat = remote_stat_fn(relative_path)
                local_fileinfo_ = cast(FileInfo, local_fileinfo)
                if (local_fileinfo_.size == local_stat.st_size and local_fileinfo_.mtime == datetime.fromtimestamp(local_stat.st_mtime, timezone.utc)
                        and remote_fileinfo.size == remote_stat.st_size and remote_fileinfo.mtime == datetime.fromtimestamp(remote_stat.st_mtime, timezone.utc)):
                    os.rename(tmp_full_path, old_full_path)
                    return True
                else:
                    os.rename(tmp_full_path, full_path)
            return False
        def _commitnew(new_full_path: str, full_path: str):
            remote_stat = remote_stat_fn(relative_path)
            if remote_fileinfo.size == remote_stat.st_size and remote_fileinfo.mtime == datetime.fromtimestamp(remote_stat.st_mtime, timezone.utc):
                return _rename(new_full_path, full_path)
            return False
        full_path = str(self.local_path / relative_path)
        # on any error any intermediate/leftover files will be cleaned up by the recovery during scan
        if not options.overwrite_destination:
            if local_fileinfo and local_fileinfo.symlink_target:
                full_path = local_fileinfo.symlink_target
            old_full_path = full_path + OLD_FILE_SUFFIX
            tmp_full_path = full_path + TMP_FILE_SUFFIX
            new_full_path = full_path + NEW_FILE_SUFFIX
            if _copy(new_full_path):
                if local_fileinfo and SETFILETIME_SUPPORTED:
                    _set_file_time(new_full_path)
                else:
                    _utime(new_full_path)
                new_fileinfo = _fileinfo(new_full_path)
                if local_fileinfo:
                    if _commitexisting(full_path, tmp_full_path, old_full_path):
                        os.rename(new_full_path, full_path)
                        os.remove(old_full_path)
                        return new_fileinfo
                else:
                    if _commitnew(new_full_path, full_path):
                        return new_fileinfo
        else:
            if _copy(full_path):
                _utime(full_path)
                return _fileinfo(full_path)
        return None

    def mkdir(self, relative_path: str):
        full_path = str(self.local_path / relative_path)
        try:
            os.mkdir(full_path)
        except FileExistsError:
            pass

    def __enter__(self):
        try:
            self.lockfile = open(str(self.local_path / LOCK_FILE_NAME), "x" if not options.ignore_locks else "w")
        except IOError as e:
            raise IOError(f"Can't acquire lock on local folder ({e}), if this is after an interrupted sync operation, delete the lock file manually or use the --ignore-locks option")
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.lockfile:
            self.lockfile.close()
            os.remove(str(self.local_path / LOCK_FILE_NAME))

class Remote:
    def __init__(self, local_folder: str, sftp: paramiko.SFTPClient, remote_read_path: str, remote_write_path: str):
        self.local_folder = PurePosixPath(local_folder)
        self.sftp = sftp
        self.remote_read_path = PurePosixPath(remote_read_path)
        self.remote_write_path = PurePosixPath(remote_write_path)

    has_invalid_filename = False

    def scandir(self):
        def _scandir(path: PurePosixPath):
            logger.info_scanning("Scanning    %s", str(self.local_folder / path))
            while True: # recovery
                entries = dict({e.filename : e for e in self.sftp.listdir_attr(str(self.remote_read_path / path))})
                oldtmpnew_entries = list([e for e in entries.keys() if e.endswith(OLD_FILE_SUFFIX) or e.endswith(TMP_FILE_SUFFIX) or e.endswith(NEW_FILE_SUFFIX)])
                if not oldtmpnew_entries:
                    break
                oldtmpnew_entry = oldtmpnew_entries[0] # do it one-by-one (there shouldn't be more) and reread the real timestamps from the os
                entry_name = oldtmpnew_entry[:-len(OLD_FILE_SUFFIX)]
                logger.info("RECOVER >>> %s", str(path / entry_name))
                old_entry_name = entry_name + OLD_FILE_SUFFIX
                tmp_entry_name = entry_name + TMP_FILE_SUFFIX
                new_entry_name = entry_name + NEW_FILE_SUFFIX
                entry_exists = entry_name in entries
                old_entry_exists = old_entry_name in entries
                tmp_entry_exists = tmp_entry_name in entries
                new_entry_exists = new_entry_name in entries
                if tmp_entry_exists:
                    self.sftp.rename(str(self.remote_write_path / path / tmp_entry_name), str(self.remote_write_path / path / entry_name))
                if not old_entry_exists and new_entry_exists:
                    self.sftp.remove(str(self.remote_write_path / path / new_entry_name))
                elif old_entry_exists:
                    if entry_exists == new_entry_exists:
                        raise RuntimeError(f"All 3 (old, new and normal) or only the old version of file {str(self.remote_read_path / path / entry_name)} exists, invalid situation")
                    if new_entry_exists:
                        self.sftp.rename(str(self.remote_write_path / path / new_entry_name), str(self.remote_write_path / path / entry_name))
                    self.sftp.remove(str(self.remote_write_path / path / old_entry_name))
            for entry in entries.values():
                relative_path = path / entry.filename
                relative_name = str(relative_path)
                if relative_name == LOCK_FILE_NAME:
                    continue
                if stat.S_ISDIR(entry.st_mode or 0):
                    yield relative_name + '/', None
                    yield from _scandir(relative_path)
                else:
                    if any(c in '[]' for c in entry.filename):
                        if options.valid_chars:
                            valid_relative_name = str(path / options.valid_filename(entry.filename))
                            logger.info("INVALID >>> %s", relative_name)
                            logger.info("              renaming to: %s", valid_relative_name)
                            # you can rename these files, only writing them on SAF cause error
                            self.sftp.rename(str(self.remote_write_path / relative_name), str(self.remote_write_path / valid_relative_name))
                            relative_name = valid_relative_name
                        else:
                            logger.warning("INVALID >>> %s", relative_name)
                            self.has_invalid_filename = True
                    yield relative_name, FileInfo(size=entry.st_size or 0, mtime=datetime.fromtimestamp(entry.st_mtime or 0, timezone.utc))
        yield from _scandir(PurePosixPath(''))

    def remove(self, relative_path: str, fileinfo: FileInfo | None):
        def _rmdir(full_path: str):
            try:
                self.sftp.rmdir(full_path)
                return True
            except FileNotFoundError:
                return True
            except IOError:
                return False
        def _rename(from_full_path: str, to_full_path: str):
            try:
                self.sftp.rename(from_full_path, to_full_path)
                return True
            except FileNotFoundError:
                return True
            except IOError:
                return False
        def _remove(full_path: str):
            try:
                self.sftp.remove(full_path)
                return True
            except FileNotFoundError:
                return True
            except IOError:
                return False
        full_path = str(self.remote_write_path / relative_path)
        success = False
        # on any error any intermediate/leftover files will be cleaned up by the recovery during scan
        if relative_path.endswith('/'):
            success = _rmdir(full_path)
        else:
            if not options.overwrite_destination:
                tmp_full_path = full_path + TMP_FILE_SUFFIX
                if _rename(full_path, tmp_full_path):
                    stat = self.sftp.stat(tmp_full_path)
                    fileinfo = cast(FileInfo, fileinfo)
                    if fileinfo.size == stat.st_size and fileinfo.mtime == datetime.fromtimestamp(stat.st_mtime or 0, timezone.utc):
                        self.sftp.remove(tmp_full_path)
                        success = True
                    else:
                        self.sftp.rename(tmp_full_path, full_path)
            else:
                success = _remove(full_path)
        return success

    def open(self, relative_path: str):
        return self.sftp.open(str(self.remote_read_path / relative_path), 'r')

    def stat(self, relative_path: str):
        return self.sftp.stat(str(self.remote_read_path / relative_path))

    def upload(self, local_open_fn, local_stat_fn, relative_path: str, local_fileinfo: FileInfo, remote_fileinfo: FileInfo | None):
        def _copy(to_full_path: str):
            try:
                with local_open_fn(relative_path) as local_file:
                    with self.sftp.open(to_full_path, "w") as remote_file:
                        shutil.copyfileobj(local_file, remote_file)
                return True
            except IOError:
                return False # any error on any side
        def _utime(full_path: str):
            self.sftp.utime(full_path, (local_fileinfo.mtime.timestamp(), local_fileinfo.mtime.timestamp()))
        def _fileinfo(full_path: str):
            stat = self.sftp.stat(full_path)
            return FileInfo(size=stat.st_size or 0, mtime=datetime.fromtimestamp(stat.st_mtime or 0, timezone.utc))
        def _rename(from_full_path: str, to_full_path: str):
            try:
                self.sftp.rename(from_full_path, to_full_path)
                return True
            except IOError:
                return False # deleted, locked by other process, or whatever
        def _commitexisting(full_path: str, tmp_full_path: str, old_full_path: str):
            if _rename(full_path, tmp_full_path):
                local_stat = local_stat_fn(relative_path)
                remote_stat = self.sftp.stat(tmp_full_path)
                remote_fileinfo_ = cast(FileInfo, remote_fileinfo)
                if (local_fileinfo.size == local_stat.st_size and local_fileinfo.mtime == datetime.fromtimestamp(local_stat.st_mtime, timezone.utc)
                        and remote_fileinfo_.size == remote_stat.st_size and remote_fileinfo_.mtime == datetime.fromtimestamp(remote_stat.st_mtime or 0, timezone.utc)):
                    self.sftp.rename(tmp_full_path, old_full_path)
                    return True
                else:
                    self.sftp.rename(tmp_full_path, full_path)
            return False
        def _commitnew(new_full_path: str, full_path: str):
            local_stat = local_stat_fn(relative_path)
            if local_fileinfo.size == local_stat.st_size and local_fileinfo.mtime == datetime.fromtimestamp(local_stat.st_mtime, timezone.utc):
                return _rename(new_full_path, full_path)
            return False
        full_path = str(self.remote_write_path / relative_path)
        # on any error any intermediate/leftover files will be cleaned up by the recovery during scan
        if not options.overwrite_destination:
            old_full_path = full_path + OLD_FILE_SUFFIX
            tmp_full_path = full_path + TMP_FILE_SUFFIX
            new_full_path = full_path + NEW_FILE_SUFFIX
            if _copy(new_full_path):
                _utime(new_full_path)
                new_fileinfo = _fileinfo(new_full_path)
                if remote_fileinfo:
                    if _commitexisting(full_path, tmp_full_path, old_full_path):
                        self.sftp.rename(new_full_path, full_path)
                        self.sftp.remove(old_full_path)
                        return new_fileinfo
                else:
                    if _commitnew(new_full_path, full_path):
                        return new_fileinfo
        else:
            if _copy(full_path):
                _utime(full_path)
                return _fileinfo(full_path)
        return None

    def mkdir(self, relative_path: str):
        full_path = str(self.remote_write_path / relative_path)
        try:
            self.sftp.mkdir(full_path)
        except IOError as e: # FileExistsError
            if e.errno == None and e.strerror == None and len(e.args) == 1 and e.args[0] == full_path:
                pass
            else:
                raise

    def __enter__(self):
        try:
            self.lockfile = self.sftp.open(str(self.remote_write_path / LOCK_FILE_NAME), "x" if not options.ignore_locks else "w")
        except IOError as e:
            raise IOError(f"Can't acquire lock on remote folder ({e}), if this is after an interrupted sync operation, delete the lock file manually or use the --ignore-locks option")
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.lockfile:
            self.lockfile.close()
            self.sftp.remove(str(self.remote_write_path / LOCK_FILE_NAME))

class Storage:
    def __init__(self, local_path: str, server_name: str):
        self.state_path = Path(local_path) / STATE_DIR_NAME
        self.state_filename = str(self.state_path / server_name)

    def save_psync_info(self, local_data: dict, remote_data: dict):
        self.state_path.mkdir(parents=True, exist_ok=True)
        old_state_file_name = self.state_filename + OLD_FILE_SUFFIX
        new_state_file_name = self.state_filename + NEW_FILE_SUFFIX
        with open(new_state_file_name, "wb") as out_file:
            pickle.dump((local_data, remote_data), out_file)
        if previous_exists := os.path.exists(self.state_filename):
            os.rename(self.state_filename, old_state_file_name)
        os.rename(new_state_file_name, self.state_filename)
        if previous_exists:
            os.remove(old_state_file_name)

    def load_psync_info(self):
        self.state_path.mkdir(parents=True, exist_ok=True)
        # recovery
        old_state_file_name = self.state_filename + OLD_FILE_SUFFIX
        new_state_file_name = self.state_filename + NEW_FILE_SUFFIX
        old_state_file_exists = os.path.exists(old_state_file_name)
        state_file_exists = os.path.exists(self.state_filename)
        new_state_file_exists = os.path.exists(new_state_file_name)
        if not old_state_file_exists and new_state_file_exists:
            os.remove(new_state_file_name)
        elif old_state_file_exists:
            if state_file_exists == new_state_file_exists:
                raise RuntimeError("All 3 (old, new and normal) or only the old state file exists, invalid situation")
            if new_state_file_exists:
                os.rename(new_state_file_name, self.state_filename)
            os.remove(old_state_file_name)

        if os.path.exists(self.state_filename) and os.path.isfile(self.state_filename):
            with open(self.state_filename, "rb") as in_file:
                return pickle.load(in_file)
        else:
            return (dict(), dict())

class Sync:
    def __init__(self, local: Local, remote: Remote, storage: Storage):
        self.local = local
        self.remote = remote
        self.storage = storage

    def _is_identical(self, relative_path: str):
        def _compare_or_hash_files():
            def _compare_files():
                logger.info("Comparing   %s", relative_path)
                local_file = self.local.open(relative_path)
                remote_file = self.remote.open(relative_path)
                identical = True
                while True:
                    local_buffer = local_file.read(1024 * 1024)
                    remote_buffer = remote_file.read(1024 * 1024)
                    if local_buffer != remote_buffer:
                        identical = False
                        break
                    if not local_buffer:
                        break
                return identical
            def _hash_files():
                def _hash_local_file():
                    local_file = self.local.open(relative_path)
                    digest = hashlib.sha256()
                    while buffer := local_file.read(65536):
                        digest.update(buffer)
                    return digest.digest()
                def _hash_remote_file():
                    remote_file = self.remote.open(relative_path)
                    return remote_file.check('sha256', 0, 0, 0)
                logger.info("Hashing     %s", relative_path)
                # TODO Do it parallel
                return _hash_local_file() == _hash_remote_file()
            if (_hash_files() if options.use_hash_for_content_comparison else _compare_files()):
                self.identical.add(relative_path)
                return True
            return False
        if relative_path.endswith('/'):
            return True
        local_fileinfo = cast(FileInfo, self.local_current[relative_path])
        remote_fileinfo = cast(FileInfo, self.remote_current[relative_path])
        return (local_fileinfo.size == remote_fileinfo.size
            and ((options.use_mtime_for_comparison and local_fileinfo.mtime == remote_fileinfo.mtime)
                or (options.use_content_for_comparison and _compare_or_hash_files())
                or (not options.use_mtime_for_comparison and not options.use_content_for_comparison)))

    def _resolve(self, relative_path: str):
        if ((options.newer_wins or options.older_wins) and not relative_path.endswith('/')
                and (local_mtime := cast(FileInfo, self.local_current[relative_path]).mtime) != (remote_mtime := cast(FileInfo, self.remote_current[relative_path]).mtime)):
            if local_mtime > remote_mtime and options.newer_wins or local_mtime < remote_mtime and options.older_wins:
                self.upload.add(relative_path)
            else:
                self.download.add(relative_path)
        else:
            prefer_local = any(fnmatch(relative_path, p) for p in options.local_wins_patterns)
            prefer_remote = any(fnmatch(relative_path, p) for p in options.remote_wins_patterns)
            if prefer_local and not prefer_remote:
                self.upload.add(relative_path)
            elif not prefer_local and prefer_remote:
                self.download.add(relative_path)
            else:
                return False
        return True

    def _resolve_local_deleted(self, relative_path: str):
        if options.change_wins_over_deletion:
            self.download.add(relative_path)
        elif options.deletion_wins_over_change:
            self.delete_remote.add(relative_path)
        else:
            return False
        return True

    def _resolve_remote_deleted(self, relative_path: str):
        if options.change_wins_over_deletion:
            self.upload.add(relative_path)
        elif options.deletion_wins_over_change:
            self.delete_local.add(relative_path)
        else:
            return False
        return True

    def collect(self):
        def _new_entries(current: dict, previous: dict):
            return {k for k in current.keys() if k not in previous}
        def _deleted_entries(current: dict, previous: dict):
            return {k for k in previous.keys() if k not in current}
        def _changed_entries(current: dict, previous: dict):
            return {k for k in current.keys() if k in previous and current[k] != previous[k]}
        def _unchanged_entries(current: dict, previous: dict):
            return {k for k in current.keys() if k in previous and current[k] == previous[k]}

        logger.info_header("----------- Scanning")

        self.local_previous, self.remote_previous = self.storage.load_psync_info()
        self.local_current = dict(sorted(self.local.scandir()))
        self.remote_current = dict(sorted(self.remote.scandir()))

        if self.local.has_invalid_filename or self.remote.has_invalid_filename:
            raise ValueError("There are invalid filenames, can't sync, see --valid-chars or --valid-chars-pattern options")
        if self.local.has_unsupported_hardlink:
            raise RuntimeError("Hardlinks can't be used without enabling --overwrite-destination option")

        self.local_new = _new_entries(self.local_current, self.local_previous)
        self.local_deleted = _deleted_entries(self.local_current, self.local_previous)
        self.local_changed = _changed_entries(self.local_current, self.local_previous)
        self.local_unchanged = _unchanged_entries(self.local_current, self.local_previous)

        self.remote_new = _new_entries(self.remote_current, self.remote_previous)
        self.remote_deleted = _deleted_entries(self.remote_current, self.remote_previous)
        self.remote_changed = _changed_entries(self.remote_current, self.remote_previous)
        self.remote_unchanged = _unchanged_entries(self.remote_current, self.remote_previous)

        self.delete_local = set()
        self.delete_remote = set()
        self.download = set()
        self.upload = set()
        self.identical = set()
        self.conflict = dict()

    def compare(self):
        logger.info_header("----------- Analyzing changes")

    def execute(self):
        def _filesize_fmt(num, suffix="B"):
            for unit in ("", "k", "M", "G"):
                if abs(num) < 1024.0:
                    if not unit:
                        return f"{num:.0f} {suffix}"
                    else:
                        return f"{num:.1f} {unit}{suffix}"
                num /= 1024.0
            return f"{num:.1f} T{suffix}"
        def _forget_changes(current: dict, previous: dict, relative_path: str):
            previous_entry = previous.get(relative_path, None)
            if previous_entry:
                current[relative_path] = previous_entry
            else:
                current.pop(relative_path, None)

        logger.info_header("----------- Executing")

        global options
        if options.dry_on_conflict and self.conflict:
            options.dry = True

        if options.dry:
            logger.info("!!!!!!!!!!! Running dry! No deletion, creation, upload or download will be executed!")

        for relative_path in chain(sorted({p for p in self.delete_local if not p.endswith('/')}, key=lambda p: (p.count('/'), p)),  # first delete files
                sorted({p for p in self.delete_local if p.endswith('/')}, key=lambda p: (-p.count('/'), p))):                      # then folders, starting deep
            logger.info("<<< DEL     %s", relative_path)
            if not options.dry:
                if self.local.remove(relative_path, self.local_current[relative_path]):
                    del self.local_current[relative_path]
                else:
                    logger.info("< CHANGED     will be processed only on the next run")

        for relative_path in chain(sorted({p for p in self.delete_remote if not p.endswith('/')}, key=lambda p: (p.count('/'), p)), # first delete files
                sorted({p for p in self.delete_remote if p.endswith('/')}, key=lambda p: (-p.count('/'), p))):                     # then folders, starting deep
            logger.info("    DEL >>> %s", relative_path)
            if not options.dry:
                if self.remote.remove(relative_path, self.remote_current[relative_path]):
                    del self.remote_current[relative_path]
                else:
                    logger.info("  CHANGED >   will be processed only on the next run")

        for relative_path in chain(sorted({p for p in self.download if p.endswith('/')}, key=lambda p: (p.count('/'), p)),          # first create folders
                sorted({p for p in self.download if not p.endswith('/')}, key=lambda p: (p.count('/'), p))):                       # then download files
            if relative_path.endswith('/'):
                logger.info("<<<<<<<     %s", relative_path)
                if not options.dry:
                    self.local.mkdir(relative_path)
                    self.local_current[relative_path] = None
            else:
                remote_fileinfo = cast(FileInfo, self.remote_current[relative_path])
                logger.info("<<<<<<<     %s, size: %s, time: %s", relative_path, _filesize_fmt(remote_fileinfo.size), remote_fileinfo.mtime)
                if not options.dry:
                    if new_local_fileinfo := self.local.download(relative_path, self.remote.open, self.remote.stat, self.local_current.get(relative_path), remote_fileinfo):
                        self.local_current[relative_path] = new_local_fileinfo
                    else:
                        logger.info("< CHANGED >   will be processed only on the next run")

        for relative_path in chain(sorted({p for p in self.upload if p.endswith('/')}, key=lambda p: (p.count('/'), p)),            # first create folders
                sorted({p for p in self.upload if not p.endswith('/')}, key=lambda p: (p.count('/'), p))):                         # then upload files
            if relative_path.endswith('/'):
                logger.info("    >>>>>>> %s", relative_path)
                if not options.dry:
                    self.remote.mkdir(relative_path)
                    self.remote_current[relative_path] = None
            else:
                local_fileinfo = cast(FileInfo, self.local_current[relative_path])
                logger.info("    >>>>>>> %s, size: %s, time: %s", relative_path, _filesize_fmt(local_fileinfo.size), local_fileinfo.mtime)
                if not options.dry:
                    if new_remote_fileinfo := self.remote.upload(self.local.open, self.local.stat, relative_path, local_fileinfo, self.remote_current.get(relative_path)):
                        self.remote_current[relative_path] = new_remote_fileinfo
                    else:
                        logger.info("< CHANGED >   will be processed only on the next run")

        for relative_path, reason in sorted(self.conflict.items(), key=lambda p: (p.count('/'), p)):
            def extend_reason():
                extended_reason = f"              {reason}"
                local_fileinfo = self.local_current.get(relative_path)
                remote_fileinfo = self.remote_current.get(relative_path)
                if local_fileinfo and remote_fileinfo:
                    extended_reason += (f", size: {_filesize_fmt(local_fileinfo.size)} ({format(local_fileinfo.size, ',d').replace(',',' ')}) "
                        f"{'>' if local_fileinfo.size > remote_fileinfo.size else '<' if local_fileinfo.size < remote_fileinfo.size else '='} "
                        f"{_filesize_fmt(remote_fileinfo.size)} ({format(remote_fileinfo.size, ',d').replace(',',' ')})"
                        f", time: {local_fileinfo.mtime} {'>' if local_fileinfo.mtime > remote_fileinfo.mtime else '<' if local_fileinfo.mtime < remote_fileinfo.mtime else '='} {remote_fileinfo.mtime}")
                else:
                    if local_fileinfo:
                        fileinfo = local_fileinfo
                        previous_fileinfo = self.local_previous.get(relative_path)
                    else:
                        fileinfo = remote_fileinfo
                        previous_fileinfo = self.remote_previous.get(relative_path)
                    if fileinfo and previous_fileinfo:
                        extended_reason += (f", size: {_filesize_fmt(previous_fileinfo.size)} ({format(previous_fileinfo.size, ',d').replace(',',' ')}) -> {_filesize_fmt(fileinfo.size)} ({format(fileinfo.size, ',d').replace(',',' ')})"
                            f", time: {previous_fileinfo.mtime} -> {fileinfo.mtime}")
                    elif fileinfo:
                        extended_reason += f", size: {_filesize_fmt(fileinfo.size)} ({format(fileinfo.size, ',d').replace(',',' ')}), time: {fileinfo.mtime}"
                return extended_reason
            logger.warning("<<< !!! >>> %s", relative_path)
            logger.warning(LazyStr(extend_reason))
            _forget_changes(self.local_current, self.local_previous, relative_path)
            _forget_changes(self.remote_current, self.remote_previous, relative_path)

        if not self.delete_local and not self.delete_remote and not self.download and not self.upload and not self.conflict:
            logger.info_header("----------- Everything is up to date!")

        if not options.dry:
            self.storage.save_psync_info(self.local_current, self.remote_current)
        else: # even if we didn't changed anything in the file-system, we can remember the fact, that some files are checked by hash/content, and they are de facto identical
            if self.identical:
                for relative_path in self.identical:
                    self.local_previous[relative_path] = self.local_current[relative_path]
                    self.remote_previous[relative_path] = self.remote_current[relative_path]
                self.storage.save_psync_info(self.local_previous, self.remote_previous)

    def run(self):
        self.collect()
        self.compare()
        self.execute()

class BidirectionalSync(Sync):
    def compare(self):
        super().compare()

        for p in self.remote_deleted:
            if p in self.local_unchanged:
                self.delete_local.add(p)

        for p in self.local_deleted:
            if p in self.remote_unchanged:
                self.delete_remote.add(p)

        for p in self.remote_changed:
            if p in self.local_unchanged:
                self.download.add(p)
        for p in self.remote_current:
            if p not in self.local_current and p not in self.local_deleted:
                self.download.add(p)

        for p in self.local_changed:
            if p in self.remote_unchanged:
                self.upload.add(p)
        for p in self.local_current:
            if p not in self.remote_current and p not in self.remote_deleted:
                self.upload.add(p)

        for p in self.remote_deleted:
            if p in self.local_changed:
                if not self._resolve_remote_deleted(p):
                    self.conflict[p] = "is changed locally but also deleted remotely"
            if p in self.local_new:
                if not self._resolve_remote_deleted(p):
                    self.conflict[p] = "is new locally but deleted remotely"
        for p in self.local_deleted:
            if p in self.remote_changed:
                if not self._resolve_local_deleted(p):
                    self.conflict[p] = "is deleted locally but also changed remotely"
            if p in self.local_new:
                if not self._resolve_local_deleted(p):
                    self.conflict[p] = "is deleted locally but new remotely"
        for p in self.remote_new:
            if p in self.local_unchanged:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is unchanged locally but new remotely and they are different"
        for p in self.local_new:
            if p in self.remote_unchanged:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is new locally but unchanged remotely and they are different"
        for p in self.local_changed:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is changed locally and remotely and they are different"
        for p in self.local_new:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is new locally and remotely but they are different"
        for p in self.local_changed:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is changed locally but new remotely and they are different"
        for p in self.local_new:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve(p):
                    self.conflict[p] = "is new locally but changed remotely and they are different"

########

class Cache:
    PRIM_SYNC_APP_NAME = 'prim-sync'

    def __init__(self):
        self.cache_path = Path(user_cache_dir(Cache.PRIM_SYNC_APP_NAME, False))

    def set(self, key:str, value: str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        with open(cache_filename, 'wt') as file:
            file.write(value)

    def get(self, key:str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        if os.path.exists(cache_filename) and os.path.isfile(cache_filename):
            with open(cache_filename, 'rt') as file:
                return file.readline().rstrip()
        else:
            return None

class SftpServiceCache:
    def __init__(self, cache: Cache):
        self.cache = cache

    def set(self, server_name:str, host: str, port: int):
        self.cache.set(server_name, '|'.join([host, str(port)]))

    def get(self, server_name:str):
        if cached_value := self.cache.get(server_name):
            cached_value = cached_value.split('|')
            return (cached_value[0], int(cached_value[1]))
        else:
            return (None, None)

class SftpServiceResolver:
    SFTP_SERVICE_TYPE = '_sftp-ssh._tcp.local.'

    def __init__(self):
        self.zeroconf = Zeroconf()
    def __enter__(self):
        self.zeroconf.__enter__()
        return self
    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.zeroconf.__exit__(exception_type, exception_value, exception_traceback)

    def get(self, server_name: str, timeout: float = 3):
        service = self.zeroconf.get_service_info(SftpServiceResolver.SFTP_SERVICE_TYPE, f"{server_name}.{SftpServiceResolver.SFTP_SERVICE_TYPE}", timeout=int(timeout*1000))
        if not service or not service.port:
            raise TimeoutError("Unable to resolve zeroconf (DNS-SD) service information")
        return (service.parsed_addresses()[0], int(service.port))

########

class WideHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 37, width: int | None = None) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

def main():
    args = None
    try:
        parser = argparse.ArgumentParser(
            description="Bidirectional and unidirectional sync over SFTP. Multiplatform Python script optimized for the Primitive FTPd Android SFTP server (https://github.com/wolpi/prim-ftpd), for more details see https://github.com/lmagyar/prim-sync",
            formatter_class=WideHelpFormatter)

        parser.add_argument('server_name', help="unique name for the server (if zeroconf is used, then the Servername configuration option from Primitive FTPd, otherwise see the --address option also)")
        parser.add_argument('keyfile', help="key filename located under your .ssh folder")
        parser.add_argument('local_prefix', metavar='local-prefix', help="local path to the parent of the folder to be synchronized")
        parser.add_argument('remote_read_prefix', metavar='remote-read-prefix', help="read-only remote path to the parent of the folder to be synchronized, eg. /fs/storage/XXXX-XXXX or /rosaf")
        parser.add_argument('remote_write_prefix', metavar='remote-write-prefix', help="read-write remote path to the parent of the folder to be synchronized, eg. /saf (you can use * if this is the same as the read-only remote path above)")
        parser.add_argument('local_folder', metavar='local-folder', help="the local folder name to be synchronized")
        parser.add_argument('remote_folder', metavar='remote-folder', help="the remote folder name to be synchronized (you can use * if this is the same as the local folder name above)")

        parser.add_argument('-a', '--address', nargs=2, metavar=('host', 'port') , help="if zeroconf is not used, then the address of the server (the host name is without '@' and ':')")
        parser.add_argument('-t', '--timestamp', help="prefix each message with an UTC timestamp", default=False, action='store_true')
        parser.add_argument('-s', '--silent', help="only errors printed", default=False, action='store_true')
        parser.add_argument('-ss', '--silent-scanning', help="don't print scanned remote folders as progress indicator", default=False, action='store_true')
        parser.add_argument('-sh', '--silent-headers', help="don't print headers", default=False, action='store_true')
        parser.add_argument('-M', '--dont-use-mtime-for-comparison', dest="use_mtime_for_comparison", help="beyond size, modification time or content must be equal, if both is disabled, only size is compared", default=True, action='store_false')
        parser.add_argument('-C', '--dont-use-content-for-comparison', dest="use_content_for_comparison", help="beyond size, modification time or content must be equal, if both is disabled, only size is compared", default=True, action='store_false')
        parser.add_argument('-H', '--dont-use-hash-for-content-comparison', dest="use_hash_for_content_comparison", help="not all sftp servers support hashing, but downloading content is mush slower than hashing", default=True, action='store_false')
        parser.add_argument('-n', '--newer-wins', help="in case of conflict, newer file wins", default=False, action='store_true')
        parser.add_argument('-o', '--older-wins', help="in case of conflict, older file wins", default=False, action='store_true')
        parser.add_argument('-cod', '--change-wins-over-deletion', help="in case of conflict, changed/new file wins over deleted file", default=False, action='store_true')
        parser.add_argument('-doc', '--deletion-wins-over-change', help="in case of conflict, deleted file wins over changed/new file", default=False, action='store_true')
        parser.add_argument('-l', '--local-wins-patterns', metavar="PATTERN", help="in case of conflict, local files matching this Unix shell pattern win, multiple values are allowed, separated by space", type=str, nargs='+', default=[])
        parser.add_argument('-r', '--remote-wins-patterns', metavar="PATTERN", help="in case of conflict, remote files matching this Unix shell pattern win, multiple values are allowed, separated by space", type=str, nargs='+', default=[])
        parser.add_argument('-v', '--valid-chars', nargs='?', metavar="PATTERN", help="replace invalid [] SD card chars in filenames with chars from pattern (1 or 2 chars long, default is '()')", default='', const='()', action='store')
        parser.add_argument('-d', '--dry', help="no files changed in the synchronized folder(s), only internal state gets updated and temporary files gets cleaned up", default=False, action='store_true')
        parser.add_argument('-D', '--dry-on-conflict', help="in case of unresolved conflict(s), run dry", default=False, action='store_true')
        parser.add_argument('--overwrite-destination', help="don't use temporary files and renaming for failsafe updates - it is faster, but you will definitely shoot yourself in the foot", default=False, action='store_true')
        parser.add_argument('--ignore-locks', help="ignore locks left over from previous run", default=False, action='store_true')

        parser.add_argument('--debug', help="use debug level logging and add stack trace for exceptions, overrides the --silent option", default=False, action='store_true')

        args = parser.parse_args()

        if args.debug:
            logger.setLevel(logging.DEBUG)
        logger.prepare(args.timestamp, args.silent, args.silent_scanning, args.silent_headers)

        if args.address and any(c in args.address[0] for c in r'/@:'):
            raise ValueError("Host name can't contain '/@:' characters")

        global options
        options = Options(
            use_mtime_for_comparison=args.use_mtime_for_comparison, use_content_for_comparison=args.use_content_for_comparison, use_hash_for_content_comparison=args.use_hash_for_content_comparison,
            newer_wins=args.newer_wins, older_wins=args.older_wins,
            change_wins_over_deletion=args.change_wins_over_deletion, deletion_wins_over_change=args.deletion_wins_over_change,
            local_wins_patterns=set(args.local_wins_patterns), remote_wins_patterns=set(args.remote_wins_patterns),
            valid_chars=dict({k : v for k, v in zip(["[", "]"], [c for c in (args.valid_chars if len(args.valid_chars) >=2 else args.valid_chars + args.valid_chars)])}),
            dry=args.dry, dry_on_conflict=args.dry_on_conflict,
            overwrite_destination=args.overwrite_destination,
            ignore_locks=args.ignore_locks
        )

        local_prefix = Path(args.local_prefix)
        remote_read_prefix = PurePosixPath(args.remote_read_prefix)
        remote_write_prefix = PurePosixPath(args.remote_write_prefix if args.remote_write_prefix != '*' else args.remote_read_prefix)
        local_folder = str(args.local_folder)
        remote_folder = str(args.remote_folder if args.remote_folder != '*' else args.local_folder)

        local_path = str(local_prefix / local_folder)
        remote_read_path = str(remote_read_prefix / remote_folder)
        remote_write_path = str(remote_write_prefix / remote_folder)

        service_cache = SftpServiceCache(Cache())
        with SftpServiceResolver() as service_resolver:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
                def ssh_connect(host: str, port: int):
                    logger.debug("Connecting to %s on port %d", host, port)
                    ssh.connect(
                        hostname=host,
                        port=port,
                        key_filename=str(Path.home() / ".ssh" / 'id_ed25519_sftp'),
                        passphrase=None,
                        timeout=10)
                if args.address:
                    ssh_connect(args.address[0], int(args.address[1]))
                else:
                    host, port = service_cache.get(args.server_name)
                    if host and port:
                        try:
                            ssh_connect(host, port)
                        except (TimeoutError, socket.gaierror):
                            host = port = None
                    if not host or not port:
                        logger.debug("Resolving %s", args.server_name)
                        host, port = service_resolver.get(args.server_name, 30)
                        ssh_connect(host, port)
                        service_cache.set(args.server_name, host, port)
                with ssh.open_sftp() as sftp:
                    with Local(local_path) as local:
                        with Remote(local_folder, sftp, remote_read_path, remote_write_path) as remote:
                            sync = BidirectionalSync(local, remote, Storage(local_path, args.server_name))
                            sync.run()

    except Exception as e:
        if not args or args.debug:
            logger.exception(e)
        else:
            logger.error(repr(e))
    
if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
    exit(logger.exitcode)
