
from abc import abstractmethod
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
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from itertools import chain
from pathlib import Path, PurePath, PurePosixPath
from typing import Self, cast

from paramiko import SSHClient, SFTPClient, MissingHostKeyPolicy, RejectPolicy
from paramiko.ssh_exception import NoValidConnectionsError, BadHostKeyException, SSHException
from platformdirs import user_cache_dir
from zeroconf import Zeroconf

########

LOCK_FILE_NAME = '.prim-sync.lock'
LOCK_FILE_SUFFIX = '.lock'
STATE_DIR_NAME = '.prim-sync'
TIMEZONE_OFFSET_MEASUREMENT_FILE_NAME = '.timezone-offset-measurement'
NEW_FILE_SUFFIX = '.prim-sync.new' # new, tmp and old suffixes have to be the same length
TMP_FILE_SUFFIX = '.prim-sync.tmp' # new, tmp and old suffixes have to be the same length
OLD_FILE_SUFFIX = '.prim-sync.old' # new, tmp and old suffixes have to be the same length

########

class LevelFormatter(logging.Formatter):
    logging.Formatter.default_msec_format = logging.Formatter.default_msec_format.replace(',', '.') if logging.Formatter.default_msec_format else None

    def __init__(self, fmts: dict[int, str], fmt: str, **kwargs):
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
class Options:
    use_mtime_for_comparison: bool = True
    use_content_for_comparison: bool = True
    use_hash_for_content_comparison: bool = True
    newer_wins: bool = False
    older_wins: bool = False
    change_wins_over_deletion: bool = False
    deletion_wins_over_change: bool = False
    local_wins: bool = False
    local_wins_patterns: set[str] = field(default_factory=set)
    remote_wins: bool = False
    remote_wins_patterns: set[str] = field(default_factory=set)
    mirror: bool = False
    mirror_patterns: set[str] = field(default_factory=set)
    remote_state_prefix: str | None = None
    dry: bool = False
    dry_on_conflict: bool = False
    overwrite_destination: bool = False
    folder_symlink_as_destination: bool = False
    ignore_locks: int | None = None

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
    def is_equal_previous(self, previous: Self, time_shift: timedelta | None):
        if time_shift is not None:
            return self.size == previous.size and self.mtime == previous.mtime + time_shift
        else:
            return self.size == previous.size and self.mtime == previous.mtime

class LocalFileInfo(FileInfo):
    def __init__(self, size: int, mtime: datetime, btime: datetime, symlink_target: str | None):
        super().__init__(size, mtime)
        self.btime = btime
        self.symlink_target = symlink_target
    def __getstate__(self):
        return FileInfo(self.size, self.mtime).__dict__

# File transactions (when restartable operation is used ie. not directly overwriting destination file; these are valid for both local and remote operations)
#
# Creating new file
#
# .old .tmp (original) .new
#                           original state
#                        x  .new file created and written (possible unfinished write operations)
#               x           .new file renamed to it's real name
#
# Overwriting file
#
# .old .tmp (original) .new
#               x           original state
#               x        x  .new file created and written (possible unfinished write operations)
#        x               x  original renamed to .tmp to determine possible change
#   x                    x  if unchanged, rename .tmp to .old (if changed, rename .tmp back to original, delete .new, start over next time)
#   x           x           .new file renamed to it's real name
#               x           .old file deleted
#
# Deleting file
#
# .old .tmp (original) .new
#               x           original state
#        x                  original renamed to .tmp to determine possible change
#                           if unchanged, delete .tmp (if changed, rename .tmp back to original, start over next time)
#
# Recovery:
#
#      .tmp
#        x                  if there is a .tmp file, rename it to original (fail if this fails)
#
# .old      (original) .new
#                        x  delete .new
#                x          OK
#                x       x  delete .new
#   x                       RuntimeError
#   x                    x  rename .new to it's real name (then .old file deleted, see next line)
#   x            x          delete .old
#   x            x       x  RuntimeError

class Local:
    def __init__(self, local_path: str):
        self.local_path = PurePath(local_path)
        self._lockfile = None
        self._has_unsupported_hardlink = None
        self._has_unsupported_folder_symlink = None

    @property
    def has_unsupported_hardlink(self) -> bool:
        if self._has_unsupported_hardlink is None:
            raise RuntimeError("Local.scandir() has to be called before has_unsupported_hardlink can be accessed")
        return self._has_unsupported_hardlink

    @property
    def has_unsupported_folder_symlink(self) -> bool:
        if self._has_unsupported_folder_symlink is None:
            raise RuntimeError("Local.scandir() has to be called before has_unsupported_folder_symlink can be accessed")
        return self._has_unsupported_folder_symlink

    def scandir(self, is_destination: bool):
        def _scandir(path: PurePosixPath):
            logger.debug("Scanning local %s", str(self.local_path / path))
            while True: # recovery
                entries = dict({e.name: e for e in os.scandir(self.local_path / path)})
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
                    if is_destination and not options.folder_symlink_as_destination:
                        if entry.is_symlink() or entry.is_junction():
                            logger.warning("<<< SYMLINK %s", relative_name)
                            self._has_unsupported_folder_symlink = True
                    yield relative_name + '/', None
                    yield from _scandir(relative_path)
                else:
                    if is_destination and not options.overwrite_destination:
                        stat = entry.stat(follow_symlinks=False)
                        if stat.st_nlink > 1:
                            logger.warning("<<< HARDLNK %s", relative_name)
                            self._has_unsupported_hardlink = True
                    stat = entry.stat(follow_symlinks=True)
                    yield relative_name, LocalFileInfo(size=stat.st_size, mtime=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                        btime=datetime.fromtimestamp(stat.st_birthtime if SETFILETIME_SUPPORTED else 0, timezone.utc),
                        symlink_target=str(Path(self.local_path / relative_path).resolve(strict=True)) if entry.is_symlink() else None)
        self._has_unsupported_hardlink = False
        self._has_unsupported_folder_symlink = False
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
                with (
                    remote_open_fn(relative_path) as remote_file,
                    open(to_full_path, "wb") as local_file
                ):
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

    def _lock(self):
        def _get_stat(file_name: str):
            try:
                return os.stat(file_name)
            except FileNotFoundError:
                return None
        def _test_file_folder(path: str):
            folder_stat = _get_stat(path)
            if folder_stat is None:
                raise RuntimeError(f"The {path} path does not exist")
            elif folder_stat.st_mode is None or not stat.S_ISDIR(folder_stat.st_mode):
                raise RuntimeError(f"The {path} path is not a folder")
        logger.debug("Locking local")
        lock_stat = None
        try:
            _test_file_folder(str(self.local_path))
            lock_file_name = str(self.local_path / LOCK_FILE_NAME)
            if options.ignore_locks is not None:
                lock_stat = _get_stat(lock_file_name)
            mode = "x" if options.ignore_locks is None or lock_stat is None or (datetime.fromtimestamp(lock_stat.st_mtime, timezone.utc) + timedelta(minutes=options.ignore_locks) > datetime.now(timezone.utc)) else "w"
            self._lockfile = open(lock_file_name, mode)
        except IOError as e:
            e.add_note(f"Can't acquire lock on local folder (can't create {e.filename}), if this is after an interrupted sync operation, delete the lock file manually or use the --ignore-locks option")
            if lock_stat is None and options.ignore_locks is None:
                lock_stat = _get_stat(lock_file_name)
            if lock_stat is not None:
                e.add_note(f"current lock file time stamp is: {datetime.fromtimestamp(lock_stat.st_mtime).replace(microsecond=0)}")
            raise

    def _unlock(self):
        if self._lockfile:
            logger.debug("Unlocking local")
            self._lockfile.close()
            os.remove(str(self.local_path / LOCK_FILE_NAME))

    def __enter__(self):
        self._lock()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self._unlock()

class Remote:
    def __init__(self, local_folder: str, sftp: SFTPClient, remote_read_path: str, remote_write_path: str):
        self.local_folder = PurePosixPath(local_folder)
        self.sftp = sftp
        self.remote_read_path = PurePosixPath(remote_read_path)
        self.remote_write_path = PurePosixPath(remote_write_path)
        self._lockfile = None
        self._timezone_offset_measurement_mtime = None

    @property
    def timezone_offset_measurement_mtime(self) -> datetime:
        if self._timezone_offset_measurement_mtime is None:
            raise RuntimeError("Local.scandir() has to be called before timezone_offset_measurement_mtime can be accessed")
        return self._timezone_offset_measurement_mtime

    def scandir(self):
        def _scandir(path: PurePosixPath):
            logger.info_scanning("Scanning    %s", str(self.local_folder / path))
            while True: # recovery
                entries = dict({e.filename: e for e in self.sftp.listdir_attr(str(self.remote_read_path / path))})
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
                if relative_name == STATE_DIR_NAME or relative_name == LOCK_FILE_NAME:
                    continue
                if stat.S_ISDIR(entry.st_mode or 0):
                    yield relative_name + '/', None
                    yield from _scandir(relative_path)
                else:
                    yield relative_name, FileInfo(size=entry.st_size or 0, mtime=datetime.fromtimestamp(entry.st_mtime or 0, timezone.utc))
        self._timezone_offset_measurement_mtime = datetime.fromtimestamp(self.sftp.stat(str(self.remote_read_path / STATE_DIR_NAME / TIMEZONE_OFFSET_MEASUREMENT_FILE_NAME)).st_mtime or 0, timezone.utc)
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
                with (
                    local_open_fn(relative_path) as local_file,
                    self.sftp.open(to_full_path, "w") as remote_file
                ):
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

    def _lock_file_name(self):
        def _remove_first_slash(path: str):
            return path[1:] if path.startswith('/') else path
        if not options.remote_state_prefix:
            return (None, str(self.remote_write_path / LOCK_FILE_NAME))
        else:
            lock_parent_folder = PurePosixPath(options.remote_state_prefix)
            lock_folder = lock_parent_folder / STATE_DIR_NAME
            lock_file_name = lock_folder / _remove_first_slash(str(self.remote_write_path) + LOCK_FILE_SUFFIX).replace('/', '#')
            return (str(lock_folder), str(lock_file_name))

    def _lock_and_initialize(self):
        def _get_stat(file_name: str):
            try:
                logger.debug("SFTP stat on %s", file_name)
                return self.sftp.stat(file_name)
            except IOError:
                return None
        def _test_folder(path: str):
            folder_stat = _get_stat(path)
            if folder_stat is None:
                return False
            elif folder_stat.st_mode is None or not stat.S_ISDIR(folder_stat.st_mode):
                raise RuntimeError(f"The {path} path is not a folder")
            else:
                return True
        def _test_file(path: str):
            file_stat = _get_stat(path)
            if file_stat is None:
                return False
            elif file_stat.st_mode is None or not stat.S_ISREG(file_stat.st_mode):
                raise RuntimeError(f"The {path} path is not a file")
            else:
                return True
        def _test_file_folder(path: str):
            if not _test_folder(path):
                raise RuntimeError(f"The {path} path does not exist")
        def _test_lock_folder(path: str):
            if not _test_folder(path):
                try:
                    logger.debug("SFTP mkdir on %s", path)
                    self.sftp.mkdir(path)
                except IOError as e: # FileExistsError
                    if e.errno == None and e.strerror == None and len(e.args) == 1 and e.args[0] == path:
                        pass
                    else:
                        raise
        def _test_state_folder(path: str):
            file_name = path + '/' + TIMEZONE_OFFSET_MEASUREMENT_FILE_NAME
            if not _test_file(file_name):
                if not _test_folder(path):
                    logger.debug("SFTP mkdir on %s", path)
                    self.sftp.mkdir(path)
                logger.debug("SFTP open+close on %s", file_name)
                self.sftp.open(file_name, 'w').close()
        logger.debug("Locking remote")
        lock_stat = None
        try:
            _test_file_folder(str(self.remote_read_path))
            _test_file_folder(str(self.remote_write_path))
            lock_folder, lock_file_name = self._lock_file_name()
            if lock_folder:
                _test_lock_folder(lock_folder)
            if options.ignore_locks is not None:
                lock_stat = _get_stat(lock_file_name)
            mode = "x" if options.ignore_locks is None or lock_stat is None or lock_stat.st_mtime is None or (datetime.fromtimestamp(lock_stat.st_mtime, timezone.utc) + timedelta(minutes=options.ignore_locks) > datetime.now(timezone.utc)) else "w"
            logger.debug("SFTP open on %s", lock_file_name)
            self._lockfile = self.sftp.open(lock_file_name, mode)
            _test_state_folder(str(self.remote_write_path / STATE_DIR_NAME))
        except IOError as e:
            e.add_note(f"Can't acquire lock on remote folder (can't create {e}), if this is after an interrupted sync operation, delete the lock file manually or use the --ignore-locks option")
            if lock_stat is None and options.ignore_locks is None:
                lock_stat = _get_stat(lock_file_name)
            if lock_stat is not None and lock_stat.st_mtime:
                e.add_note(f"current lock file time stamp is: {datetime.fromtimestamp(lock_stat.st_mtime)}")
            raise

    def _unlock(self):
        if self._lockfile:
            logger.debug("Unlocking remote")
            _lock_folder, lock_file_name = self._lock_file_name()
            logger.debug("SFTP close on %s", lock_file_name)
            self._lockfile.close()
            logger.debug("SFTP remove on %s", lock_file_name)
            self.sftp.remove(lock_file_name)

    def __enter__(self):
        self._lock_and_initialize()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self._unlock()

@dataclass
class State:
    local: dict
    remote: dict
    remote_timezone_mtime: datetime | None

class Storage:
    class Unpickler(pickle.Unpickler):
        def find_class(self, module, name):
            try:
                return super().find_class(__name__, name)
            except AttributeError:
                return super().find_class(module, name)

    def __init__(self, local_path: str, server_name: str):
        self.state_path = Path(local_path) / STATE_DIR_NAME
        self.state_filename = str(self.state_path / server_name)

    def save_state(self, state: State):
        logger.debug("Saving state")
        self.state_path.mkdir(parents=True, exist_ok=True)
        old_state_file_name = self.state_filename + OLD_FILE_SUFFIX
        new_state_file_name = self.state_filename + NEW_FILE_SUFFIX
        with open(new_state_file_name, "wb") as out_file:
            pickle.dump(state, out_file)
        if previous_exists := os.path.exists(self.state_filename):
            os.rename(self.state_filename, old_state_file_name)
        os.rename(new_state_file_name, self.state_filename)
        if previous_exists:
            os.remove(old_state_file_name)

    def load_state(self):
        logger.debug("Loading state")
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
                return cast(State, Storage.Unpickler(in_file).load())
        else:
            return State(dict(), dict(), None)

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

    @property
    @abstractmethod
    def is_local_destination(self) -> bool:
        pass

    def collect(self):
        def _equal_entries(current, previous, time_shift: timedelta | None):
            if isinstance(current, FileInfo) and isinstance(previous, FileInfo):
                return current.is_equal_previous(previous, time_shift)
            else:
                return current == previous
        def _new_entries(current: dict, previous: dict):
            return {k for k in current.keys() if k not in previous}
        def _deleted_entries(current: dict, previous: dict):
            return {k for k in previous.keys() if k not in current}
        def _changed_entries(current: dict, previous: dict, time_shift: timedelta | None = None):
            return {k for k in current.keys() if k in previous and not _equal_entries(current[k], previous[k], time_shift)}
        def _unchanged_entries(current: dict, previous: dict, time_shift: timedelta | None = None):
            return {k for k in current.keys() if k in previous and _equal_entries(current[k], previous[k], time_shift)}

        logger.info_header("----------- Scanning")

        previous_state = self.storage.load_state()
        self.local_previous = previous_state.local
        self.remote_previous = previous_state.remote
        self.remote_timezone_mtime_previous = previous_state.remote_timezone_mtime

        self.local_current = dict(sorted(self.local.scandir(self.is_local_destination)))
        if self.local.has_unsupported_hardlink:
            raise RuntimeError("Hardlinks can't be used on local side as destination without enabling --overwrite-destination option")
        if self.local.has_unsupported_folder_symlink:
            raise RuntimeError("Folder symlinks or junctions can't be used on local side as destination without enabling --folder-symlink-as-destination option")
        self.remote_current = dict(sorted(self.remote.scandir()))
        self.remote_timezone_mtime_current = self.remote.timezone_offset_measurement_mtime

        # FAT (FAT32, exFAT) stores mtime in local time, if the DST changes or the phone moves to another timezone, all mtime will change.
        # But using the timezone offset of the phone (eg. date +"%z") won't work, because the DST +1 offset is not added but subtracted from the timezone,
        # ie. UTC+1 in DST is UTC+2, but this is equivalnet with UTC+0 and not UTC+2 timezone offset, total chaos.
        # That's why a never changing file is used to determine the real offset.
        remote_time_shift = None
        if self.remote_timezone_mtime_previous is not None:
            remote_timezone_mtime_change = self.remote_timezone_mtime_current - self.remote_timezone_mtime_previous
            remote_timezone_mtime_change_minutes = remote_timezone_mtime_change.total_seconds() / 60
            if (remote_timezone_mtime_change_minutes % 15
                    or remote_timezone_mtime_change_minutes > (12+14)*60
                    or remote_timezone_mtime_change_minutes < -(12+14)*60):
                logger.warning("Remote timezone offset change %s minutes is not divisible by 15 minutes or larger than 26 hours (valid timezone range is -12:00 to +14:00), offset change is ignored",
                    remote_timezone_mtime_change_minutes)
            elif remote_timezone_mtime_change_minutes:
                logger.debug("Remote timezone offset change %s minutes is detected, any modification time change that is identical with this is ignored",
                    int(remote_timezone_mtime_change_minutes))
                remote_time_shift = remote_timezone_mtime_change

        self.local_new = _new_entries(self.local_current, self.local_previous)
        self.local_deleted = _deleted_entries(self.local_current, self.local_previous)
        self.local_changed = _changed_entries(self.local_current, self.local_previous)
        self.local_unchanged = _unchanged_entries(self.local_current, self.local_previous)

        self.remote_new = _new_entries(self.remote_current, self.remote_previous)
        self.remote_deleted = _deleted_entries(self.remote_current, self.remote_previous)
        self.remote_changed = _changed_entries(self.remote_current, self.remote_previous, remote_time_shift)
        self.remote_unchanged = _unchanged_entries(self.remote_current, self.remote_previous, remote_time_shift)

        self.delete_local = set()
        self.delete_remote = set()
        self.download = set()
        self.upload = set()
        self.identical = set()
        self.conflict = dict()

    def compare(self):
        logger.info_header("----------- Analyzing")

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

        if options.dry and (self.delete_local or self.delete_remote or self.download or self.upload):
            logger.info("!!!!!!!!!!! Running dry! No deletion, creation, upload or download will be executed!")

        for relative_path in chain(sorted({p for p in self.delete_local if not p.endswith('/')}, key=lambda p: (p.count('/'), p)),  # first delete files
                sorted({p for p in self.delete_local if p.endswith('/')}, key=lambda p: (-p.count('/'), p))):                       # then folders, starting deep
            logger.info("<<< DEL     %s", relative_path)
            if not options.dry:
                if self.local.remove(relative_path, self.local_current[relative_path]):
                    del self.local_current[relative_path]
                else:
                    logger.info("< CHANGED     will be processed only on the next run")

        for relative_path in chain(sorted({p for p in self.delete_remote if not p.endswith('/')}, key=lambda p: (p.count('/'), p)), # first delete files
                sorted({p for p in self.delete_remote if p.endswith('/')}, key=lambda p: (-p.count('/'), p))):                      # then folders, starting deep
            logger.info("    DEL >>> %s", relative_path)
            if not options.dry:
                if self.remote.remove(relative_path, self.remote_current[relative_path]):
                    del self.remote_current[relative_path]
                else:
                    logger.info("  CHANGED >   will be processed only on the next run")

        for relative_path in chain(sorted({p for p in self.download if p.endswith('/')}, key=lambda p: (p.count('/'), p)),          # first create folders
                sorted({p for p in self.download if not p.endswith('/')}, key=lambda p: (p.count('/'), p))):                        # then download files
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
                sorted({p for p in self.upload if not p.endswith('/')}, key=lambda p: (p.count('/'), p))):                          # then upload files
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
            def _extended_reason():
                def _extended_reason_compare(left_fileinfo: FileInfo, right_fileinfo: FileInfo):
                    return (
                        f", size: {_filesize_fmt(left_fileinfo.size)} ({format(left_fileinfo.size, ',d').replace(',',' ')}) "
                            f"{'>' if left_fileinfo.size > right_fileinfo.size else '<' if left_fileinfo.size < right_fileinfo.size else '='} "
                            f"{_filesize_fmt(right_fileinfo.size)} ({format(right_fileinfo.size, ',d').replace(',',' ')})"
                        f", time: {left_fileinfo.mtime} {'>' if left_fileinfo.mtime > right_fileinfo.mtime else '<' if left_fileinfo.mtime < right_fileinfo.mtime else '='} {right_fileinfo.mtime}")
                extended_reason = f"              {reason}"
                local_fileinfo = self.local_current.get(relative_path)
                remote_fileinfo = self.remote_current.get(relative_path)
                if local_fileinfo and remote_fileinfo:
                    extended_reason += _extended_reason_compare(local_fileinfo, remote_fileinfo)
                else:
                    if local_fileinfo:
                        fileinfo = local_fileinfo
                        previous_fileinfo = self.local_previous.get(relative_path)
                    else:
                        fileinfo = remote_fileinfo
                        previous_fileinfo = self.remote_previous.get(relative_path)
                    if fileinfo and previous_fileinfo:
                        extended_reason += _extended_reason_compare(previous_fileinfo, fileinfo)
                    elif fileinfo:
                        extended_reason += f", size: {_filesize_fmt(fileinfo.size)} ({format(fileinfo.size, ',d').replace(',',' ')}), time: {fileinfo.mtime}"
                return extended_reason
            logger.warning("<<< !!! >>> %s", relative_path)
            logger.warning(LazyStr(_extended_reason))
            _forget_changes(self.local_current, self.local_previous, relative_path)
            _forget_changes(self.remote_current, self.remote_previous, relative_path)

        if not self.delete_local and not self.delete_remote and not self.download and not self.upload and not self.conflict:
            logger.info_header("----------- Everything is up to date!")

        if not options.dry:
            self.storage.save_state(State(self.local_current, self.remote_current, self.remote_timezone_mtime_current))
        else:
            if self.identical:
                # even if we didn't changed anything in the file-system, we can remember the fact, that some files are checked by hash/content, and they are de facto identical
                for relative_path in self.identical:
                    self.local_previous[relative_path] = self.local_current[relative_path]
                    self.remote_previous[relative_path] = self.remote_current[relative_path]
                self.storage.save_state(State(self.local_previous, self.remote_previous, self.remote_timezone_mtime_previous))

    def run(self):
        self.collect()
        self.compare()
        self.execute()

# Bidirectional comparison
#
#   L\R  |   x   |   -   |   o   |   +   |   ?   |
# -------|-------|-------|-------|-------|-------|
#    x   |   x   |  --   |  <<   |  <C>  |   >>  |
#    -   |   --  |   x   |  <!>  |  <!>  |   x   |
#    o   |   >>  |  <!>  |  <C>  |  <C>  |   >>  |
#    +   |  <C>  |  <!>  |  <C>  |  <C>  |   >>  |
#    ?   |  <<   |   x   |  <<   |  <<   |#######|
#
# Header:
# L\R = Local\Remote
# x unchanged
# - deleted
# o changed
# + new
# ? unknown (we have never seen it)
#
# Action:
#  x  do nothing
# --  delete local
#  -- delete remote
# <<  download
#  >> upload
# <C> compare (content or hash) to determine whether we have a conflict
# <!> conflict

class BidirectionalSync(Sync):
    @property
    def is_local_destination(self) -> bool:
        return True

    def _resolve(self, relative_path: str):
        if ((options.newer_wins or options.older_wins) and not relative_path.endswith('/')
                and (local_mtime := cast(FileInfo, self.local_current[relative_path]).mtime) != (remote_mtime := cast(FileInfo, self.remote_current[relative_path]).mtime)):
            if local_mtime > remote_mtime and options.newer_wins or local_mtime < remote_mtime and options.older_wins:
                self.upload.add(relative_path)
            else:
                self.download.add(relative_path)
        else:
            prefer_local = options.local_wins or options.local_wins_patterns and any(fnmatch(relative_path, p) for p in options.local_wins_patterns)
            prefer_remote = options.remote_wins or options.remote_wins_patterns and any(fnmatch(relative_path, p) for p in options.remote_wins_patterns)
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

# Unidirectional inward (<-) comparison
#
#   L\R  |   x   |   -   |   o   |   +   |   ?   |
# -------|-------|-------|-------|-------|-------|
#    x   |   x   |  --   |  <<   |  <C   |  -!   |
#    -   |  <!   |   x   |  <!   |  <!   |   x   |
#    o   |  <!   |  -!   |  <C   |  <C   |  -!   |
#    +   |  <C   |  -!   |  <C   |  <C   |  -!   |
#    ?   |  <<   |   x   |  <<   |  <<   |#######|
#
# Header:
# L\R = Local\Remote
# x unchanged
# - deleted
# o changed
# + new
# ? unknown (we have never seen it)
#
# Action:
#  x  do nothing
# --  delete local
# <<  download
# <C  compare (content or hash) to determine whether we have a conflict to download
# -!  conflict to delete local
# <!  conflict to download

class UnidirectionalInwardSync(Sync):
    @property
    def is_local_destination(self) -> bool:
        return True

    def _resolve_download(self, relative_path: str):
        if options.mirror or options.mirror_patterns and any(fnmatch(relative_path, p) for p in options.mirror_patterns):
            self.download.add(relative_path)
        else:
            return False
        return True

    def _resolve_local_deletion(self, relative_path: str):
        if options.mirror or options.mirror_patterns and any(fnmatch(relative_path, p) for p in options.mirror_patterns):
            self.delete_local.add(relative_path)
        else:
            return False
        return True

    def compare(self):
        super().compare()

        for p in self.remote_deleted:
            if p in self.local_unchanged:
                self.delete_local.add(p)

        for p in self.remote_changed:
            if p in self.local_unchanged:
                self.download.add(p)
        for p in self.remote_current:
            if p not in self.local_current and p not in self.local_deleted:
                self.download.add(p)

        for p in self.local_changed:
            if p not in self.remote_current:
                if not self._resolve_local_deletion(p):
                    if p in self.remote_deleted:
                        self.conflict[p] = "is changed locally but also deleted remotely" # existing text
                    else:
                        self.conflict[p] = "is changed locally but unknown remotely"
        for p in self.local_new:
            if p not in self.remote_current:
                if not self._resolve_local_deletion(p):
                    if p in self.remote_deleted:
                        self.conflict[p] = "is new locally but deleted remotely" # existing text
                    else:
                        self.conflict[p] = "is new locally but unknown remotely"
        for p in self.local_unchanged:
            if p not in self.remote_current and p not in self.remote_deleted:
                if not self._resolve_local_deletion(p):
                    self.conflict[p] = "unchanged locally but is unknown remotely"

        for p in self.local_deleted:
            if p in self.remote_current:
                if not self._resolve_download(p):
                    self.conflict[p] = "is deleted locally but exists remotely"
        for p in self.local_changed:
            if p in self.remote_unchanged:
                if not self._resolve_download(p):
                    self.conflict[p] = "is changed locally but unchanged remotely"

        for p in self.remote_new:
            if p in self.local_unchanged:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is unchanged locally but new remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_unchanged:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is new locally but unchanged remotely and they are different" # existing text
        for p in self.local_changed:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is changed locally and remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is new locally and remotely but they are different" # existing text
        for p in self.local_changed:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is changed locally but new remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve_download(p):
                    self.conflict[p] = "is new locally but changed remotely and they are different" # existing text

# Unidirectional outward (->) comparison
#
#   L\R  |   x   |   -   |   o   |   +   |   ?   |
# -------|-------|-------|-------|-------|-------|
#    x   |   x   |   !>  |   !>  |   C>  |   >>  |
#    -   |   --  |   x   |   !-  |   !-  |   x   |
#    o   |   >>  |   !>  |   C>  |   C>  |   >>  |
#    +   |   C>  |   !>  |   C>  |   C>  |   >>  |
#    ?   |   !-  |   x   |   !-  |   !-  |#######|
#
# Header:
# L\R = Local\Remote
# x unchanged
# - deleted
# o changed
# + new
# ? unknown (we have never seen it)
#
# Action:
#  x  do nothing
#  -- delete remote
#  >> upload
#  C> compare (content or hash) to determine whether we have a conflict to upload
#  !- conflict to delete remote
#  !> conflict to upload

class UnidirectionalOutwardSync(Sync):
    @property
    def is_local_destination(self) -> bool:
        return False

    def _resolve_upload(self, relative_path: str):
        if options.mirror or options.mirror_patterns and any(fnmatch(relative_path, p) for p in options.mirror_patterns):
            self.upload.add(relative_path)
        else:
            return False
        return True

    def _resolve_remote_deletion(self, relative_path: str):
        if options.mirror or options.mirror_patterns and any(fnmatch(relative_path, p) for p in options.mirror_patterns):
            self.delete_remote.add(relative_path)
        else:
            return False
        return True

    def compare(self):
        super().compare()

        for p in self.local_deleted:
            if p in self.remote_unchanged:
                self.delete_remote.add(p)

        for p in self.local_changed:
            if p in self.remote_unchanged:
                self.upload.add(p)
        for p in self.local_current:
            if p not in self.remote_current and p not in self.remote_deleted:
                self.upload.add(p)

        for p in self.remote_changed:
            if p not in self.local_current:
                if not self._resolve_remote_deletion(p):
                    if p in self.local_deleted:
                        self.conflict[p] = "is deleted locally but also changed remotely" # existing text
                    else:
                        self.conflict[p] = "is unknown locally but also changed remotely"
        for p in self.remote_new:
            if p not in self.local_current:
                if not self._resolve_remote_deletion(p):
                    if p in self.local_deleted:
                        self.conflict[p] = "is deleted locally but new remotely" # existing text
                    else:
                        self.conflict[p] = "is unknown locally but new remotely"
        for p in self.remote_unchanged:
            if p not in self.local_current and p not in self.local_deleted:
                if not self._resolve_remote_deletion(p):
                    self.conflict[p] = "is unknown locally but unchanged remotely"

        for p in self.remote_deleted:
            if p in self.local_current:
                if not self._resolve_upload(p):
                    self.conflict[p] = "exists locally but is deleted remotely"
        for p in self.remote_changed:
            if p in self.local_unchanged:
                if not self._resolve_upload(p):
                    self.conflict[p] = "is unchanged locally but changed remotely"

        for p in self.remote_new:
            if p in self.local_unchanged:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is unchanged locally but new remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_unchanged:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is new locally but unchanged remotely and they are different" # existing text
        for p in self.local_changed:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is changed locally and remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is new locally and remotely but they are different" # existing text
        for p in self.local_changed:
            if p in self.remote_new:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is changed locally but new remotely and they are different" # existing text
        for p in self.local_new:
            if p in self.remote_changed:
                if not self._is_identical(p) and not self._resolve_upload(p):
                    self.conflict[p] = "is new locally but changed remotely and they are different" # existing text

########

class Cache:
    PRIM_SYNC_APP_NAME = 'prim-sync'

    def __init__(self):
        self.cache_path = Path(user_cache_dir(Cache.PRIM_SYNC_APP_NAME, False))

    def set(self, key: str, value: str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        with open(cache_filename, 'wt') as file:
            file.write(value)

    def get(self, key: str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        if os.path.exists(cache_filename) and os.path.isfile(cache_filename):
            with open(cache_filename, 'rt') as file:
                return file.readline().rstrip()
        else:
            return None

class ServiceCache:
    def __init__(self, cache: Cache):
        self.cache = cache

    def set(self, service_name: str, host: str, port: int):
        self.cache.set(service_name, '|'.join([host, str(port)]))

    def get(self, service_name: str):
        if cached_value := self.cache.get(service_name):
            cached_value = cached_value.split('|')
            return (cached_value[0], int(cached_value[1]))
        else:
            return (None, None)

class ServiceResolver:
    def __init__(self, zeroconf: Zeroconf, service_type: str):
        self.zeroconf = zeroconf
        self.service_type = service_type

    def get(self, service_name: str, timeout: float = 3):
        service_info = self.zeroconf.get_service_info(self.service_type, f"{service_name}.{self.service_type}", timeout=int(timeout*1000))
        if not service_info or not service_info.port:
            raise TimeoutError("Unable to resolve zeroconf (DNS-SD) service information - if you are using an Android phone as SFTP server, please turn on the screen, because Android doesn't answer DNS-SD queries when the screen is off")
        return (service_info.parsed_addresses()[0], int(service_info.port))

SFTP_SERVICE_TYPE = '_sftp-ssh._tcp.local.'

class SftpServiceResolver(ServiceResolver):
    def __init__(self, zeroconf: Zeroconf):
        super().__init__(zeroconf, SFTP_SERVICE_TYPE)

class ZeroconfPolicy(MissingHostKeyPolicy):
    def __init__(self, service_name: str):
        self.service_name = service_name

    def missing_host_key(self, client, hostname, key):
        # _host_keys is a non-public attribute, in case of new Paramiko versions, check this line
        host_keys = client._host_keys.get(self.service_name) # type: ignore
        if host_keys is None:
            raise SSHException("Server {} not found in known_hosts".format(self.service_name))
        host_key = host_keys.get(key.get_name())
        if host_key != key:
            raise BadHostKeyException(hostname, key, host_key)

########

class WideHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 37, width: int | None = None) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

def main():
    args = None
    try:
        parser = argparse.ArgumentParser(
            description="Bidirectional and unidirectional sync over SFTP. Multiplatform Python script optimized for the Primitive FTPd Android SFTP server (https://github.com/wolpi/prim-ftpd), for more details see https://github.com/lmagyar/prim-sync",
            formatter_class=WideHelpFormatter)

        parser.add_argument('server_name', metavar='server-name', help="unique name for the server (if zeroconf is used, then the Servername configuration option from Primitive FTPd, otherwise see the --address option also)")
        parser.add_argument('keyfile', help="key filename located under your .ssh folder")
        parser.add_argument('local_prefix', metavar='local-prefix', help="local path to the parent of the folder to be synchronized")
        parser.add_argument('remote_read_prefix', metavar='remote-read-prefix', help="read-only remote path to the parent of the folder to be synchronized, eg. /fs/storage/XXXX-XXXX or /rosaf")
        parser.add_argument('remote_write_prefix', metavar='remote-write-prefix', help="read-write remote path to the parent of the folder to be synchronized, eg. /saf (you can use * if this is the same as the read-only remote path above)")
        parser.add_argument('local_folder', metavar='local-folder', help="the local folder name to be synchronized")
        parser.add_argument('remote_folder', metavar='remote-folder', help="the remote folder name to be synchronized (you can use * if this is the same as the local folder name above)")

        parser.add_argument('-a', '--address', nargs=2, metavar=('host', 'port') , help="if zeroconf is not used, then the address of the server")
        parser_direction_group = parser.add_mutually_exclusive_group()
        parser_direction_group.add_argument('-ui', '--unidirectional-inward', help="unidirectional inward sync (default is bidirectional sync)", default=False, action='store_true')
        parser_direction_group.add_argument('-uo', '--unidirectional-outward', help="unidirectional outward sync (default is bidirectional sync)", default=False, action='store_true')
        parser.add_argument('-d', '--dry', help="no files changed in the synchronized folder(s), only internal state gets updated and temporary files get cleaned up", default=False, action='store_true')
        parser.add_argument('-D', '--dry-on-conflict', help="in case of unresolved conflict(s), run dry", default=False, action='store_true')
        parser.add_argument('-rs', '--remote-state-prefix', metavar="PATH", help="stores remote state in a common .prim-sync folder under PATH instead of under the remote-folder argument (decreases SD card wear), eg. /fs/storage/emulated/0\n"
                            "Note: currently only the .lock file is stored here\n"
                            "Note: if you access the same server from multiple clients, you have to specify the same --remote-state-prefix option everywhere to prevent concurrent access")
        parser.add_argument('--overwrite-destination', help="don't use temporary files and renaming for failsafe updates - it is faster, but you will definitely shoot yourself in the foot when used with bidirectional sync", default=False, action='store_true')
        parser.add_argument('--folder-symlink-as-destination', help="enables writing and deleting symlinked folders and files in them on the local side - it can make sense, but you will definitely shoot yourself in the foot", default=False, action='store_true')
        parser.add_argument('--ignore-locks', nargs='?', metavar="MINUTES", help="ignore locks left over from previous run, optionally only if they are older than MINUTES minutes", type=int, default=None, const=0, action='store')

        logging_group = parser.add_argument_group('logging')
        logging_group.add_argument('-t', '--timestamp', help="prefix each message with a timestamp", default=False, action='store_true')
        logging_group.add_argument('-s', '--silent', help="only errors printed", default=False, action='store_true')
        logging_group.add_argument('-ss', '--silent-scanning', help="don't print scanned remote folders as progress indicator", default=False, action='store_true')
        logging_group.add_argument('-sh', '--silent-headers', help="don't print headers", default=False, action='store_true')
        logging_group.add_argument('--debug', help="use debug level logging and add stack trace for exceptions, disables the --silent and enables the --timestamp options", default=False, action='store_true')

        comparison_group = parser.add_argument_group('comparison')
        comparison_group.add_argument('-M', '--dont-use-mtime-for-comparison', dest="use_mtime_for_comparison", help="beyond size, modification time or content must be equal, if both are disabled, only size is compared", default=True, action='store_false')
        comparison_group.add_argument('-C', '--dont-use-content-for-comparison', dest="use_content_for_comparison", help="beyond size, modification time or content must be equal, if both are disabled, only size is compared", default=True, action='store_false')
        comparison_group.add_argument('-H', '--dont-use-hash-for-content-comparison', dest="use_hash_for_content_comparison", help="not all sftp servers support hashing, but downloading content for comparison is mush slower than hashing", default=True, action='store_false')

        bidir_conflict_resolution_group = parser.add_argument_group('bidirectional conflict resolution')
        bidir_conflict_resolution_newer_older_group = bidir_conflict_resolution_group.add_mutually_exclusive_group()
        bidir_conflict_resolution_newer_older_group.add_argument('-n', '--newer-wins', help="in case of conflict, newer file wins", default=False, action='store_true')
        bidir_conflict_resolution_newer_older_group.add_argument('-o', '--older-wins', help="in case of conflict, older file wins", default=False, action='store_true')
        bidir_conflict_resolution_change_deletion_group = bidir_conflict_resolution_group.add_mutually_exclusive_group()
        bidir_conflict_resolution_change_deletion_group.add_argument('-cod', '--change-wins-over-deletion', help="in case of conflict, changed/new file wins over deleted file", default=False, action='store_true')
        bidir_conflict_resolution_change_deletion_group.add_argument('-doc', '--deletion-wins-over-change', help="in case of conflict, deleted file wins over changed/new file", default=False, action='store_true')
        bidir_conflict_resolution_group.add_argument('-l', '--local-wins-patterns', nargs='*', metavar="PATTERN", help="in case of conflict, local files matching this Unix shell PATTERN win, multiple values are allowed, separated by space\n"
                                                      "if no PATTERN is specified, local always wins")
        bidir_conflict_resolution_group.add_argument('-r', '--remote-wins-patterns', nargs='*', metavar="PATTERN", help="in case of conflict, remote files matching this Unix shell PATTERN win, multiple values are allowed, separated by space\n"
                                                      "if no PATTERN is specified, remote always wins")

        unidir_conflict_resolution_group = parser.add_argument_group('unidirectional conflict resolution')
        unidir_conflict_resolution_group.add_argument('-m', '--mirror-patterns', nargs='*', metavar="PATTERN", help="in case of conflict, mirror source side files matching this Unix shell PATTERN to destination side, multiple values are allowed, separated by space\n"
                                                      "if no PATTERN is specified, all files will be mirrored")

        args = parser.parse_args()

        if args.debug:
            logger.setLevel(logging.DEBUG)
        logger.prepare(args.timestamp or args.debug, args.silent, args.silent_scanning, args.silent_headers)

        if args.unidirectional_inward or args.unidirectional_outward:
            if args.newer_wins or args.older_wins or args.change_wins_over_deletion or args.deletion_wins_over_change or args.local_wins_patterns is not None or args.remote_wins_patterns is not None:
                raise ValueError("Can't specify bidirectional options for unidirectional sync")
        else:
            if args.mirror_patterns is not None:
                raise ValueError("Can't specify unidirectional options for bidirectional sync")

        global options
        options = Options(
            use_mtime_for_comparison=args.use_mtime_for_comparison,
            use_content_for_comparison=args.use_content_for_comparison,
            use_hash_for_content_comparison=args.use_hash_for_content_comparison,
            newer_wins=args.newer_wins,
            older_wins=args.older_wins,
            change_wins_over_deletion=args.change_wins_over_deletion,
            deletion_wins_over_change=args.deletion_wins_over_change,
            local_wins=(args.local_wins_patterns is not None and len(args.local_wins_patterns) == 0),
            local_wins_patterns=set(args.local_wins_patterns or []),
            remote_wins=(args.remote_wins_patterns is not None and len(args.remote_wins_patterns) == 0),
            remote_wins_patterns=set(args.remote_wins_patterns or []),
            mirror=(args.mirror_patterns is not None and len(args.mirror_patterns) == 0),
            mirror_patterns=set(args.mirror_patterns or []),
            remote_state_prefix=args.remote_state_prefix,
            dry=args.dry,
            dry_on_conflict=args.dry_on_conflict,
            overwrite_destination=args.overwrite_destination,
            folder_symlink_as_destination=args.folder_symlink_as_destination,
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

        with Zeroconf() as zeroconf:
            service_cache = ServiceCache(Cache())
            service_resolver = SftpServiceResolver(zeroconf)
            with SSHClient() as ssh:
                ssh.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
                ssh.set_missing_host_key_policy(ZeroconfPolicy(args.server_name))
                def _connect_ssh(connect_timeout: float, resolve_timeout: float):
                    def _connect(host: str, port: int, timeout: float):
                        logger.debug("Connecting to %s on port %d (timeout is %d seconds)", host, port, timeout)
                        ssh.connect(
                            hostname=host,
                            port=port,
                            key_filename=str(Path.home() / ".ssh" / args.keyfile),
                            passphrase=None,
                            timeout=timeout)
                    def _resolve(service_name: str, timeout: float):
                        logger.debug("Resolving %s (timeout is %d seconds)", service_name, timeout)
                        return service_resolver.get(service_name, timeout)
                    if args.address:
                        _connect(args.address[0], int(args.address[1]), connect_timeout)
                    else:
                        host, port = service_cache.get(args.server_name)
                        if host and port:
                            try:
                                _connect(host, port, connect_timeout)
                                return
                            except (TimeoutError, socket.gaierror, ConnectionRefusedError, NoValidConnectionsError, BadHostKeyException) as e:
                                logger.debug(LazyStr(repr, e))
                                pass
                        host, port = _resolve(args.server_name, resolve_timeout)
                        _connect(host, port, connect_timeout)
                        service_cache.set(args.server_name, host, port)
                _connect_ssh(10, 30)
                with (
                    ssh.open_sftp() as sftp,
                    Local(local_path) as local,
                    Remote(local_folder, sftp, remote_read_path, remote_write_path) as remote
                ):
                    storage = Storage(local_path, args.server_name)
                    if args.unidirectional_inward:
                        sync = UnidirectionalInwardSync(local, remote, storage)
                    elif args.unidirectional_outward:
                        sync = UnidirectionalOutwardSync(local, remote, storage)
                    else:
                        sync = BidirectionalSync(local, remote, storage)
                    sync.run()

    except Exception as e:
        if not args or args.debug:
            logger.exception(e)
        else:
            if hasattr(e, '__notes__'):
                logger.error("%s: %s", LazyStr(repr, e), LazyStr(", ".join, e.__notes__))
            else:
                logger.error(LazyStr(repr, e))

    return logger.exitcode

def run():
    with suppress(KeyboardInterrupt):
        exit(main())
