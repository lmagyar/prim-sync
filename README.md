
> [!CAUTION]
> ***This repository is in alpha and currently works only with my modified version of [Primitive FTPd Android SFTP server](https://github.com/wolpi/prim-ftpd)!***
> - ***use my fork at https://github.com/lmagyar/prim-ftpd***
> - ***or wait until the new features got merged into Primitive FTPd (see: [#349](https://github.com/wolpi/prim-ftpd/pull/349) [#350](https://github.com/wolpi/prim-ftpd/pull/350) [#360](https://github.com/wolpi/prim-ftpd/pull/360) [#371](https://github.com/wolpi/prim-ftpd/pull/371))***

# Primitive Sync

Bidirectional and unidirectional sync over SFTP. Multiplatform Python script optimized for the [Primitive FTPd Android SFTP server](https://github.com/wolpi/prim-ftpd).

Why another sync solution? Because none of the professional solutions can write SD cards and follow local symlinks, or are extremely slow or full of bugs (Syncthing, Resilio Sync, rsync, osync, rclone, Unison). I gave up and wrote it.

See my other project, https://github.com/lmagyar/prim-ctrl, for remote management of your phone's Primitive FTPd SFTP server and optionally Tailscale VPN.

## Features

- Follow local symlinks
- Hash files for fast comparison ***( !!! currently requires the forked Primitive FTPd !!! )***
- Write SD card (with Primitive FTPd and Storage Access Framework)
- Dual access in case of SD card (read-only plain-old file-system for fast scan and download and writing with the slower Storage Access Framework)
- Failsafe, restartable operation (costs some time, remote renames on SD card are slow)
- Automatically replace `[` and `]` chars (that are invalid for SD card and Storage Access Framework)

#### Notes on following local symlinks

- File symlinks just work
- File hardlinks are OK for unidirectional outward sync, but have to use --overwrite-destination option in case of bidirectional or unidirectional inward sync
  - Better not to use file hardlinks, use symlinks
- Folder symlinks or junctions are OK for unidirectional outward sync, but be ***very-very-very*** careful with bidirectional or unidirectional inward sync
  - If you have a folder symlink and you think you delete files on your phone under the symlinked folder, or even you delete the symlinked folder, because "they are only under a symlink", you shoot yourself in the foot
  - Syncing file deletions means file deletions synced first, then the containing folder deletion synced
  - So first all the files will be deleted in the symlink ***target*** folder, then the folder symlink itself will be deleted, though the target folder is not deleted
  - So symlinking the family picture albums' folder better done with an unidirectional outward sync
  - Or symlink only the files if you enable deletion on the phone
  - You have been warned!

## Installation

You need to install:
- Primitive FTPd on your phone - see: https://github.com/wolpi/prim-ftpd ***use the F-Droid version!***
- Python 3.12+, pip and venv - see: https://www.python.org/downloads/ or
  <details><summary>Unix</summary>

  ```
  sudo apt update
  sudo apt upgrade
  sudo apt install python3 python3-pip python3-venv
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  choco install python3 -y
  ```
  </details>
- This repo
  <details><summary>Unix</summary>

  ```
  git clone https://github.com/lmagyar/prim-sync
  cd prim-sync
  python3 -m venv --upgrade-deps .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  git clone https://github.com/lmagyar/prim-sync
  cd prim-sync
  py -m venv --upgrade-deps .venv
  .venv\Scripts\activate
  pip install -r requirements.txt
  ```
  </details>

## Configuration

### Android

You have to enable Primitive FTPd to run as much in the background as possible, please see the relevant [Readme section](https://github.com/wolpi/prim-ftpd#running-in-the-background).

### Networking

Either use the built-in zeroconf (DNS-SD) functionality in Primitive FTPd (see below), or set up a constant address (IP or host name) for your phone (fixed LAN IP, VPN, hosts file, your choice).

### Primitive FTPd

- Home tab:
  - Select "Virtual folders" and follow the relevant [Readme section](https://github.com/wolpi/prim-ftpd#external-sd-card-readwrite-access---android-storage-access-framework)
- Configuration tab:
  - Authentication
      - Anonymous Login: disable
      - Username/Password: eg. sftp/sftp (will be disabled)
      - Public Key Authentication: disable (will be enabled)
  - Connectivity
      - Server(s) to be started: SFTP only
      - Secure Port: eg. 2222
      - Server Idle Timeout: 0
      - Idle timeout to stop server: eg. 60 or 0
      - Allowed IPs pattern, IP to bind to: at first leave them empty, you can harden your security later
  - UI
      - This is based on your preferences
  - System
      - Server Start Directory: /storage/emulated/0
      - Prevent Standby: enable
      - Announce server in LAN: enable if you use zeroconf (DNS-SD)
      - Servername: make it unique, even if you don't use zeroconf, especially when multiple phones are synced, because this will be used as unique identifier to store the per-device-sync-state between runs
      - SFTP Hostkey algorithms: enable at least ed25519
      - Other options can be left unchanged
- Stop the server (if you have started)
- Close and restart the whole app
- Start the server

### SSH keys

You need to generate an SSH key pair.
<details><summary>Unix</summary>

```
sudo apt install openssh-client
mkdir ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_sftp -N ""
```
</details>
<details><summary>Windows</summary>

Go to _Settings / System / Optional features / Add an optional feature_ and add "OpenSSH Client"
```
mkdir %USERPROFILE%\.ssh
ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\id_ed25519_sftp -N ""
```
</details>

Then install it in Primitive FTPd:
- Use your favorite SFTP client (eg. WinSCP, FileZilla) to access the Primitive FTPd, use username/password to authenticate.
- Open for editing the `/fs/storage/emulated/0/Android/data/org.primftpd/files/.ssh/authorized_keys` file.
- Append the content of the previously generated `.ssh/id_ed25519_sftp.pub` file to it. It is something like "ssh-ed25519 XXXxxxXXXxxx you@your-device"

Then add your phone to the known_hosts file if your favorite SFTP client hasn't done it:
- Use ssh to access the Primitive FTPd, use username/password to authenticate.
  <details><summary>Unix</summary>

  ```
  ssh -oUserKnownHostsFile=~/.ssh/known_hosts -oPort=2222 sftp@your.phone.host.name
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  ssh -oUserKnownHostsFile=%USERPROFILE%\.ssh\known_hosts -oPort=2222 sftp@your.phone.host.name
  ```
  </details>
- Acceph host key
- The error "shell request failed on channel 0" is OK, there is no SSH server in Primitive FTPd, our goal was to connect and store the server key in the known_hosts file.

### Primitive FTPd again

- Configuration tab:
  - Authentication
      - Password: delete it
      - Public Key Authentication: enable
- Stop the server
- Close and restart the whole app
- Start the server

## Usage

Create a backup of your files!!! Really!!! If you use symlinks, this is only question of time when will you delete something unintendedly!!!

The first upload is better done over USB connection and manual copy, because copying files over Wi-Fi is much slower. The prim-sync script handles both this upload and the changes in the future.

The first run will be longer than a regular run, because without prior knowledge, the prim-sync script handles all files on both sides as newly created and compares them or their hashes (hashing is much faster than downloading and comparing the content).

On regular runs the meaning of the log lines are:
- Scanning - Name of the remote folder that is scanned (only remote is logged, remote is the bottleneck)
- Comparing, Hashing - Comparing the content or the hash of the files on the two sides.
- <<< !!! >>> - Conflicting changes that are not resolved by any command line option, the details are in the next line.
- RECOVER - The previous run failed (probably network/connection problem), and there are intermediate/leftover files that are deleted on the next (ie. this) run.
- INVALID - Invalid characters in the filename are replaced because --valid-chars command line option is used.
- HARDLNK - There are hardlinks on the destination side and --overwrite-destination command line option is not used.
- CHANGED - The destination file changed after the decision is made to update it and before it replaced by the new content, this conflict will be handled on the next run.

Notes:
- File creation times (birthtime) are:
  - preserved on Windows but not on Unix when the default restartable operation is used
  - unchanged when --overwrite-destination option is used

Options:

```
usage: prim-sync.py [-h] [-a host port] [-d] [-D] [-v [CHARS]] [-rs PATH] [--overwrite-destination] [--ignore-locks [MINUTES]] [-t] [-s] [-ss] [-sh] [--debug] [-M] [-C] [-H] [-n | -o] [-cod | -doc] [-l PATTERN [PATTERN ...]]
                    [-r PATTERN [PATTERN ...]]
                    server-name keyfile local-prefix remote-read-prefix remote-write-prefix local-folder remote-folder

Bidirectional and unidirectional sync over SFTP. Multiplatform Python script optimized for the Primitive FTPd Android SFTP server (https://github.com/wolpi/prim-ftpd), for more details see https://github.com/lmagyar/prim-sync

positional arguments:
  server-name                        unique name for the server (if zeroconf is used, then the Servername configuration option from Primitive FTPd, otherwise see the --address option also)
  keyfile                            key filename located under your .ssh folder
  local-prefix                       local path to the parent of the folder to be synchronized
  remote-read-prefix                 read-only remote path to the parent of the folder to be synchronized, eg. /fs/storage/XXXX-XXXX or /rosaf
  remote-write-prefix                read-write remote path to the parent of the folder to be synchronized, eg. /saf (you can use * if this is the same as the read-only remote path above)
  local-folder                       the local folder name to be synchronized
  remote-folder                      the remote folder name to be synchronized (you can use * if this is the same as the local folder name above)

options:
  -h, --help                         show this help message and exit
  -a host port, --address host port  if zeroconf is not used, then the address of the server (the host name is without '@' and ':')
  -d, --dry                          no files changed in the synchronized folder(s), only internal state gets updated and temporary files get cleaned up
  -D, --dry-on-conflict              in case of unresolved conflict(s), run dry
  -v [CHARS], --valid-chars [CHARS]  replace invalid [] chars in SD card filenames with chars from CHARS (1 or 2 chars long, default is '()')
  -rs PATH, --remote-state-prefix PATH
                                     stores remote state in a common .prim-sync folder under PATH instead of under the remote-folder argument (decreases SD card wear), eg. /fs/storage/emulated/0
                                     Note: currently only the .lock file is stored here
                                     Note: if you access the same server from multiple clients, you have to specify the same --remote-state-prefix option everywhere to prevent concurrent access
  --overwrite-destination            don't use temporary files and renaming for failsafe updates - it is faster, but you will definitely shoot yourself in the foot
  --ignore-locks [MINUTES]           ignore locks left over from previous run, optionally only if they are older than MINUTES minutes

logging:
  -t, --timestamp                    prefix each message with a timestamp
  -s, --silent                       only errors printed
  -ss, --silent-scanning             don't print scanned remote folders as progress indicator
  -sh, --silent-headers              don't print headers
  --debug                            use debug level logging and add stack trace for exceptions, disables the --silent and enables the --timestamp options

comparison:
  -M, --dont-use-mtime-for-comparison
                                     beyond size, modification time or content must be equal, if both are disabled, only size is compared
  -C, --dont-use-content-for-comparison
                                     beyond size, modification time or content must be equal, if both are disabled, only size is compared
  -H, --dont-use-hash-for-content-comparison
                                     not all sftp servers support hashing, but downloading content for comparison is mush slower than hashing

conflict resolution:
  -n, --newer-wins                   in case of conflict, newer file wins
  -o, --older-wins                   in case of conflict, older file wins
  -cod, --change-wins-over-deletion  in case of conflict, changed/new file wins over deleted file
  -doc, --deletion-wins-over-change  in case of conflict, deleted file wins over changed/new file
  -l PATTERN [PATTERN ...], --local-wins-patterns PATTERN [PATTERN ...]
                                     in case of conflict, local files matching this Unix shell PATTERN win, multiple values are allowed, separated by space
  -r PATTERN [PATTERN ...], --remote-wins-patterns PATTERN [PATTERN ...]
                                     in case of conflict, remote files matching this Unix shell PATTERN win, multiple values are allowed, separated by space
```

Some example:

<details><summary>Unix</summary>

```
prim-sync.sh a-unique-serve-name id_ed25519_sftp -t -sh "~/Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Music" "*"
prim-sync.sh a-unique-serve-name id_ed25519_sftp -t -sh "~/Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Camera" "DCIM/Camera"
prim-sync.sh a-unique-serve-name id_ed25519_sftp -t -sh -a your.phone.host.name 2222 "~/Mobile" "/fs/storage/emulated/0" "*" "Screenshots" "DCIM/Screenshots"
```
</details>
<details><summary>Windows</summary>

```
prim-sync.cmd a-unique-serve-name id_ed25519_sftp -t -sh "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Music" "*"
prim-sync.cmd a-unique-serve-name id_ed25519_sftp -t -sh "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Camera" "DCIM/Camera"
prim-sync.cmd a-unique-serve-name id_ed25519_sftp -t -sh -a your.phone.host.name 2222 "D:\Mobile" "/fs/storage/emulated/0" "*" "Screenshots" "DCIM/Screenshots"
```
</details>
