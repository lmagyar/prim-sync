
# Primitive Sync

Bidirectional and unidirectional sync over SFTP. Multiplatform Python script optimized for the [Primitive FTPd Android SFTP server](https://github.com/wolpi/prim-ftpd) (required minimum version is 7.3).

Why another sync solution? Because none of the professional solutions can write SD cards and follow local symlinks, or are extremely slow or full of bugs (Syncthing, Resilio Sync, rsync, osync, rclone, Unison). I gave up and wrote it.

See my other project, https://github.com/lmagyar/prim-ctrl, for remote control of your phone's Primitive FTPd SFTP server and optionally Tailscale VPN.

See my other project, https://github.com/lmagyar/prim-batch, for batch execution of prim-ctrl and prim-sync commands.

**Note:** These are my first ever Python projects, any comments on how to make them better are appreciated.

## Features

- Follow local symlinks
- Hash files for fast comparison
- Write SD card (with Primitive FTPd and Storage Access Framework)
- Dual access in case of SD card (reading plain-old file-system for fast scan and download, and writing with the slower Storage Access Framework)
- Failsafe, restartable operation (costs some time, renames on SD card are slow)
- Connect through zeroconf (DNS-SD)
- Handle FAT timezone and DST offset changes (FAT32 or exFAT SD card)

### Notes on following local symlinks

- File symlinks just work
- File hardlinks are OK for unidirectional outward sync, but have to use --overwrite-destination option in case of bidirectional or unidirectional inward sync
  - Better not to use file hardlinks, use symlinks
- Folder symlinks or junctions are OK for unidirectional outward sync, but be **very-very-very** careful with bidirectional or unidirectional inward sync
  - If you have a folder symlink and you think you delete files on your phone under the symlinked folder, or even you delete the symlinked folder, because "they are only under a symlink", you shoot yourself in the foot
  - Syncing file deletions means file deletions synced first, then the containing folder deletion synced
  - So first all the files will be deleted in the symlink **target** folder, then the folder symlink itself will be deleted, though the target folder is not deleted
  - So symlinking the family picture albums' folder better done with an unidirectional outward sync
  - Or symlink only the files if you enable deletion on the phone
  - You have been warned!

## Installation

You need to install:
- Primitive FTPd on your phone - see: https://github.com/wolpi/prim-ftpd

  **Install from [F-Droid](https://f-droid.org/app/org.primftpd) (not from Google Play) (required minimum version is 7.3)**

- Python 3.12+, pip and venv on your laptop - see: https://www.python.org/downloads/ or
  <details><summary>Ubuntu</summary>

  ```
  sudo apt update
  sudo apt upgrade
  sudo apt install python3 python3-pip python3-venv
  ```
  </details>
  <details><summary>Windows</summary>

  - Install from Microsoft Store the latest [Python 3](https://apps.microsoft.com/search?query=python+3&department=Apps) (search), [Python 3.12](https://www.microsoft.com/store/productId/9NCVDN91XZQP) (App)
  - Install from Winget: `winget install Python.Python.3.12`
  - Install from Chocolatey: `choco install python3 -y`
  </details>

- pipx - see: https://pipx.pypa.io/stable/installation/#installing-pipx or
  <details><summary>Ubuntu</summary>

  ```
  sudo apt install pipx
  pipx ensurepath
  ```
  </details>
  <details><summary>Windows</summary>

  ```
  py -m pip install --user pipx
  py -m pipx ensurepath
  ```
  </details>

- This repo
  ```
  pipx install prim-sync
  ```

Optionally, if you want to edit or even contribute to the source, you also need to install:
- poetry - see: https://python-poetry.org/
  ```
  pipx install poetry
  ```

## Configuration

### Android

You have to enable Primitive FTPd to run as much in the background as possible, please see the relevant [Readme section](https://github.com/wolpi/prim-ftpd#running-in-the-background).

### Networking

Either use the built-in zeroconf (DNS-SD) functionality in Primitive FTPd (see below), or set up a constant address (IP or host name, for the -a option) for your phone (fixed LAN IP, VPN, hosts file, your choice).

### Primitive FTPd

- Home tab
  - Select "Virtual folders" and follow the relevant [Readme section](https://github.com/wolpi/prim-ftpd#external-sd-card-readwrite-access---android-storage-access-framework)
- Configuration tab
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
    - Server Start Directory: eg. /storage/emulated/0
    - Prevent Standby: enable
    - Announce server in LAN: enable if you use zeroconf (DNS-SD)
    - Servername: eg. your-phone-pftpd - make it unique, even if you don't use zeroconf, especially when multiple phones are synced, because this will be used as unique identifier to store the per-device-sync-state between runs
    - SFTP Hostkey algorithms: enable at least ed25519
    - Other options can be left unchanged
- Stop the server (if you have started)
- Close and restart the whole app
- Start the server

### SSH keys

You need to generate an SSH key pair:

<details><summary>Ubuntu</summary>

- Execute:
  ```
  sudo apt install openssh-client
  mkdir ~/.ssh
  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_sftp -N ""
  ```

  **Note:** See below later, how to protect the private SSH key with passphrase.
</details>
<details><summary>Windows</summary>

- Go to _Settings / System / Optional features / Add an optional feature_ and add "OpenSSH Client"
- Execute:
  ```
  mkdir %USERPROFILE%\.ssh
  ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\id_ed25519_sftp -N ""
  ```

  **Note:** See below later, how to protect the private SSH key with passphrase.
</details>

Then install it in Primitive FTPd:
- Use your favorite SFTP client (eg. WinSCP, FileZilla) to access the Primitive FTPd, use username/password to authenticate.

  **Note:** Even if you plan to access Primitive FTPd through zeroconf (DNS-SD), use it's hostname or IP to connect to it at this step.
- Open for editing the `/fs/storage/emulated/0/Android/data/org.primftpd/files/.ssh/authorized_keys` file.
- Append the content of the previously generated `.ssh/id_ed25519_sftp.pub` file to it. It is something like "ssh-ed25519 XXXxxxXXXxxx you@your-device"

Then add your phone to the known_hosts file if your favorite SFTP client hasn't done it:
- Use ssh to access the Primitive FTPd, use username/password to authenticate.

  **Note:** Even if you plan to access Primitive FTPd through zeroconf (DNS-SD), use it's hostname or IP to connect to it at this step.
  <details><summary>Ubuntu</summary>

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

If you plan to access Primitive FTPd through zeroconf (DNS-SD):
- Use your favorite text editor to open the known_hosts file updated in the previous step
- Locate the line for your server that looks sg. like:
  ```
  [your.phone.host.name]:2222 ssh-ed25519 XXXxxxXXXxxx
  ```
- Replace the `[your.phone.host.name]:2222` text with the Primitive FTPd Servername configuration option, see above (that is sg. like `your-phone-pftpd`), so it will look sg. like:
  ```
  your-phone-pftpd ssh-ed25519 XXXxxxXXXxxx
  ```
- Note: If you plan to access Primitive FTPd additionally through -a option also (ie. through VPN), you can have only this single line in your known_hosts file for both connection type.
- Reason: zeroconf (DNS-SD) and SSH don't mix well, SSH uses hostname and DNS-SD uses service name (on a host), but the SSH client in prim-sync is modified to be able to connect to and accept keys from hosts that are identified with the DNS-SD service name (Primitive FTPd Servername configuration option).

### Primitive FTPd again

- Configuration tab:
  - Authentication
      - Password: delete it
      - Public Key Authentication: enable
- Stop the server
- Close and restart the whole app
- Start the server

### Optionally protecting the private SSH key with passphrase

We can protect the private SSH key generated above with a passphrase and use the ssh-agent to store the unprotected key in memory and help the SSH client in prim-sync to authenticate with Primitive FTPd.

<details><summary>Ubuntu</summary>

- Protect the already generated key with a passphrase:

  ```
  ssh-keygen -p -f ~/.ssh/id_ed25519_sftp
  ```

- Install ssh-agent as a systemd service:

  [How to start and use ssh-agent as systemd service?](https://unix.stackexchange.com/a/390631/548885)

  **Note:** Identities that you've added ***will not be*** available after reboot.

- Useful commands:

  ```
  ssh-add ~/.ssh/id_ed25519_sftp     # Adds private key identities to the agent
  ssh-add -L                         # Lists public key parameters of all identities currently represented by the agent
  ssh-add -d ~/.ssh/id_ed25519_sftp  # Removes private key identities from the agent
  ```
</details>
<details><summary>Windows</summary>

- Protect the already generated key with a passphrase:

  ```
  ssh-keygen -p -f %USERPROFILE%\.ssh\id_ed25519_sftp
  ```

- Start ssh-agent (OpenSSH Authentication Agent) automatically as a service (use an administrative PowerShell terminal):

  ```
  Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
  ```

  **Note:** Identities that you've added ***will be*** available even after reboot.

- Useful commands:

  ```
  ssh-add %USERPROFILE%\.ssh\id_ed25519_sftp     # Adds private key identities to the agent
  ssh-add -L                                     # Lists public key parameters of all identities currently represented by the agent
  ssh-add -d %USERPROFILE%\.ssh\id_ed25519_sftp  # Removes private key identities from the agent
  ```
</details>

## Usage

Create a backup of your files!!! Really!!! If you use symlinks, this is only question of time when will you delete something unintendedly!!!

The first upload is better done over USB connection and manual copy, because copying files over Wi-Fi is much slower.

The first run will be longer than a regular run, because without prior knowledge, the prim-sync script handles all files on both sides as newly created and compares them or their hashes (hashing is much faster than downloading and comparing the content).

On regular runs the meaning of the log lines are:
- Scanning - Name of the remote folder that is scanned (only remote is logged, remote is the bottleneck)
- Comparing, Hashing - Comparing the content or the hash of the files on the two sides.
- <<< !!! >>> - Conflicting changes that are not resolved by any command line option, the details are in the next line.
- RECOVER - The previous run failed (probably network/connection problem), and there are intermediate/leftover files that are deleted on the next (ie. this) run.
- HARDLNK - There are hardlinks on the destination side and --overwrite-destination command line option is not used.
- SYMLINK - There are folder symlinks or junctions on the destination side and --folder-symlink-as-destination command line option is not used.
- CHANGED - The destination file changed after the decision is made to update it and before it replaced by the new content, this conflict will be handled on the next run.

Notes:
- In the log lines the left side is the Local and the right side is the Remote
- Local file creation times (birthtime) are:
  - preserved on Windows but not on Unix when the default restartable operation is used
  - unchanged when --overwrite-destination option is used
- Files in the remote folder and it's subfolders must be on the same filesystem (ie. do not mix FAT and non-FAT filesystems, the prim-sync script assumes the FAT timezone or DST offset changes are the same for all files under the remote folder)
- You can brainwash (ie. delete the state under the .prim-sync folder) between two runs. After this, the script will behave, as if the next run is the first run (see "first run" above).
- Never ever delete any files where the name ends with .prim-sync.new or .tmp or .old, the pure existence of these files are the "transaction state", if you delete any of these files, the recovery algorythm won't be able to figure out in which phase got the restartable operation interrupted. If you delete any of these files, you are on your own to figure out how to recover from the interruption.

### Some example

<details><summary>Ubuntu</summary>

```
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" "~/Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Camera" "DCIM/Camera"
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" -uo -m --overwrite-destination "~/Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Music" "*"
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" -a your.phone.host.name 2222 "~/Mobile" "/fs/storage/emulated/0" "*" "Screenshots" "DCIM/Screenshots"
```
</details>
<details><summary>Windows</summary>

```
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Camera" "DCIM/Camera"
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" -uo -m --overwrite-destination "D:\Mobile" "/fs/storage/XXXX-XXXX" "/saf" "Music" "*"
prim-sync your-phone-pftpd id_ed25519_sftp -t -sh -rs "/fs/storage/emulated/0" -a your.phone.host.name 2222 "D:\Mobile" "/fs/storage/emulated/0" "*" "Screenshots" "DCIM/Screenshots"
```
</details>

### Options

```
usage: prim-sync [-h] [-a host port] [-ui | -uo] [-d] [-D] [-rs PATH] [--overwrite-destination] [--folder-symlink-as-destination] [--ignore-locks [MINUTES]] [-t] [-s] [-ss] [-sh] [--debug] [-M] [-C] [-H]
                 [-n | -o] [-cod | -doc] [-l [PATTERN ...]] [-r [PATTERN ...]] [-m [PATTERN ...]]
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
  -a host port, --address host port  if zeroconf is not used, then the address of the server
  -ui, --unidirectional-inward       unidirectional inward sync (default is bidirectional sync)
  -uo, --unidirectional-outward      unidirectional outward sync (default is bidirectional sync)
  -d, --dry                          no files changed in the synchronized folder(s), only internal state gets updated and temporary files get cleaned up
  -D, --dry-on-conflict              in case of unresolved conflict(s), run dry
  -rs PATH, --remote-state-prefix PATH
                                     stores remote state in a common .prim-sync folder under PATH instead of under the remote-folder argument (decreases SD card wear), eg. /fs/storage/emulated/0
                                     Note: currently only the .lock file is stored here
                                     Note: if you access the same server from multiple clients, you have to specify the same --remote-state-prefix option everywhere to prevent concurrent access
  --overwrite-destination            don't use temporary files and renaming for failsafe updates - it is faster, but you will definitely shoot yourself in the foot when used with bidirectional sync
  --folder-symlink-as-destination    enables writing and deleting symlinked folders and files in them on the local side - it can make sense, but you will definitely shoot yourself in the foot
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

bidirectional conflict resolution:
  -n, --newer-wins                   in case of conflict, newer file wins
  -o, --older-wins                   in case of conflict, older file wins
  -cod, --change-wins-over-deletion  in case of conflict, changed/new file wins over deleted file
  -doc, --deletion-wins-over-change  in case of conflict, deleted file wins over changed/new file
  -l [PATTERN ...], --local-wins-patterns [PATTERN ...]
                                     in case of conflict, local files matching this Unix shell PATTERN win, multiple values are allowed, separated by space
                                     if no PATTERN is specified, local always wins
  -r [PATTERN ...], --remote-wins-patterns [PATTERN ...]
                                     in case of conflict, remote files matching this Unix shell PATTERN win, multiple values are allowed, separated by space
                                     if no PATTERN is specified, remote always wins

unidirectional conflict resolution:
  -m [PATTERN ...], --mirror-patterns [PATTERN ...]
                                     in case of conflict, mirror source side files matching this Unix shell PATTERN to destination side, multiple values are allowed, separated by space
                                     if no PATTERN is specified, all files will be mirrored
```
