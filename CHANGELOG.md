# Changelog

## 0.8.6

- Extend error message on broken symlinks

## 0.8.5

- Refactor exception logging arguments

## 0.8.4

- Rerelease

## 0.8.3

- Fix folder name path separator in logs

## 0.8.2

- Fix hashing/comapring log message priority

## 0.8.1

- Fix hashing on timestamp change for unidir sync

## 0.8.0

- Hash if size equals and only timestamp is changed on one side
- Add folder name before relative path in logs

## 0.7.3

- Update help and readme

## 0.7.2

- Refactor caching, logging

## 0.7.1

- Refactor exception logging
- Update dependencies

## 0.7.0

- Handle timezone offset and DST changes on remote FAT filesystems
- Drop reading the old state storage format
- Do not mention my forked prim-ftpd, PR-s got merged in the original repo
- Remove --valid-chars option
- Add documentation about using ssh-agent for passphrases
- Update dependencies

## 0.6.0

- Remove server-name validation for prim-ftpd and --dont-validate-server-name option

## 0.5.2

- Fix zeroconf (DNS-SD) service name resolution in known_hosts file
- Update Python installation in Readme

## 0.5.1

- Mention in the error message to turn on Android screen, when DNS-SD queries time out

## 0.5.0

- Update dependencies

## 0.4.0

- Add server-name validation for prim-ftpd and --dont-validate-server-name option
- Rename --mirror to --mirror-patterns
- Add --folder-symlink-as-destination
- Log "Running dry" only when there is something not to execute
- Publish on PyPI
- Use python-poetry

## 0.3.0

- Update dependencies

## 0.2.0

- Enable -l and -r (--local-wins-patterns and --remote-wins-patterns) options without pattern, meaning always wins

## 0.1.0

- Initial upload
