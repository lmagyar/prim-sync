# Changelog

## vNext

- Handle timezone offset changes on remote FAT filesystems
- Drop reading the old state storage format

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
