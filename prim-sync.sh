#!/bin/bash
if [[ "${OSTYPE:-}" == "cygwin" || "${OSTYPE:-}" == "msys" ]] ; then
    venv_python_path="Scripts/python.exe"
else
    venv_python_path="bin/python"
fi
${0%/*}/.venv/${venv_python_path} ${0%/*}/prim-sync.py "$@"
