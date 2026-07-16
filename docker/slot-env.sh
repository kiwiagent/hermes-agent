#!/bin/sh
# Resolve the active managed slot and export its runtime environment.
# shellcheck shell=sh
set -eu

HERMES_INSTALL_ROOT="${HERMES_INSTALL_ROOT:-/opt/hermes}"
current_file="$HERMES_INSTALL_ROOT/current.txt"
[ -r "$current_file" ] || {
    echo "hermes: managed current.txt is missing: $current_file" >&2
    return 1 2>/dev/null || exit 1
}
HERMES_SLOT_VERSION=$(tr -d '\r\n' < "$current_file")
case "$HERMES_SLOT_VERSION" in
    ''|*/*|*'..'*)
        echo "hermes: invalid managed slot in $current_file" >&2
        return 1 2>/dev/null || exit 1
        ;;
esac
HERMES_SLOT_ROOT="$HERMES_INSTALL_ROOT/versions/$HERMES_SLOT_VERSION"
HERMES_SLOT_VENV="$HERMES_SLOT_ROOT/runtime/venv"
HERMES_SLOT_PYTHON="$HERMES_SLOT_VENV/bin/python"
[ -x "$HERMES_SLOT_PYTHON" ] || {
    echo "hermes: active slot runtime is missing: $HERMES_SLOT_PYTHON" >&2
    return 1 2>/dev/null || exit 1
}

export HERMES_SLOT_VERSION HERMES_SLOT_ROOT HERMES_SLOT_VENV HERMES_SLOT_PYTHON
export VIRTUAL_ENV="$HERMES_SLOT_VENV"
export UV_PYTHON="$HERMES_SLOT_PYTHON"
export UV_NO_CONFIG=1
unset PYTHONHOME PYTHONPATH
PATH="$HERMES_INSTALL_ROOT/bin:$HERMES_SLOT_VENV/bin:$HERMES_SLOT_ROOT/runtime/tools:$HERMES_SLOT_ROOT/runtime/node/bin:$HERMES_SLOT_ROOT/runtime/python/bin:${PATH:-}"
export PATH
