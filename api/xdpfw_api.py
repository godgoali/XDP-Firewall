#!/usr/bin/env python3
"""Simple REST API for managing XDP Firewall rules.

This script exposes minimal endpoints for adding and deleting
filter rules using the existing ``xdpfw-add`` and ``xdpfw-del``
CLI utilities.

Dependencies: ``Flask``. Install via ``pip install flask``.
"""

from flask import Flask, request, jsonify
import subprocess
import shutil

app = Flask(__name__)

ADD_BIN = shutil.which("xdpfw-add") or "/usr/bin/xdpfw-add"
DEL_BIN = shutil.which("xdpfw-del") or "/usr/bin/xdpfw-del"


def run_cmd(cmd):
    """Execute command and capture output."""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


@app.route("/filters", methods=["POST"])
def add_filter():
    """Add a filter rule via ``xdpfw-add``."""
    data = request.get_json(force=True) or {}
    args = []
    for key, value in data.items():
        if isinstance(value, bool):
            value = int(value)
        args.append(f"--{key.replace('_', '-')}={value}")

    cmd = f"{ADD_BIN} " + " ".join(args)
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        return jsonify({"error": err.strip()}), 400
    return jsonify({"result": out.strip()})


@app.route("/filters/<int:idx>", methods=["DELETE"])
def delete_filter(idx):
    """Delete a filter rule via ``xdpfw-del``."""
    cmd = f"{DEL_BIN} --idx={idx}"
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        return jsonify({"error": err.strip()}), 400
    return jsonify({"result": out.strip()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
