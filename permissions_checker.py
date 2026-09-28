import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

POWERSHELL = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)

EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".com", ".scr", ".msi", ".dll", ".vbs",
}

# Well-known SIDs are identical on every Windows language.
BROAD_GROUPS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
}

WRITE_RIGHTS = {
    "FullControl", "Modify", "Write", "WriteData", "CreateFiles",
    "AppendData", "CreateDirectories", "Delete",
    "DeleteSubdirectoriesAndFiles", "ChangePermissions", "TakeOwnership",
}
# Numeric form: generic all/write, write data, append, delete child, delete,
# write DAC, write owner.
WRITE_MASK = 0x10000000 | 0x40000000 | 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000

PS_SCRIPT = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
try {
    $item = Get-Item -LiteralPath $env:AUDIT_PATH -Force
    if ($item.PSIsContainer) { $items = @(Get-ChildItem -LiteralPath $item.FullName -Force) }
    else { $items = @($item) }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 3
}
$items | ForEach-Object {
    $full = $_.FullName
    $isDir = [bool]$_.PSIsContainer
    try {
        $acl = Get-Acl -LiteralPath $full
        $aces = @($acl.Access | ForEach-Object {
            $ace = $_
            $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { [string]$ace.IdentityReference }
            [pscustomobject]@{
                Sid = $sid
                Rights = [string]$ace.FileSystemRights
                Type = [string]$ace.AccessControlType
                PropagationFlags = [string]$ace.PropagationFlags
            }
        })
        [pscustomobject]@{ Path = $full; IsDir = $isDir; Aces = $aces; Error = $null }
    } catch {
        [pscustomobject]@{ Path = $full; IsDir = $isDir; Aces = @(); Error = $_.Exception.Message }
    }
} | ConvertTo-Json -Depth 4
"""


def query_acls(path):
    """Return a list of ACL entries for the path, or None on failure."""
    env = dict(os.environ, AUDIT_PATH=str(path))
    try:
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, env=env,
        )
    except FileNotFoundError:
        print("PowerShell not found. This script only works on Windows.")
        return None
    except subprocess.TimeoutExpired:
        print("Permission query timed out.")
        return None

    if result.returncode != 0:
        print("Could not read permissions.")
        print(result.stderr.strip())
        return None

    output = result.stdout.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print("Could not parse permission data.")
        return None
    return [data] if isinstance(data, dict) else data


def has_write_access(rights):
    rights = rights.strip()
    try:
        return bool(int(rights) & 0xFFFFFFFF & WRITE_MASK)
    except ValueError:
        return any(r.strip() in WRITE_RIGHTS for r in rights.split(","))


def analyze(entry):
    """Return (status, findings) for one file or directory."""
    if entry.get("Error"):
        return "UNKNOWN", [f"Could not read ACL: {entry['Error']}"]

    path = Path(entry["Path"])
    is_executable = not entry["IsDir"] and path.suffix.lower() in EXECUTABLE_EXTENSIONS

    aces = entry.get("Aces") or []
    if isinstance(aces, dict):
        aces = [aces]

    findings = []
    for ace in aces:
        if ace["Type"] != "Allow":
            continue
        if "InheritOnly" in ace["PropagationFlags"]:  # applies to children only
            continue
        group = BROAD_GROUPS.get(ace["Sid"])
        if group and has_write_access(ace["Rights"]):
            findings.append(f"{group} can write/modify ({ace['Rights']})")

    if not findings:
        return "PASS", []
    return ("FAIL" if is_executable else "WARN"), findings


def run(path=None, show_all=False):
    print("=" * 60)
    print("   PERMISSION CHECKER (broad write access)")
    print("=" * 60)

    if not path:
        print("\nEnter the file or directory to check.")
        path = input("Path: ")
    path = path.strip().strip('"')

    if not path:
        print("\nNo path provided.")
        return 2
    if path.startswith(("\\\\", "//")):
        print("\nNetwork (UNC) paths are not allowed.")
        return 2

    target = Path(path)
    if not target.exists():
        print("\nThe specified path does not exist.")
        return 2

    entries = query_acls(target)
    if entries is None:
        return 2
    if not entries:
        print("\nNothing to check (directory is empty).")
        return 0

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "UNKNOWN": 0}
    for entry in entries:
        status, findings = analyze(entry)
        counts[status] += 1
        if status == "PASS" and not show_all:
            continue
        kind = "DIR " if entry["IsDir"] else "FILE"
        print(f"\n[{status}] {kind} {Path(entry['Path']).name}")
        for finding in findings:
            print(f"        - {finding}")

    print("\n" + "-" * 60)
    print(f"Checked: {len(entries)}   Pass: {counts['PASS']}   Warn: {counts['WARN']}"
          f"   Fail: {counts['FAIL']}   Unknown: {counts['UNKNOWN']}")

    if counts["FAIL"] or counts["WARN"]:
        print("Result: ATTENTION REQUIRED")
        return 1
    if counts["UNKNOWN"]:
        print("Result: COULD NOT VERIFY SOME ITEMS")
        return 2
    print("Result: NO BROAD WRITE PERMISSIONS FOUND")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Read-only check for files/folders that broad groups can modify."
    )
    parser.add_argument("path", nargs="?", help="File or directory (prompted if omitted)")
    parser.add_argument("--all", action="store_true", help="also list items with no findings")
    args = parser.parse_args()
    return run(args.path, args.all)


if __name__ == "__main__":
    sys.exit(main())

