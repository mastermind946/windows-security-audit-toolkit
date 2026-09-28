import json
import os
import subprocess
import sys

POWERSHELL = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)

# [string] cast makes the output "True"/"False"/"NotConfigured" instead of an enum number
COMMAND = (
    "Get-NetFirewallProfile | "
    "Select-Object Name, @{n='Enabled';e={[string]$_.Enabled}} | "
    "ConvertTo-Json"
)

STATUS_MAP = {"True": "ENABLED", "False": "DISABLED"}


def get_firewall_profiles():
    """Return {profile_name: status}, or None if the query failed."""
    try:
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", COMMAND],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        print("PowerShell not found. This script only works on Windows.")
        return None
    except subprocess.TimeoutExpired:
        print("Firewall query timed out.")
        return None

    if result.returncode != 0:
        print("Failed to check Windows Firewall.")
        print(result.stderr.strip())
        return None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Could not parse firewall output.")
        return None

    if isinstance(data, dict):  # a single profile comes back as an object, not a list
        data = [data]

    return {
        item["Name"]: STATUS_MAP.get(item["Enabled"], "UNKNOWN")
        for item in data
    }


def check_firewall():
    profiles = get_firewall_profiles()
    if profiles is None:
        return 2

    statuses = list(profiles.values())
    enabled = statuses.count("ENABLED")
    disabled = statuses.count("DISABLED")
    unknown = statuses.count("UNKNOWN")

    print()
    print("========================================")
    print("       WINDOWS FIREWALL CHECKER")
    print("========================================")

    for name, status in profiles.items():
        print(f"{name.capitalize() + ' Profile':<16}: {status}")

    print("----------------------------------------")
    print(f"Profiles Checked : {len(statuses)}")
    print(f"Enabled          : {enabled}")
    print(f"Disabled         : {disabled}")
    print(f"Unknown          : {unknown}")
    print("----------------------------------------")

    if unknown > 0:
        print("Result           : COULD NOT VERIFY")
        code = 2
    elif disabled > 0:
        print("Result           : ATTENTION REQUIRED")
        code = 1
    else:
        print("Result           : FIREWALL ENABLED")
        code = 0

    print("========================================")
    return code


if __name__ == "__main__":
    sys.exit(check_firewall())