import os
import subprocess
import sys

NET = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "net.exe")


def num(value):
    try:
        return int(value)
    except ValueError:
        return None


# Each check returns True (pass), False (fail) or None (can't tell).
def min_length_ok(v):
    n = num(v)
    return None if n is None else n >= 14


def max_age_ok(v):
    n = num(v)
    if n is None:
        return False if v.lower() == "unlimited" else None
    return 0 < n <= 365


def history_ok(v):
    n = num(v)
    if n is None:
        return False if v.lower() == "none" else None
    return n >= 24


def threshold_ok(v):
    n = num(v)
    if n is None:
        return False if v.lower() == "never" else None
    return 1 <= n <= 5


def duration_ok(v):
    if v.lower() == "never":  # locked until an admin unlocks it
        return True
    n = num(v)
    return None if n is None else n >= 15


def window_ok(v):
    n = num(v)
    return None if n is None else n >= 15


# (section, label, key from `net accounts`, unit, check, requirement text)
CHECKS = [
    ("Password Policy", "Minimum length", "Minimum password length", "chars", min_length_ok, ">= 14"),
    ("Password Policy", "Maximum age", "Maximum password age (days)", "days", max_age_ok, "1-365"),
    ("Password Policy", "History", "Length of password history maintained", "passwords", history_ok, ">= 24"),
    ("Account Lockout", "Lockout threshold", "Lockout threshold", "attempts", threshold_ok, "1-5"),
    ("Account Lockout", "Lockout duration", "Lockout duration (minutes)", "min", duration_ok, ">= 15"),
    ("Account Lockout", "Observation window", "Lockout observation window (minutes)", "min", window_ok, ">= 15"),
]


def read_policy():
    """Return the parsed `net accounts` output as a dict, or None on failure."""
    try:
        result = subprocess.run(
            [NET, "accounts"], capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        print("net.exe not found. This script only works on Windows.")
        return None
    except subprocess.TimeoutExpired:
        print("Policy query timed out.")
        return None

    if result.returncode != 0:
        print("Could not read local policy.")
        print(result.stderr.strip())
        return None

    policy = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        policy[key.strip()] = value.strip()
    return policy


def get_local_policy():
    policy = read_policy()
    if policy is None:
        return 2

    print("===== LOCAL POLICY CHECK =====")
    passed = failed = unknown = 0
    current_section = None

    for section, label, key, unit, check, requirement in CHECKS:
        if section != current_section:
            print(f"\n[{section}]")
            current_section = section

        value = policy.get(key)
        outcome = check(value) if value is not None else None

        if outcome is True:
            tag, passed = "[PASS]", passed + 1
        elif outcome is False:
            tag, failed = "[FAIL]", failed + 1
        else:
            tag, unknown = "[????]", unknown + 1

        shown = value if value is not None else "not found"
        print(f"{tag} {label:<20}: {shown:<10} (required: {requirement} {unit})")

    print("\n------------------------------")
    print(f"Passed: {passed}   Failed: {failed}   Unverified: {unknown}")

    if failed > 0:
        print("Result: ATTENTION REQUIRED")
        return 1
    if unknown > 0:
        print("Result: COULD NOT VERIFY (non-English Windows or unexpected output?)")
        return 2
    print("Result: POLICY MEETS REQUIREMENTS")
    return 0


if __name__ == "__main__":
    sys.exit(get_local_policy())





