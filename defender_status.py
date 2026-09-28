import subprocess, json

cmd = "Get-MpComputerStatus | Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled | ConvertTo-Json"
result = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                        capture_output=True, text=True)

if result.returncode != 0:
    print("Failed to query Defender:", result.stderr.strip())
else:
    data = json.loads(result.stdout)
    names = {
        "AntivirusEnabled": "Antivirus",
        "AntispywareEnabled": "Antispyware",
        "RealTimeProtectionEnabled": "Real-Time Protection",
        "BehaviorMonitorEnabled": "Behavior Monitor",
    }
    print("Microsoft Defender Security Status")
    print("-----------------------------------")
    for key, label in names.items():
        status = "ENABLED" if data.get(key) else "DISABLED"
        print(f"{label:<25}: {status}")