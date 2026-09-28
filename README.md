# Windows Security Audit Toolkit

A collection of Python scripts that check basic security settings on a Windows machine and report what looks safe and what needs attention.

Uses only Python's built-in libraries, so there is nothing extra to install.

## What It Checks

- `firewall_status.py` - Whether Windows Firewall is enabled for each profile (Domain, Private, Public).
- `defender_status.py` - Windows Defender status: real-time protection, antivirus, and signature updates.
- `local_policy_checker.py` - Local security policy, such as password and account lockout settings.            
- `permissions_checker.py` - Permissions on sensitive files and directories.                                  

## Requirements

- Windows 10 or 11
- Python 3.8 or newer

## Usage

Open PowerShell or Command Prompt, go to the project folder, and run any script.


## Disclaimer

This toolkit only **reads** settings. It does not change anything on your system. It is a learning project and not a replacement for professional security tools. Only run it on machines you own or have permission to audit.

## License

Released under the MIT License. See the `LICENSE` file for details.
