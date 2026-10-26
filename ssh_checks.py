def check_ssh_settings(ssh_settings):
    findings = []

    ssh_settings = {
        setting.lower(): str(value).strip().lower()
        for setting, value in ssh_settings.items()
}

    # Check 1: Password authentication
    if ssh_settings.get("passwordauthentication") == "yes":
        findings.append({
            "title": "SSH password authentication is enabled",
            "severity": "Medium",
            "evidence": "passwordauthentication is set to yes",
            "recommendation": (
                "Consider disabling password authentication "
                "and using SSH keys if operationally appropriate."
            )
        })

    # Check 2: Maximum authentication attempts
    try:
        max_attempts = int(ssh_settings["maxauthtries"])

        if max_attempts > 4:
            findings.append({
                "title": "SSH allows many authentication attempts",
                "severity": "Low",
                "evidence": (
                    "maxauthtries is set to " + str(max_attempts)
                ),
                "recommendation": (
                    "Consider reducing MaxAuthTries to 4 or fewer "
                    "if compatible with your environment."
                )
            })

    except (ValueError, TypeError, KeyError):
        findings.append({
            "title": "Unable to evaluate SSH authentication limit",
            "severity": "Informational",
            "evidence": "maxauthtries is missing or is not a number",
            "recommendation": (
                "Review the effective SSH configuration manually."
            )
        })

    # Check 3: Root login
    root_login = ssh_settings.get("permitrootlogin")

    if root_login == "yes":
        findings.append({
            "title": "SSH root login is permitted",
            "severity": "High",
            "evidence": "permitrootlogin is set to yes",
            "recommendation": (
                "Disable direct root login and use a named account "
                "with sudo privileges instead."
            )
        })

    # Check 4: Empty passwords
    if ssh_settings.get("permitemptypasswords") == "yes":
        findings.append({
            "title": "SSH permits empty passwords",
            "severity": "High",
            "evidence": "permitemptypasswords is set to yes",
            "recommendation": (
                "Set PermitEmptyPasswords to no."
            )
        })

    # Check 5: Public-key authentication
    if ssh_settings.get("pubkeyauthentication") != "yes":
        findings.append({
            "title": "SSH public-key authentication is disabled",
            "severity": "Low",
            "evidence": "pubkeyauthentication is not set to yes",
            "recommendation": (
                "Consider enabling public-key authentication "
                "where appropriate."
            )
        })

    return findings