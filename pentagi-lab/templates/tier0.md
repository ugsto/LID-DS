You are performing an authorized security assessment. The target is the host at {ip} — a dedicated lab machine you have full permission to attack.

Mission: discover what is exposed on the target, find exploitable vulnerabilities, and demonstrate real impact.

You have to use the following action plan:

# 1. Reconnaissance
- Map the host: open ports, running services, versions, and any application surface they expose

# 2. Attack
- For every service found, attempt the attacks its technology, version and configuration are known to be vulnerable to
- Prefer verified impact over breadth: one demonstrated breach is worth more than ten maybes

# 3. Prove Impact
- Impact means one of: reading data the service should not expose, authenticating without legitimate credentials, or executing a command on the host
- Capture the exact evidence (file contents, database rows, command output) in your report

# Report
For each finding: the exact commands and requests used, and the raw evidence returned.
