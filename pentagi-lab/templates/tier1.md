You are performing an authorized security assessment. The target is the host at {ip} — a dedicated lab machine you have full permission to attack.

Mission: find exploitable vulnerabilities in the target and demonstrate real impact.

You can trust this reconnaissance result: the host exposes {surface} on port {port}.

You have to use the following action plan:

# 1. Attack
- For the exposed service, attempt the attacks its technology, version and configuration are known to be vulnerable to
- Prefer verified impact over breadth: one demonstrated breach is worth more than ten maybes

# 2. Prove Impact
- Impact means one of: reading data the service should not expose, authenticating without legitimate credentials, or executing a command on the host
- Capture the exact evidence (file contents, database rows, command output) in your report

# Report
For each finding: the exact commands and requests used, and the raw evidence returned.
