# Safety & scope

This is authorized academic coursework: a self-contained lab for **detecting and
mitigating** availability attacks in a containerized environment. It is
defensive in purpose.

- **Isolated by construction.** All services run on a private Docker bridge
  network. The only published ports are the dashboard and the local victim
  entrypoint, for your own testing.
- **The victim is intentionally vulnerable** (pinned pre-patch Tomcat). Treat it
  as radioactive: never expose it to a shared or untrusted network, never run it
  on a public host.
- **The attack client is lab-fenced.** `attacker/attack.py` refuses any target
  that does not resolve to a loopback/RFC-1918 private address or a lab service
  name. There is intentionally no override flag.
- **Only attack your own victim.** These techniques are illegal and harmful used
  against systems you do not own or have explicit written authorization to test.

CVEs reproduced for study: CVE-2023-44487 (Rapid Reset) and CVE-2025-8671
(MadeYouReset). Both are public, vendor-disclosed vulnerabilities with available
fixes; this lab pins pre-patch versions solely to study detection and mitigation.
