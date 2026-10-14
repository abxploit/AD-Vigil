# AD Vigil — Active Directory Security Assessment & Purple Team Platform

**Find the weakness. Detect the activity. Strengthen the domain.**

AD Vigil is an authorized-lab Active Directory security assessment and Purple Team platform focused on inventory, security configuration analysis, evidence collection, defensive detection, and correlation.

## Phase 1

The current foundation includes:

- A PySide6 desktop shell with connection configuration and assessment status.
- Typed configuration and input validation.
- Structured application logging.
- LDAP connection handling with no credential persistence.
- Read-only paged inventory of users, groups, computers, domain controllers, and SPNs.

Advanced attack functionality, destructive actions, persistence, and automatic exploitation are intentionally not included.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

The application accepts credentials at runtime and does not write passwords to configuration or scan results.

## Directory and protocol assessment

The existing assessment also includes read-only discovery and review for:

- Organizational Units: paged OU inventory, derived parent/child placement, associations to already-collected users/groups/computers, direct GPO links, and an optional DACL-only security-descriptor read. DACL records distinguish allow/deny ACEs and inheritance flags. Permission findings are ACE observations, not a complete effective-access calculation.
- Domain trusts: local `trustedDomain` objects under `CN=System`, decoded direction/type/attribute flags, and preserved unknown bits. Trust partners are not contacted or authenticated to.
- Protocols: unauthenticated LDAP/LDAPS/SMB reachability checks, certificate-verified LDAPS negotiation, and anonymous SMB2/3 negotiate metadata. The SMB dependency is declared in `requirements.txt`.

Coverage for OU discovery, OU DACL retrieval, trust discovery, and protocol checks is recorded separately in Overview and Scan History. Missing or inaccessible attributes are unknown, not clean. LDAP signing and channel-binding requirements are not inferred from a successful bind. The tool does not send credentials during its protocol checks, probe SMBv1 with a downgrade, authenticate to SMB shares, or access NETLOGON. SYSVOL access coverage is reused from the existing bounded GPO content check under the current Windows process identity.

The OU inventory has a configurable `max_ous` service limit (default 3,000); incomplete results report a limit or partial status. Network probes have short per-connection timeouts and honor cooperative cancellation between probes. `Registry.pol`, complete effective policy processing, partner-domain inspection, forest topology beyond locally visible trusts, and effective ACL evaluation are not currently implemented.

## Live-lab validation checklist

Run only in an authorized lab and verify the following against known-good expected configuration:

1. Compare OU counts, hierarchy, direct links, and known DACLs with approved AD administration tools; test with both sufficient and restricted read permissions.
2. Compare trust direction/type/attributes with the domain's documented trust configuration; confirm the tool does not attempt partner authentication.
3. Test LDAP/LDAPS using a valid certificate, an expired certificate, and a hostname mismatch. Confirm no real password is sent by any probe.
4. Test SMB with SMB signing required and optional, plus SMB unavailable/refused. Confirm output separates reachability, negotiation, and signing-required evidence.
5. Stop scans during OU discovery, trust discovery, and protocol probes; confirm partial coverage is retained, connections close, and progress never reports completion early.
6. Confirm SYSVOL/NETLOGON limitations and unavailable settings remain unassessed rather than reported as secure.

No live-domain validation is implied by the automated test results.

## Purple Team telemetry and correlation

The Purple Team tab imports JSON, JSON Lines/NDJSON, CSV, and Windows Event XML exports without executing input files. UTF-8 and BOM-marked UTF-16 are supported. Imports are capped at 64 MiB and 100,000 records; malformed JSONL rows are reported while valid records are retained. Event fields with explicit timezone information are normalized to UTC; timezone-naive timestamps remain incomplete rather than being assigned a guessed timezone. Records missing event IDs/timestamps retain a partial parse status, credential-bearing fields and quoted or unquoted command-line assignments are redacted, and duplicate event records are skipped. Coverage records source format/name, channels, event IDs, time range, parse errors, incomplete records, and partial status.

EVTX is not supported in this build: `python-evtx` was not available in the inspected environment and no EVTX parser was added. Export the required Windows channels to XML or CSV before import.

The initial rule set groups repeated 4625 failures by target account, host, source IP, and logon type; correlates a same-key 4624 after repeated failures; records privileged group changes (4728/4729/4732/4733/4756/4757) and account creation (4720); flags selected PowerShell indicators (4103/4104/4688/Sysmon 1); and reviews conservative 4768/4769 Kerberos indicators. A new account followed by a matching privileged-group addition within 24 hours receives a separate investigation alert. Alerts are evidence references and investigative leads, not proof of compromise or malicious intent. The failure threshold (default 5) and time window (default 10 minutes) are configurable in the dashboard.

Purple Team correlations appear both in the new tab and in the existing Finding details panel. States distinguish Not evaluated, Telemetry unavailable, No matching events observed, Matching events found, and Inconclusive. No-match means only that the imported data did not produce a match; it is not evidence that the behavior did not occur. A synthetic demo button creates clearly labeled in-memory sample events for demonstrations without contacting AD or executing commands.

The “Load synthetic demo” button creates clearly labeled in-memory sample events; it does not contact AD or execute commands. “Export JSON report” combines assessment scope/counts, AD findings, alert summaries/event references, log-source coverage, and finding correlations. It deliberately excludes normalized raw event payloads and complete command lines. Review exported AD finding evidence for appropriateness before sharing reports.

## Test

```powershell
pytest
```

Use only against Active Directory environments where you have explicit authorization.
