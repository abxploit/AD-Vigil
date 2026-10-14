# AD Vigil

Read-only Active Directory inventory, security findings, and Windows event telemetry correlation for authorized labs.

AD Vigil is a PySide6 desktop application for collecting directory evidence over LDAP and reviewing selected security configurations. It combines inventory and evidence-based finding checks with import and correlation of Windows event exports. It is intended for security engineers, defenders, and Purple Team practitioners working in environments where they have explicit authorization. The Purple Team workflow lets a reviewer compare imported defensive telemetry with assessment findings and inspect event references, making it a combined assessment and defensive review platform rather than an exploitation tool.

## Key features

### Active Directory inventory and findings

- Read-only LDAP inventory of users, groups, computers, domain controllers, and service principal names (SPNs).
- Organizational Unit (OU) hierarchy, object association counts, direct Group Policy links, and optional security descriptor/DACL reads.
- Local `trustedDomain` object discovery and decoded trust direction, type, and attributes. Trust partners are not contacted.
- Group Policy Object discovery, links, and bounded review of selected SYSVOL policy files.
- **15 finding checks** across account security, Kerberos exposure, delegation, privileged membership and service accounts, pre-Windows 2000 access, GPO, OU, trust, and protocol evidence. Findings cite collected evidence; they are not effective-permission calculations.
- Missing or inaccessible data is reported as unknown or incomplete, not clean. A missing match is not proof that an issue is absent.

### Protocol checks

- Credential-free LDAP and LDAPS reachability checks; LDAPS validates the TLS certificate and host name.
- Unauthenticated SMB2/3 negotiation metadata, including advertised signing support and requirement.
- These checks do not send credentials, authenticate to SMB shares, probe SMBv1, or establish LDAP signing or channel-binding policy.

### Purple Team telemetry import and correlation

- Import JSON, JSON Lines (`.jsonl`), NDJSON, CSV, and Windows Event XML (`.xml`) exports. UTF-8 and BOM-marked UTF-16 are supported.
- Imports are bounded to 64 MiB and 100,000 records. Duplicate records are skipped; malformed JSON Lines are reported while valid records are retained.
- **10 detection rules** cover authentication failures and related successful logons, privileged group changes, account creation, selected PowerShell/process indicators, Kerberos indicators, and directory changes.
- Event IDs covered: **1, 4103, 4104, 4624, 4625, 4688, 4720, 4728, 4729, 4732, 4733, 4756, 4757, 4768, 4769, and 5136**. Rule eligibility depends on required fields and channels; an ID alone does not guarantee a rule can evaluate an event.
- Alerts link to source event references. Finding correlation states distinguish unevaluated, unavailable, no observed match, matched, and inconclusive. No match is not proof that activity did not occur.
- EVTX files are unsupported. Export event logs to XML or CSV before importing.

### Reporting

- Export assessment data as JSON; Purple Team JSON reports can include assessment scope/counts, AD findings, alert summaries and event references, source coverage, and finding correlations.
- The combined Purple Team report excludes normalized raw event payloads and complete command lines. Sensitive values are redacted during telemetry normalization and connection error reporting; review AD evidence before sharing any report.

## Screenshots

Capture these four application views and save them at the listed paths:

- `docs/screenshots/main-window.png` — main window showing the assessment workspace.
- `docs/screenshots/findings-panel.png` — findings list and selected finding evidence.
- `docs/screenshots/purple-team-demo.png` — Purple Team tab populated with synthetic demo data.
- `docs/screenshots/exported-report.png` — representative exported JSON report opened in a readable viewer, with sensitive values removed.

## Tech stack and requirements

- Python: the project does not declare a minimum version; the test run documented below used Python 3.11.9.
- PySide6 for the desktop UI, `ldap3` for LDAP, and `smbprotocol` for SMB negotiation.
- Other declared dependencies: `pycryptodome`; development/package dependencies: `pytest` and `pyinstaller` (see `requirements.txt`).

## Project structure

```text
main.py                         Qt application entry point
config/settings.py              Runtime connection settings
core/connection.py              LDAP connection compatibility exports
core/ldap_connection.py         Read-only LDAP connection handling
core/scanner.py                 Assessment orchestration and inventory
core/ou_assessment.py           OU and DACL collection
core/gpo_assessment.py          GPO discovery and bounded policy review
core/trust_assessment.py        Local trust discovery and decoding
core/protocol_assessment.py     LDAP/LDAPS/SMB checks
core/findings/                  Evidence-based AD finding engine and rules
core/telemetry.py               Event import, normalization, and redaction
core/defensive_detections.py    Telemetry detection rules
core/purple_team.py             Alert, finding correlation, and JSON report logic
core/security_report.py         Assessment report generation
gui/                            PySide6 windows and result views
utils/                          Validators and logging
tests/                          Automated unit and UI tests
```

The repository contains 53 Python files in total: 37 application files and 16 test files (excluding generated environments and caches).

## Installation and run

From the project directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Credentials are supplied at runtime. Passwords are not written to configuration or scan results.

## Quick demo without Active Directory

1. Start the application with `python main.py`.
2. Open the Purple Team tab.
3. Select **Load synthetic demo**.
4. Review the clearly labeled in-memory sample events, generated alerts, and finding correlations.

The demo does not connect to AD, read a log file, or execute commands.

## Safety and design principles

- Directory collection and assessment are read-only; protocol probes do not send credentials.
- Credentials are runtime inputs and are not persisted by the application.
- Telemetry normalization redacts credential-bearing fields and common quoted or unquoted secret assignments. The combined Purple Team export omits raw normalized event payloads and complete command lines.
- No exploitation, persistence, or destructive actions are implemented. Use only in environments where you have explicit authorization.

## Known limitations and not implemented

- No effective ACL evaluation. DACL output consists of collected ACE observations; it does not calculate a principal's effective rights.
- Unknown or inaccessible attributes remain unknown. No matching telemetry means only that the imported data produced no match; neither state means clean.
- EVTX parsing, `Registry.pol` parsing, complete effective Group Policy processing, partner-domain inspection, and forest topology beyond locally visible trusts are not implemented.
- Protocol checks do not infer LDAP signing or channel-binding requirements from a successful bind. SMB results are limited to unauthenticated reachability and negotiation evidence.
- SYSVOL coverage comes from a bounded check of selected GPO content under the current Windows process identity; NETLOGON is not accessed.
- Synthetic demo data and automated tests do not validate behavior against a live domain.

## Live-lab validation checklist

Run these checks only in an authorized lab and compare results with approved administration tools and known configuration:

1. Compare OU counts, hierarchy, direct GPO links, and known DACLs with sufficient and restricted read permissions.
2. Compare local trust direction, type, and attributes with documented settings; verify partner domains are not contacted.
3. Check LDAP/LDAPS with valid, expired, and hostname-mismatched certificates; confirm probes send no password.
4. Check SMB with signing required, optional, unavailable, and refused; distinguish reachability from negotiation evidence.
5. Cancel OU, trust, and protocol operations and verify partial coverage and cleanup.
6. Confirm unavailable SYSVOL/NETLOGON and policy data remain unassessed rather than reported as secure.

Automated tests use controlled test data and mocks. They do not imply live-domain validation.

## Testing

Run:

```powershell
pytest
```

Result from this checkout (Python 3.11.9, pytest 8.4.2): **138 tests collected; 137 passed, 1 failed**. The failure was `test_purple_dashboard_cancel_waits_for_worker_cleanup` in `tests/test_result_views.py`; `cancel_import_and_wait(2000)` returned false. This test-suite result is not evidence of live-domain behavior.

## Roadmap

The current README and implementation identify these possible future work areas: EVTX ingestion, `Registry.pol` parsing, complete effective Group Policy processing, partner-domain inspection, broader forest topology, and effective ACL evaluation. They are not implemented in this build.

## License and author

No license file is present in the repository. Contact the author for licensing terms.

**Author:** Abinesh M — [github.com/abxploit](https://github.com/abxploit)
