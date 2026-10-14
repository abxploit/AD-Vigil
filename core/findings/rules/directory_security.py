"""OU and trust findings that require directly collected evidence."""

from typing import Any

from core.findings.rules.common import make_finding
from core.models import Finding, Severity


def analyze_ou_security(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for ou in data.get("ous", []):
        dn = str(ou.get("distinguishedName") or "")
        name = str(ou.get("name") or dn or "Unknown OU")
        if not dn:
            continue
        links = ou.get("direct_gpo_links", [])
        if not links:
            findings.append(make_finding(
                "AD-OU-001", dn,
                title="OU has no directly linked GPO observed",
                severity=Severity.INFO,
                category="OU Security",
                affected_object=name,
                affected_type="Organizational Unit",
                description="No direct gPLink value was collected for this OU. This does not establish that the OU has no effective policy; parent inheritance and processing conditions were not evaluated.",
                evidence={"ou_dn": dn, "gPLink": ou.get("gPLink"), "gPOptions": ou.get("gPOptions")},
                impact="Policy coverage for objects in this OU cannot be inferred from direct links alone.",
                remediation="Review the intended Group Policy design and effective policy on representative systems.",
                confidence="High",
                source_attributes=["gPLink", "gPOptions"],
                raw_evidence={"source_attributes": ou.get("source_attributes", {})},
                detection_limitations="This is a linked-policy observation only; inheritance, security filtering, WMI filters, and client processing were not calculated.",
            ))
        if not str(ou.get("description") or "").strip():
            findings.append(make_finding(
                "AD-OU-002", dn,
                title="OU has no description recorded",
                severity=Severity.INFO,
                category="OU Security",
                affected_object=name,
                affected_type="Organizational Unit",
                description="The OU description attribute was missing or empty. This is an inventory-quality observation, not a vulnerability.",
                evidence={"ou_dn": dn, "description": ou.get("description")},
                impact="Missing documentation can make delegated administration and ownership less clear.",
                remediation="Add an accurate description and owner through the organization's change process if useful.",
                confidence="High",
                source_attributes=["description"],
                raw_evidence={"source_attributes": ou.get("source_attributes", {})},
            ))
        privileged = ou.get("privileged_objects", [])
        if privileged:
            findings.append(make_finding(
                "AD-OU-003", dn,
                title="OU contains privileged directory objects",
                severity=Severity.INFO,
                category="OU Security",
                affected_object=name,
                affected_type="Organizational Unit",
                description="Collected inventory associates privileged users, groups, or domain controllers with this OU.",
                evidence={"ou_dn": dn, "privileged_objects": privileged},
                impact="Administrative OU placement merits review of delegation and change controls.",
                remediation="Review OU ownership, delegated rights, and change monitoring for these objects.",
                confidence="Medium",
                source_attributes=["distinguishedName", "memberOf", "objectClass"],
                raw_evidence={"privileged_objects": privileged},
                detection_limitations="Membership is derived from the collected inventory and direct memberOf values; nested and primary-group membership may be incomplete.",
            ))
        descriptor = ou.get("security_descriptor")
        if not isinstance(descriptor, dict):
            continue
        if descriptor.get("dacl_state") == "Null DACL":
            findings.append(make_finding(
                "AD-OU-004", dn,
                title="OU security descriptor has a null DACL",
                severity=Severity.HIGH,
                category="OU Security",
                affected_object=name,
                affected_type="Organizational Unit",
                description="The retrieved self-relative security descriptor indicates no DACL is present, which permits broad access under Windows DACL semantics.",
                evidence={"ou_dn": dn, "dacl_state": "Null DACL"},
                impact="A null DACL can allow principals broad access to the OU and its objects, subject to object-specific processing.",
                remediation="Restore an approved restrictive DACL after validating delegated administration requirements.",
                confidence="High",
                source_attributes=["nTSecurityDescriptor"],
                raw_evidence={"dacl_state": "Null DACL"},
            ))
        for ace in descriptor.get("aces", []):
            if ace.get("type") not in {"allow", "allow_object"} or not _broad_principal(str(ace.get("sid", ""))):
                continue
            sensitive = sorted(set(ace.get("rights", [])) & {
                "generic_all", "generic_write", "write_dacl", "write_owner", "create_child",
                "delete_child", "write_property", "delete_tree", "control_access", "reset_password",
            })
            if not sensitive:
                continue
            findings.append(make_finding(
                "AD-OU-005", f"{dn}|{ace.get('sid')}|{ace.get('mask')}|{ace.get('object_guid')}",
                title="Broad principal has potentially sensitive OU access rights",
                severity=Severity.MEDIUM,
                category="OU Security",
                affected_object=name,
                affected_type="Organizational Unit",
                description=f"A collected allow ACE for {ace.get('sid')} contains {', '.join(sensitive)}. This is an ACE-level observation, not a complete effective-access calculation.",
                evidence={"ou_dn": dn, "ace": ace, "security_descriptor_status": ou.get("security_descriptor_status")},
                impact="If applicable after inheritance and deny ACE evaluation, these rights may allow broad modification of directory objects or permissions.",
                remediation="Review the delegated access with the OU owner and remove excessive rights using the organization's approved ACL process.",
                confidence="Medium",
                source_attributes=["nTSecurityDescriptor"],
                raw_evidence={"ace": ace},
                detection_limitations="ACE inheritance scope, object-specific property sets, deny ACE interactions, and effective access were not fully evaluated.",
            ))
    return findings


def analyze_trust_security(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for trust in data.get("trusts", []):
        partner = str(trust.get("trustPartner") or trust.get("distinguishedName") or "Unknown trust partner")
        dn = str(trust.get("distinguishedName") or partner)
        if trust.get("is_external") is True:
            findings.append(make_finding(
                "AD-TR-001", dn,
                title="External trust relationship observed",
                severity=Severity.INFO,
                category="Trust Security",
                affected_object=partner,
                affected_type="Domain Trust",
                description="The trustedDomain attributes identify a downlevel/external trust or mark it as treat-as-external. This warrants context review but is not by itself a vulnerability.",
                evidence=_trust_evidence(trust),
                impact="Trusts expand the administrative boundary and should match documented business and security requirements.",
                remediation="Confirm the relationship is expected, scoped, monitored, and governed by current trust policy.",
                confidence="High",
                source_attributes=["trustPartner", "trustType", "trustAttributes"],
                raw_evidence={"source_attributes": trust.get("source_attributes", {})},
                detection_limitations=trust.get("limitations", "Partner domain was not inspected."),
            ))
            if trust.get("sid_filtering_enabled") is False:
                findings.append(make_finding(
                    "AD-TR-002", dn,
                    title="External trust does not indicate SID filtering enabled",
                    severity=Severity.MEDIUM,
                    category="Trust Security",
                    affected_object=partner,
                    affected_type="Domain Trust",
                    description="The trust type/attributes indicate an external trust, but the quarantined-domain SID-filtering flag is absent.",
                    evidence=_trust_evidence(trust),
                    impact="Without SID filtering, foreign SIDs may be treated differently across the trust boundary, depending on trust configuration and platform behavior.",
                    remediation="Verify the intended SID-filtering configuration using supported domain trust administration tools and enable the organization's required protections.",
                    confidence="Medium",
                    source_attributes=["trustType", "trustAttributes"],
                    raw_evidence={"source_attributes": trust.get("source_attributes", {})},
                    detection_limitations="The finding is based only on the local trustedDomain flags; partner-side configuration and effective authentication behavior were not checked.",
                ))
    return findings


def analyze_protocol_security(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for protocol in data.get("protocols", []):
        check = str(protocol.get("check", ""))
        status = str(protocol.get("status", ""))
        rule_id = ""
        title = ""
        severity = Severity.INFO
        description = ""
        impact = ""
        remediation = ""
        if check == "Configured LDAP client transport" and status == "Plain LDAP configured":
            rule_id = "AD-PR-001"
            title = "Configured LDAP connection is not TLS protected"
            description = "The current assessment connection is configured for LDAP without TLS. This describes the client transport only; it does not establish the server's signing or channel-binding policy, and does not prove that a password was transmitted in clear text."
            impact = "Without transport encryption, LDAP traffic may be observable or exposed to network manipulation depending on the authentication mechanism and network path."
            remediation = "Use LDAPS or a correctly validated StartTLS connection for authenticated LDAP operations where supported."
        elif check == "LDAPS TLS/636" and status == "Certificate validation failed":
            rule_id = "AD-PR-002"
            title = "LDAPS certificate validation failed"
            severity = Severity.MEDIUM
            description = "The TLS handshake to the target failed the operating system trust-chain or hostname validation. The TLS endpoint identity is therefore unverified."
            impact = "Clients cannot reliably authenticate the LDAPS endpoint identity, increasing exposure to interception or misdirection."
            remediation = "Install a valid certificate for the domain controller hostname with a trusted chain and correct validity period."
        elif (
            check == "SMB negotiation"
            and status == "Negotiated"
            and protocol.get("signing_required") is False
        ):
            rule_id = "AD-PR-003"
            title = (
                "SMB signing is supported but not required"
                if protocol.get("signing_supported") is True
                else "SMB signing is not offered or required"
            )
            severity = Severity.MEDIUM
            description = (
                "The unauthenticated SMB2/SMB3 negotiate response advertised signing support without the signing-required bit."
                if protocol.get("signing_supported") is True
                else "The unauthenticated SMB2/SMB3 negotiate response did not advertise signing support or require signing."
            )
            impact = "SMB sessions may not be required to provide message integrity, depending on client policy and session negotiation."
            remediation = "Review server and client SMB signing policy and require signing where compatible with the organization's security baseline."
        if not rule_id:
            continue
        evidence = {
            key: protocol.get(key)
            for key in (
                "check", "status", "port", "target_hostname", "target_ip", "evidence_source",
                "dialect", "signing_supported", "signing_required", "tls_version", "cipher",
                "certificate_validation", "error_type",
            )
            if key in protocol
        }
        evidence.setdefault("evidence_source", "Not recorded")
        findings.append(make_finding(
            rule_id,
            f"{protocol.get('target_ip', protocol.get('port', 'configured'))}|{check}",
            title=title,
            severity=severity,
            category="Protocol Security",
            affected_object=str(protocol.get("target_hostname") or protocol.get("target_ip") or "Configured service"),
            affected_type="Host Service",
            description=description,
            evidence={**evidence, "expected_behavior": remediation, "assessment_status": status},
            impact=impact,
            remediation=remediation,
            confidence="High" if check != "Configured LDAP client transport" else "High",
            source_attributes=["protocol negotiation", "client connection configuration"],
            raw_evidence=dict(protocol),
            detection_limitations=(
                "This observation is limited to the stated connection or negotiation response. "
                "Unreported server configuration remains unknown; no authentication or downgrade test was performed."
            ),
        ))
    return findings


def _broad_principal(sid: str) -> bool:
    normalized = sid.casefold()
    return normalized in {"s-1-1-0", "s-1-5-11", "s-1-5-32-545"} or normalized.endswith("-513")


def _trust_evidence(trust: dict[str, Any]) -> dict[str, Any]:
    return {
        key: trust.get(key)
        for key in (
            "source_domain", "target_domain", "trustDirection", "direction", "trustType", "type",
            "trustAttributes", "attribute_flags", "unknown_attribute_bits", "transitive",
            "sid_filtering_enabled", "selective_authentication_indicated", "distinguishedName",
        )
    }