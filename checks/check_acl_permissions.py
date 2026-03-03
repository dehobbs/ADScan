"""
checks/check_acl_permissions.py - ACL / Permissions checks

Checks:
  - ESC4  : Certificate template write ACL (enroll + write = full control)       -20
  - ESC5  : PKI object ACL abuse (CA/template/OID container ACLs)                -15
  - ESC7  : CA Officer / CA Manager abuse                                        -15
  - DCSync: Non-privileged principals with DS-Replication rights                 -25
  - Protected Users: Group existence and membership                              -5
  - Delegation ACLs: Accounts with AllowedToActOnBehalfOfOtherIdentity set       -10
"""

CHECK_NAME = "ACL / Permissions"
CHECK_ORDER = 15

def run_check(connector, verbose=False):
    findings = []

    pki_base = "CN=Public Key Services,CN=Services,CN=Configuration," + connector.base_dn
    schema_base = "CN=Schema,CN=Configuration," + connector.base_dn

    # ESC4: Certificate template write ACL
    try:
        templates = connector.ldap_search(
            "CN=Certificate Templates," + pki_base,
            "(objectClass=pKICertificateTemplate)",
            ["cn", "nTSecurityDescriptor"],
            scope="ONELEVEL",
        ) or []
        dangerous_templates = []
        for t in templates:
            name = t.get("cn", "Unknown")
            sd = t.get("nTSecurityDescriptor")
            if sd:
                sd_str = str(sd) if not isinstance(sd, str) else sd
                if any(kw in sd_str for kw in ("WriteDacl", "WriteOwner", "WriteProperty", "GenericWrite", "GenericAll")):
                    dangerous_templates.append(name)
        if dangerous_templates:
            findings.append({
                "title": "ESC4 - Certificate Template Write ACL",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    f"{len(dangerous_templates)} certificate template(s) have overly permissive ACLs "
                    "that allow non-privileged principals to modify enrollment settings "
                    "(ESC4 ADCS escalation path)."
                ),
                "recommendation": (
                    "Review certificate template ACLs. Remove Write/GenericAll permissions "
                    "from non-administrative accounts. Use Manage CA or Manage Certificates "
                    "roles only for authorised PKI administrators."
                ),
                "details": dangerous_templates,
            })
    except Exception as exc:
        if verbose:
            print(f"[ACL] ESC4 check error: {exc}")

    # ESC5: PKI object ACL abuse
    try:
        pki_containers = [
            ("Certification Authorities", "CN=Certification Authorities," + pki_base),
            ("Enrollment Services", "CN=Enrollment Services," + pki_base),
            ("OID Container", "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration," + connector.base_dn),
        ]
        esc5_issues = []
        for label, dn in pki_containers:
            try:
                objs = connector.ldap_search(dn, "(objectClass=*)", ["cn", "nTSecurityDescriptor"], scope="BASE") or []
                for o in objs:
                    sd = o.get("nTSecurityDescriptor")
                    if sd:
                        sd_str = str(sd) if not isinstance(sd, str) else sd
                        if any(kw in sd_str for kw in ("WriteDacl", "WriteOwner", "GenericAll", "GenericWrite")):
                            esc5_issues.append(label)
                            break
            except Exception:
                pass
        if esc5_issues:
            findings.append({
                "title": "ESC5 - PKI Object ACL Abuse",
                "severity": "high",
                "deduction": 15,
                "description": (
                    "One or more PKI containers have dangerous ACL entries that could allow "
                    "privilege escalation via ADCS (ESC5). "
                    f"Affected containers: {', '.join(esc5_issues)}."
                ),
                "recommendation": (
                    "Review and harden ACLs on Certification Authorities, Enrollment Services, "
                    "and OID containers. Only Enterprise Admins should have write access."
                ),
                "details": esc5_issues,
            })
    except Exception as exc:
        if verbose:
            print(f"[ACL] ESC5 check error: {exc}")

    # ESC7: CA Officer / CA Manager abuse
    try:
        cas = connector.ldap_search(
            "CN=Enrollment Services," + pki_base,
            "(objectClass=pKIEnrollmentService)",
            ["cn", "nTSecurityDescriptor"],
            scope="ONELEVEL",
        ) or []
        esc7_cas = []
        for ca in cas:
            sd = ca.get("nTSecurityDescriptor")
            if sd:
                sd_str = str(sd) if not isinstance(sd, str) else sd
                if "ManageCertificates" in sd_str or "ManageCA" in sd_str:
                    esc7_cas.append(ca.get("cn", "Unknown CA"))
        if esc7_cas:
            findings.append({
                "title": "ESC7 - CA Officer / CA Manager ACL Misconfiguration",
                "severity": "high",
                "deduction": 15,
                "description": (
                    f"{len(esc7_cas)} CA(s) may expose CA Officer or CA Manager permissions "
                    "to unintended principals (ESC7 ADCS escalation path)."
                ),
                "recommendation": (
                    "Audit Manage CA and Manage Certificates ACEs on each CA. "
                    "These roles allow approving pending certificate requests and can be "
                    "abused to obtain Domain Controller or Domain Admin certificates."
                ),
                "details": esc7_cas,
            })
    except Exception as exc:
        if verbose:
            print(f"[ACL] ESC7 check error: {exc}")

    # DCSync: Non-privileged principals with DS-Replication rights
    try:
        domain_obj = connector.ldap_search(
            connector.base_dn, "(objectClass=*)", ["nTSecurityDescriptor"], scope="BASE"
        ) or []
        dcsync_principals = []
        ds_repl_guids = [
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
        ]
        for obj in domain_obj:
            sd = obj.get("nTSecurityDescriptor")
            if sd:
                sd_str = str(sd) if not isinstance(sd, str) else sd
                for guid in ds_repl_guids:
                    if guid.lower() in sd_str.lower():
                        dcsync_principals.append(f"Replication right detected (GUID {guid[:8]}...)")
                        break
        if dcsync_principals:
            findings.append({
                "title": "DCSync Rights Detected on Domain Object",
                "severity": "critical",
                "deduction": 25,
                "description": (
                    "DS-Replication-Get-Changes / DS-Replication-Get-Changes-All rights were detected "
                    "on the domain root object. Non-privileged principals with these rights can "
                    "perform DCSync attacks to extract credential hashes for any account."
                ),
                "recommendation": (
                    "Run: Get-ObjectAcl -DistinguishedName <domain_dn> -ResolveGUIDs | "
                    "Where-Object { $_.ObjectType -like '*Replication*' } "
                    "Remove any unexpected DCSync permissions immediately."
                ),
                "details": dcsync_principals,
            })
    except Exception as exc:
        if verbose:
            print(f"[ACL] DCSync check error: {exc}")

    # Protected Users Group
    try:
        pu_groups = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=group)(cn=Protected Users))",
            ["cn", "member"],
        ) or []
        if not pu_groups:
            findings.append({
                "title": "Protected Users Group Not Populated",
                "severity": "low",
                "deduction": 5,
                "description": (
                    "The Protected Users security group exists in Windows Server 2012R2+ domains "
                    "but appears to have no members. Privileged accounts should be placed in this "
                    "group to restrict credential exposure."
                ),
                "recommendation": (
                    "Add all Domain Admins, Enterprise Admins, and other highly privileged accounts "
                    "to the Protected Users group. Test for service disruption before mass migration."
                ),
                "details": [],
            })
        else:
            members = pu_groups[0].get("member", [])
            if not members:
                findings.append({
                    "title": "Protected Users Group Is Empty",
                    "severity": "low",
                    "deduction": 5,
                    "description": (
                        "The Protected Users group exists but contains no members. "
                        "Privileged accounts are not benefiting from its credential-theft mitigations."
                    ),
                    "recommendation": (
                        "Populate Protected Users with all tier-0 accounts: Domain Admins, "
                        "Enterprise Admins, Schema Admins, krbtgt, and key service accounts."
                    ),
                    "details": [],
                })
    except Exception as exc:
        if verbose:
            print(f"[ACL] Protected Users check error: {exc}")

    # Delegation ACLs: AllowedToActOnBehalfOfOtherIdentity
    try:
        rbcd_accounts = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            ["cn", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        ) or []
        if rbcd_accounts:
            names = [a.get("cn", "Unknown") for a in rbcd_accounts]
            findings.append({
                "title": "Resource-Based Constrained Delegation (RBCD) Configured",
                "severity": "medium",
                "deduction": 10,
                "description": (
                    f"{len(rbcd_accounts)} computer account(s) have "
                    "msDS-AllowedToActOnBehalfOfOtherIdentity set, enabling RBCD. "
                    "If the trusted principal is attacker-controlled, full compromise of "
                    "the target computer is possible."
                ),
                "recommendation": (
                    "Review each account listed. Remove RBCD settings that are not "
                    "intentionally configured and operationally required."
                ),
                "details": names,
            })
    except Exception as exc:
        if verbose:
            print(f"[ACL] RBCD check error: {exc}")

    return findings
