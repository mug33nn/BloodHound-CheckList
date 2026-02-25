# BloodHound Active Directory Enumeration Checklist
## Comprehensive Attack Path & Lateral Movement Analysis

Reference: https://queries.specterops.io/ | SpecterOps BloodHound Query Library

---

## 1. Domain Overview & Reconnaissance

### 1.1 Domain Information
```cypher
MATCH (d:Domain) RETURN d.name, d.functionallevel, d.objectid
```

### 1.2 Domain Trust Mapping
```cypher
MATCH p = (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p
```

### 1.3 All Domain Controllers
```cypher
MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' RETURN c.name, c.operatingsystem
```

### 1.4 Total Object Count (Users, Computers, Groups)
```cypher
MATCH (u:User) RETURN 'Users' AS type, COUNT(u) AS count
UNION
MATCH (c:Computer) RETURN 'Computers' AS type, COUNT(c) AS count
UNION
MATCH (g:Group) RETURN 'Groups' AS type, COUNT(g) AS count
```

---

## 2. Privileged Accounts & Groups

### 2.1 Domain Admins Members (Direct + Nested)
```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' WITH g MATCH p = (u)-[:MemberOf*1..]->(g) RETURN p
```

### 2.2 Enterprise Admins Members
```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-519' WITH g MATCH p = (u)-[:MemberOf*1..]->(g) RETURN p
```

### 2.3 Built-in Administrators Members
```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-544' WITH g MATCH p = (u)-[:MemberOf*1..]->(g) RETURN p
```

### 2.4 High-Value Groups (Server Operators, Account Operators, Backup Operators, Print Operators)
```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-549' OR g.objectid ENDS WITH '-548' OR g.objectid ENDS WITH '-551' OR g.objectid ENDS WITH '-550' WITH g MATCH p = (u)-[:MemberOf*1..]->(g) RETURN g.name, u.name
```

### 2.5 Users with AdminCount=1 (Protected by AdminSDHolder)
```cypher
MATCH (u:User) WHERE u.admincount = true RETURN u.name, u.enabled, u.pwdlastset
```

### 2.6 Users with DCSync Privileges
```cypher
MATCH p = (n)-[:DCSync|GetChanges|GetChangesAll|GetChangesInFilteredSet]->(d:Domain) RETURN p
```

---

## 3. Kerberos Attack Surface

### 3.1 Kerberoastable Users (SPN Set)
```cypher
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name, u.serviceprincipalnames, u.admincount, u.pwdlastset ORDER BY u.pwdlastset ASC
```

### 3.2 Kerberoastable Users with Path to Domain Admin
```cypher
MATCH (u:User {hasspn:true, enabled:true}) MATCH p = shortestPath((u)-[:MemberOf|AdminTo|HasSession|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword|AddMember*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p
```

### 3.3 AS-REP Roastable Users (No Preauth Required)
```cypher
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u.name, u.pwdlastset
```

### 3.4 Unconstrained Delegation — Computers
```cypher
MATCH (c:Computer) WHERE c.unconstraineddelegation = true AND NOT c.name CONTAINS 'DC' RETURN c.name, c.operatingsystem
```

### 3.5 Unconstrained Delegation — Users
```cypher
MATCH (u:User) WHERE u.unconstraineddelegation = true RETURN u.name
```

### 3.6 Constrained Delegation
```cypher
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL AND SIZE(c.allowedtodelegate) > 0 RETURN c.name, c.allowedtodelegate, labels(c)
```

### 3.7 Resource-Based Constrained Delegation (RBCD)
```cypher
MATCH p = (n)-[:AllowedToAct]->(c:Computer) RETURN p
```

---

## 4. Shortest Paths to Domain Admin

### 4.1 Shortest Paths from Owned Principals to Domain Admins
```cypher
MATCH p = shortestPath((n {owned:true})-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p
```

### 4.2 Shortest Paths from Kerberoastable Users to Domain Admins
```cypher
MATCH (u:User {hasspn:true, enabled:true}) MATCH p = shortestPath((u)-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p
```

### 4.3 Shortest Paths to Domain Admins (from All Users)
```cypher
MATCH p = shortestPath((u:User {enabled:true})-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' AND NOT (u)-[:MemberOf*1..]->(g) RETURN p
```

### 4.4 Shortest Paths to High-Value Targets
```cypher
MATCH p = shortestPath((n)-[*1..]->(m {highvalue:true})) WHERE NOT n = m RETURN p
```

### 4.5 Shortest Paths to Domain Controllers
```cypher
MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c) AS dcs MATCH p = shortestPath((n:User {enabled:true})-[*1..]->(dc)) WHERE dc IN dcs AND NOT (n)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@PURPLETEAM.WORK'}) RETURN p
```

---

## 5. Lateral Movement

### 5.1 Computers Where Domain Users Have Local Admin
```cypher
MATCH p = (g:Group)-[:AdminTo]->(c:Computer) WHERE g.objectid ENDS WITH '-513' RETURN p
```

### 5.2 Computers Where Domain Users Can RDP
```cypher
MATCH p = (g:Group)-[:CanRDP]->(c:Computer) WHERE g.objectid ENDS WITH '-513' RETURN p
```

### 5.3 Users with Local Admin on Multiple Computers
```cypher
MATCH (u:User)-[:AdminTo]->(c:Computer) WITH u, COUNT(c) AS adminCount WHERE adminCount > 1 RETURN u.name, adminCount ORDER BY adminCount DESC
```

### 5.4 Domain Admin Sessions on Non-DC Computers
```cypher
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' WITH u MATCH (c:Computer)-[:HasSession]->(u) WHERE NOT (c)-[:MemberOf*1..]->(dc:Group) OR NOT dc.objectid ENDS WITH '-516' RETURN c.name, u.name
```

### 5.5 Computers with Multiple Admins (High-Value Pivot Points)
```cypher
MATCH (u)-[:AdminTo]->(c:Computer) WITH c, COUNT(u) AS adminCount WHERE adminCount > 5 RETURN c.name, adminCount ORDER BY adminCount DESC
```

### 5.6 All Active Sessions
```cypher
MATCH p = (c:Computer)-[:HasSession]->(u:User) RETURN c.name, u.name
```

---

## 6. ACL / DACL Abuse

### 6.1 Users with GenericAll on Other Users
```cypher
MATCH p = (u1:User)-[:GenericAll]->(u2:User) WHERE u1 <> u2 RETURN p
```

### 6.2 Users with GenericWrite on Other Users (Targeted Kerberoast / Shadow Credentials)
```cypher
MATCH p = (u1:User)-[:GenericWrite]->(u2:User) WHERE u1 <> u2 RETURN p
```

### 6.3 Users with WriteDACL on Domain Object
```cypher
MATCH p = (n)-[:WriteDacl]->(d:Domain) RETURN p
```

### 6.4 Users with WriteOwner on Domain Object
```cypher
MATCH p = (n)-[:WriteOwner]->(d:Domain) RETURN p
```

### 6.5 Principals with GenericAll/WriteDACL/WriteOwner on Groups
```cypher
MATCH p = (n)-[:GenericAll|WriteDacl|WriteOwner]->(g:Group) WHERE g.highvalue = true RETURN p
```

### 6.6 Users Who Can Force Change Password
```cypher
MATCH p = (u1)-[:ForceChangePassword]->(u2:User) RETURN p
```

### 6.7 Users with AddMember on Groups
```cypher
MATCH p = (n)-[:AddMember]->(g:Group) WHERE g.highvalue = true RETURN p
```

### 6.8 Principals with AllExtendedRights
```cypher
MATCH p = (n)-[:AllExtendedRights]->(m) RETURN p
```

### 6.9 Owns Relationship Abuse
```cypher
MATCH p = (n)-[:Owns]->(m) WHERE NOT n.name CONTAINS 'ADMIN' RETURN p
```

---

## 7. GPO Abuse

### 7.1 GPOs with Links to OUs Containing High-Value Targets
```cypher
MATCH (gpo:GPO)-[:GpLink]->(ou:OU) MATCH (ou)-[:Contains*1..]->(n {highvalue:true}) RETURN gpo.name, ou.name, n.name
```

### 7.2 Non-Admin Users with Write Access to GPOs
```cypher
MATCH p = (u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(gpo:GPO) WHERE NOT (u)-[:MemberOf*1..]->(g:Group) OR NOT g.objectid ENDS WITH '-512' RETURN p
```

### 7.3 GPOs that Apply to Domain Controllers OU
```cypher
MATCH (gpo:GPO)-[:GpLink]->(ou:OU) WHERE ou.name =~ '(?i).*domain controllers.*' RETURN gpo.name, ou.name
```

---

## 8. ADCS (Active Directory Certificate Services)

### 8.1 All Enterprise CAs
```cypher
MATCH (eca:EnterpriseCA) RETURN eca.name, eca.caname, eca.dnsname
```

### 8.2 ESC1 — Enrollee Supplies Subject + Client Auth + No Manager Approval
```cypher
MATCH p = ()-[:Enroll|AllExtendedRights|GenericAll]->(ct:CertTemplate) WHERE ct.enrolleesuppliessubject = true AND ct.authenticationenabled = true AND ct.requiresmanagerapproval = false AND ct.enabled = true RETURN p
```

### 8.3 ESC1 — Full Chain (Template → CA → NTAuth → Domain)
```cypher
MATCH (ct:CertTemplate) WHERE ct.enrolleesuppliessubject = true AND ct.authenticationenabled = true AND ct.requiresmanagerapproval = false AND ct.enabled = true MATCH (eca:EnterpriseCA)-[:PublishedTo]->(ct) MATCH p1 = ()-[:Enroll]->(ct) MATCH p2 = (eca)-[:TrustedForNTAuth]->(:NTAuthStore)-[:NTAuthStoreFor]->(d:Domain) RETURN ct.name, eca.name, d.name
```

### 8.4 ESC2 — Any Purpose EKU or No EKU
```cypher
MATCH (ct:CertTemplate) WHERE ct.enabled = true AND (ct.ekus IS NULL OR SIZE(ct.ekus) = 0 OR ANY(eku IN ct.ekus WHERE eku = '2.5.29.37.0')) AND ct.requiresmanagerapproval = false MATCH p = ()-[:Enroll|AllExtendedRights|GenericAll]->(ct) RETURN p
```

### 8.5 ESC3 — Enrollment Agent Templates
```cypher
MATCH (ct:CertTemplate) WHERE ct.enabled = true AND ct.requiresmanagerapproval = false AND ANY(eku IN ct.ekus WHERE eku = '1.3.6.1.4.1.311.20.2.1') MATCH p = ()-[:Enroll|AllExtendedRights|GenericAll]->(ct) RETURN p
```

### 8.6 ESC4 — Write Access to Certificate Templates
```cypher
MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(ct:CertTemplate) WHERE ct.enabled = true RETURN p
```

### 8.7 ESC6 — Check EDITF_ATTRIBUTESUBJECTALTNAME2
*Note: Check via command line on CA server*
```
certutil -config "CA_SERVER\CA_NAME" -getreg "policy\EditFlags"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA_NAME" /v EditFlags
```
*Check CBA enforcement:*
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA_NAME" /v StrongCertificateBindingEnforcement
```
*Values: 0=disabled, 1=compatibility mode, 2=full enforcement (ESC6 blocked)*

### 8.8 ESC7 — ManageCA / Manage Certificates Privileges
```cypher
MATCH p = (n)-[:ManageCA|ManageCertificates]->(eca:EnterpriseCA) RETURN p
```
*Also via command line:*
```
certutil -config "CA_SERVER\CA_NAME" -getacl
```

### 8.9 ESC8 — HTTP Enrollment Endpoints (NTLM Relay)
```cypher
MATCH (eca:EnterpriseCA) WHERE eca.webenrollmenturi IS NOT NULL RETURN eca.name, eca.webenrollmenturi
```

### 8.10 Principals with Enrollment Rights on CAs
```cypher
MATCH p = ()-[:Enroll]->(eca:EnterpriseCA) RETURN p
```

### 8.11 Enterprise CAs Trusted for NT Authentication
```cypher
MATCH p = (:EnterpriseCA)-[:TrustedForNTAuth]->(:NTAuthStore)-[:NTAuthStoreFor]->(:Domain) RETURN p
```

---

## 9. Password & Credential Hygiene

### 9.1 Users with Password Never Expires
```cypher
MATCH (u:User) WHERE u.pwdneverexpires = true AND u.enabled = true RETURN u.name, u.pwdlastset, u.admincount ORDER BY u.pwdlastset ASC
```

### 9.2 Users with Password Not Required
```cypher
MATCH (u:User) WHERE u.passwordnotreqd = true AND u.enabled = true RETURN u.name
```

### 9.3 Users with Old Passwords (>365 days)
```cypher
MATCH (u:User) WHERE u.enabled = true AND u.pwdlastset < (datetime().epochSeconds - 31536000) RETURN u.name, datetime({epochSeconds: toInteger(u.pwdlastset)}) AS pwdlastset ORDER BY u.pwdlastset ASC
```

### 9.4 Users Who Never Logged In
```cypher
MATCH (u:User) WHERE u.enabled = true AND u.lastlogon IS NULL RETURN u.name
```

### 9.5 Enabled Users with Reversible Encryption
```cypher
MATCH (u:User) WHERE u.enabled = true AND u.userpassword IS NOT NULL RETURN u.name
```

### 9.6 Users Storing Passwords in Description Field
```cypher
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description =~ '(?i).*(pass|pwd|cred|key|secret).*' RETURN u.name, u.description
```

---

## 10. Computer Hygiene & Attack Surface

### 10.1 Computers with Obsolete Operating Systems
```cypher
MATCH (c:Computer) WHERE c.operatingsystem =~ '(?i).*(2003|2008|xp|vista|windows 7|windows 8).*' AND c.enabled = true RETURN c.name, c.operatingsystem, c.lastlogontimestamp ORDER BY c.lastlogontimestamp DESC
```

### 10.2 Computers with LAPS Not Enabled
```cypher
MATCH (c:Computer) WHERE c.haslaps = false AND c.enabled = true RETURN c.name, c.operatingsystem
```

### 10.3 Computers Not Logged In >90 Days (Stale)
```cypher
MATCH (c:Computer) WHERE c.enabled = true AND c.lastlogontimestamp < (datetime().epochSeconds - 7776000) RETURN c.name, datetime({epochSeconds: toInteger(c.lastlogontimestamp)}) AS lastlogon ORDER BY c.lastlogontimestamp ASC
```

---

## 11. gMSA & Service Accounts

### 11.1 gMSA Accounts and Who Can Read Their Passwords
```cypher
MATCH p = (n)-[:ReadGMSAPassword]->(m) RETURN p
```

### 11.2 gMSA with Unconstrained Delegation
```cypher
MATCH (n)-[:ReadGMSAPassword]->(m) WHERE m.unconstraineddelegation = true RETURN n.name, m.name
```

---

## 12. Cross-Domain & Forest Trusts

### 12.1 All Domain Trusts
```cypher
MATCH p = (d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN d1.name, d2.name, p
```

### 12.2 Foreign Group Membership
```cypher
MATCH p = (u)-[:MemberOf]->(g:Group) WHERE u.domain <> g.domain RETURN u.name, u.domain, g.name, g.domain
```

### 12.3 Users from External Domains with Admin Access
```cypher
MATCH (u)-[:AdminTo]->(c:Computer) WHERE u.domain <> c.domain RETURN u.name, u.domain, c.name, c.domain
```

---

## 13. Post-Compromise Analysis (After Owning Principals)

### 13.1 Mark Compromised Principals as Owned
*In BloodHound GUI: Right-click node → Mark as Owned*
*Or via Cypher:*
```cypher
MATCH (u:User {name:'COMPROMISED_USER@DOMAIN.COM'}) SET u.owned = true RETURN u.name
```

### 13.2 What Can Owned Principals Reach?
```cypher
MATCH p = (n {owned:true})-[r*1..]->(m) WHERE NOT n = m RETURN p
```

### 13.3 Shortest Paths from Owned to Domain Admins
```cypher
MATCH p = shortestPath((n {owned:true})-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' RETURN p
```

### 13.4 Shortest Paths from Owned to High-Value Targets
```cypher
MATCH p = shortestPath((n {owned:true})-[*1..]->(m {highvalue:true})) WHERE NOT n = m RETURN p
```

### 13.5 Computers Where Owned Users Have Admin
```cypher
MATCH (n {owned:true})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN n.name, c.name
```

### 13.6 Sessions of Owned Principals
```cypher
MATCH (c:Computer)-[:HasSession]->(u {owned:true}) RETURN c.name, u.name
```

### 14 Credentail Enumeration
```cypher
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description <> '' RETURN u.name, u.description ORDER BY u.name
```
More targeted — filter for password-like keywords:
```cypher
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description =~ '(?i).*(pass|pwd|cred|secret|key|login|temp|initial|default|p@ss|123|!).*' RETURN u.name, u.description
```

Also check computer descriptions:
```cypher
MATCH (c:Computer) WHERE c.description IS NOT NULL AND c.description =~ '(?i).*(pass|pwd|cred|secret|key).*' RETURN c.name, c.description
```

```
ldapsearch "(objectClass=user)" --attributes samaccountname,description
```

```
PatchlessinlinePowershell "Get-DomainUser -LDAPFilter '(description=*)' | Where-Object { $_.description -match 'pass|pwd|cred|secret|key|temp|initial' } | Select-Object samaccountname, description" --amsi --etw --pipe desc1
```

---

## 15. Quick Reference — BloodHound Built-in Analysis Queries

Use the **Analysis** tab in BloodHound GUI for these pre-built queries:

| Query | Purpose |
|-------|---------|
| Find all Domain Admins | Enumerate DA group membership |
| Shortest Paths to Domain Admins | Attack paths to DA |
| Shortest Paths to High-Value Targets | Paths to HVT nodes |
| Shortest Paths from Kerberoastable Users | Kerberoast → DA paths |
| Shortest Paths to Unconstrained Delegation Systems | Unconstrained delegation abuse |
| Shortest Path from Owned Principals | Post-compromise paths |
| Find Principals with DCSync Rights | DCSync attack surface |
| Users with Foreign Domain Group Membership | Cross-domain paths |
| Groups with Foreign Domain Group Membership | Cross-domain trust abuse |
| Map Domain Trusts | Trust relationships |

---

## 16. Recommended Enumeration Workflow

1. **Import SharpHound Data** → Upload ZIP to BloodHound
2. **Mark Owned Principals** → Set compromised accounts as owned
3. **Run Domain Overview** → Sections 1-2 (domain info, privileged accounts)
4. **Check Kerberos Attack Surface** → Section 3 (Kerberoast, ASREP, delegation)
5. **Find Shortest Paths** → Section 4 (paths to DA from owned/kerberoastable)
6. **Enumerate Lateral Movement** → Section 5 (admin access, sessions, RDP)
7. **Check ACL Abuse** → Section 6 (GenericAll, WriteDACL, ForceChangePassword)
8. **Audit GPOs** → Section 7 (writable GPOs linked to high-value OUs)
9. **Enumerate ADCS** → Section 8 (ESC1-ESC8 checks)
10. **Review Credential Hygiene** → Section 9 (old passwords, no preauth)
11. **Check Computer Hygiene** → Section 10 (obsolete OS, no LAPS)
12. **Analyze Cross-Domain** → Section 12 (trusts, foreign membership)
13. **Post-Compromise Analysis** → Section 13 (from owned principals)

---

*Reference: https://queries.specterops.io/*
