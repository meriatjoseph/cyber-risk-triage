# TawasolPay — Top 5 Prioritised Cyber Risks

_Generated 2026-09-15 18:04 UTC — ranked by exposure, active exploitation, campaign match, business criticality, and missing controls (NOT CVSS alone)._

> **MDR Advisory — Risk level: HIGH.** Three active ransomware-associated campaigns have been observed exploiting vulnerabilities present in common fintech infrastructure. At least two of these campaigns have confirmed victims in the UAE this month.  
> Named campaigns: CrimsonJackal, RedMantis, SilentForge, IronVeil, WinterViper.

---

## #1 — load-balancer-prod-01 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-01 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Customer Login (owner: Chief Digital Officer) — Users cannot authenticate to the customer portal; all customer-facing transactions blocked. Customer-facing: Yes; compliance scope: GDPR; RTO: 1h
- **Why it ranks here:** The Citrix ADC Session Token Leak (CVE‑2023‑4966) on the internet‑exposed load‑balancer‑prod‑01 is ranked highest because it is a zero‑auth, publicly reachable vulnerability confirmed in the CISA Known Exploited Vulnerabilities catalog, actively exploited by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, threatens the high‑criticality, customer‑facing login service with a 1‑hour RTO, is in scope for GDPR, and lacks any EDR protection, making IA‑13(3) – Token Management the appropriate NIST control to mitigate the risk.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IA-13(3) — Token Management** _(similarity 0.38)_: In accordance with [organization-defined parameter], assertions and access tokens are:
(a) generated;
(b) issued;
(c) refreshed;
(d) revoked;
(e) time-restricted; and
(f) audience-restricted....
  - **SC-7(10) — Prevent Exfiltration** _(similarity 0.37)_: (a) Prevent the exfiltration of information; and
(b) Conduct exfiltration tests [frequency]....

---

## #2 — load-balancer-prod-02 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-02 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** The Citrix ADC Session Token Leak (CVE‑2023‑4966) on the internet‑exposed load‑balancer‑prod‑02 is ranked highest because it is a zero‑auth, publicly reachable vulnerability confirmed in the CISA KEV, actively exploited by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, threatens the high‑criticality, customer‑facing Payment Processing service with a 1‑hour RTO, is in‑scope for PCI DSS, and the asset lacks EDR, making IA‑13(3) – Token Management the required NIST control.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IA-13(3) — Token Management** _(similarity 0.38)_: In accordance with [organization-defined parameter], assertions and access tokens are:
(a) generated;
(b) issued;
(c) refreshed;
(d) revoked;
(e) time-restricted; and
(f) audience-restricted....
  - **SC-7(10) — Prevent Exfiltration** _(similarity 0.37)_: (a) Prevent the exfiltration of information; and
(b) Conduct exfiltration tests [frequency]....

---

## #3 — vpn-edge-01 · Fortinet SSL-VPN Heap Buffer Overflow RCE  (Risk score: 94/100)

- **Asset:** vpn-edge-01 (VPN Gateway, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Fortinet SSL-VPN Heap Buffer Overflow RCE (CVE-2024-21762, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-02-09), **known ransomware campaign use**
- **Threat intel match:** CrimsonJackal / "Gateway Breaker" (Weaponized, High confidence, ransomware-associated: Yes) — Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging.
- **Business service at risk:** Remote Access (owner: CIO) — Remote employees and administrators lose secure network access. Customer-facing: No; compliance scope: ISO 27001; RTO: 2h
- **Why it ranks here:** The finding ranks highest because the publicly exposed VPN gateway is critical for remote access, the CVE‑2024‑21762 vulnerability is confirmed as a known exploited vulnerability with weaponized ransomware code actively used by CrimsonJackal, it can be exploited without authentication, the asset has no EDR and a 2‑hour RTO leaves no downtime tolerance, and the recommended NIST control RA‑5(10) – Correlate Scanning Information – is essential to detect and mitigate such active exploitation.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **RA-5(10) — Correlate Scanning Information** _(similarity 0.38)_: Correlate the output from vulnerability scanning tools to determine the presence of multi-vulnerability and multi-hop attack vectors....
  - **SA-15(5) — Attack Surface Reduction** _(similarity 0.38)_: Require the developer of the system, system component, or system service to reduce attack surfaces to [thresholds]....

---

## #4 — vpn-edge-02 · Fortinet SSL-VPN Heap Buffer Overflow RCE  (Risk score: 94/100)

- **Asset:** vpn-edge-02 (VPN Gateway, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Fortinet SSL-VPN Heap Buffer Overflow RCE (CVE-2024-21762, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-02-09), **known ransomware campaign use**
- **Threat intel match:** CrimsonJackal / "Gateway Breaker" (Weaponized, High confidence, ransomware-associated: Yes) — Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging.
- **Business service at risk:** Remote Access (owner: CIO) — Remote employees and administrators lose secure network access. Customer-facing: No; compliance scope: ISO 27001; RTO: 2h
- **Why it ranks here:** The finding ranks highest because the publicly exposed VPN gateway is critical for remote access, the CVE‑2024‑21762 vulnerability is confirmed in the CISA Known Exploited Vulnerabilities catalog, weaponized exploit code is actively used by the ransomware‑associated CrimsonJackal “Gateway Breaker” campaign, the asset lacks any EDR protection, and a 2‑hour RTO leaves virtually no downtime tolerance, so the risk is mitigated by correlating scanning information per NIST SP 800‑53 control RA‑5(10).
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **RA-5(10) — Correlate Scanning Information** _(similarity 0.38)_: Correlate the output from vulnerability scanning tools to determine the presence of multi-vulnerability and multi-hop attack vectors....
  - **SA-15(5) — Attack Surface Reduction** _(similarity 0.38)_: Require the developer of the system, system component, or system service to reduce attack surfaces to [thresholds]....

---

## #5 — payment-api-prod-01 · Payment API Insecure Direct Object Reference  (Risk score: 90/100)

- **Asset:** payment-api-prod-01 (API Server, Production, UAE) — owner: Payments Team; internet-exposed: Yes; EDR installed: Yes
- **Vulnerability:** Payment API Insecure Direct Object Reference (CVE-SYN-2026-0010, CVSS 9.1 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil also targeting payment API IDOR vulnerabilities in tandem with CitrixBleed to escalate access post-session-hijack.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** The payment‑API‑prod‑01 server is ranked highest because its publicly reachable Payment Handler is vulnerable to CVE‑SYN‑2026‑0010, which is actively exploited by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, the asset is critical and customer‑facing with a 1‑hour RTO, it is in‑scope for PCI DSS, and the vulnerability can be exploited without authentication, making the incident response control IR‑6(2) – Vulnerabilities Related to Incidents – essential for rapid detection and containment.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IR-6(2) — Vulnerabilities Related to Incidents** _(similarity 0.38)_: Report system vulnerabilities associated with reported incidents to [personnel or roles]....
  - **AC-25 — Reference Monitor** _(similarity 0.37)_: Implement a reference monitor for [access control policies] that is tamperproof, always invoked, and small enough to be subject to analysis and testing, the completeness of which can be assured....

---
