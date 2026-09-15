# TawasolPay — Top 5 Prioritised Cyber Risks

_Generated 2026-09-15 18:20 UTC — ranked by exposure, active exploitation, campaign match, business criticality, and missing controls (NOT CVSS alone)._

> **MDR Advisory — Risk level: HIGH.** Three active ransomware-associated campaigns have been observed exploiting vulnerabilities present in common fintech infrastructure. At least two of these campaigns have confirmed victims in the UAE this month.  
> Named campaigns: CrimsonJackal, RedMantis, SilentForge, IronVeil, WinterViper.

---

## #1 — load-balancer-prod-01 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-01 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Customer Login (owner: Chief Digital Officer) — Users cannot authenticate to the customer portal; all customer-facing transactions blocked. Customer-facing: Yes; compliance scope: GDPR; RTO: 1h
- **Why it ranks here:** The Citrix ADC Session Token Leak (CVE‑2023‑4966) is ranked highest because it is publicly reachable, actively exploited by a ransomware‑associated campaign, exposes a customer‑facing login with a 1‑hour RTO, is in scope for GDPR, and the asset lacks EDR, making IA‑13(3) – Token Management the required NIST control.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IA-13(3) — Token Management** _(similarity 0.40)_: In accordance with [organization-defined parameter], assertions and access tokens are:
(a) generated;
(b) issued;
(c) refreshed;
(d) revoked;
(e) time-restricted; and
(f) audience-restricted....
  - **SA-11(6) — Attack Surface Reviews** _(similarity 0.37)_: Require the developer of the system, system component, or system service to perform attack surface reviews....

---

## #2 — load-balancer-prod-02 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-02 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** The Citrix ADC Session Token Leak (CVE‑2023‑4966) on load‑balancer‑prod‑02 is ranked highest because it is internet‑exposed, exploitable without authentication, confirmed in the CISA KEV, actively exploited by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, and threatens the high‑criticality, customer‑facing Payment Processing service with a 1‑hour RTO and PCI DSS scope, so the recommended NIST control is IA‑13(3) – Token Management.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IA-13(3) — Token Management** _(similarity 0.40)_: In accordance with [organization-defined parameter], assertions and access tokens are:
(a) generated;
(b) issued;
(c) refreshed;
(d) revoked;
(e) time-restricted; and
(f) audience-restricted....
  - **SA-11(6) — Attack Surface Reviews** _(similarity 0.37)_: Require the developer of the system, system component, or system service to perform attack surface reviews....

---

## #3 — vpn-edge-01 · Fortinet SSL-VPN Heap Buffer Overflow RCE  (Risk score: 94/100)

- **Asset:** vpn-edge-01 (VPN Gateway, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Fortinet SSL-VPN Heap Buffer Overflow RCE (CVE-2024-21762, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-02-09), **known ransomware campaign use**
- **Threat intel match:** CrimsonJackal / "Gateway Breaker" (Weaponized, High confidence, ransomware-associated: Yes) — Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging.
- **Business service at risk:** Remote Access (owner: CIO) — Remote employees and administrators lose secure network access. Customer-facing: No; compliance scope: ISO 27001; RTO: 2h
- **Why it ranks here:** The VPN gateway’s publicly reachable firmware, the confirmed CVE‑2024‑21762 with weaponized exploit code actively used by the ransomware‑associated CrimsonJackal “Gateway Breaker” campaign, its critical business service impact, zero authentication requirement, and the asset’s criticality with a 2‑hour RTO make this finding a top‑priority risk, so it is mitigated by implementing NIST SP 800‑53 control SA‑15(5) – Attack Surface Reduction.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **SA-15(5) — Attack Surface Reduction** _(similarity 0.40)_: Require the developer of the system, system component, or system service to reduce attack surfaces to [thresholds]....
  - **RA-5(10) — Correlate Scanning Information** _(similarity 0.40)_: Correlate the output from vulnerability scanning tools to determine the presence of multi-vulnerability and multi-hop attack vectors....

---

## #4 — vpn-edge-02 · Fortinet SSL-VPN Heap Buffer Overflow RCE  (Risk score: 94/100)

- **Asset:** vpn-edge-02 (VPN Gateway, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Fortinet SSL-VPN Heap Buffer Overflow RCE (CVE-2024-21762, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-02-09), **known ransomware campaign use**
- **Threat intel match:** CrimsonJackal / "Gateway Breaker" (Weaponized, High confidence, ransomware-associated: Yes) — Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging.
- **Business service at risk:** Remote Access (owner: CIO) — Remote employees and administrators lose secure network access. Customer-facing: No; compliance scope: ISO 27001; RTO: 2h
- **Why it ranks here:** The VPN gateway’s publicly exposed firmware, the CVE‑2024‑21762 heap overflow confirmed in CISA’s Known Exploited Vulnerabilities catalog and actively weaponized by the ransomware‑associated CrimsonJackal “Gateway Breaker” campaign, combined with the asset’s critical remote‑access role, 2‑hour RTO, lack of EDR, and the fact that the flaw is exploitable without authentication, places this finding at the top of the priority list and warrants implementing NIST SP 800‑53 control SA‑15(5) – Attack Surface Reduction.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **SA-15(5) — Attack Surface Reduction** _(similarity 0.40)_: Require the developer of the system, system component, or system service to reduce attack surfaces to [thresholds]....
  - **RA-5(10) — Correlate Scanning Information** _(similarity 0.40)_: Correlate the output from vulnerability scanning tools to determine the presence of multi-vulnerability and multi-hop attack vectors....

---

## #5 — payment-api-prod-01 · Payment API Insecure Direct Object Reference  (Risk score: 90/100)

- **Asset:** payment-api-prod-01 (API Server, Production, UAE) — owner: Payments Team; internet-exposed: Yes; EDR installed: Yes
- **Vulnerability:** Payment API Insecure Direct Object Reference (CVE-SYN-2026-0010, CVSS 9.1 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil also targeting payment API IDOR vulnerabilities in tandem with CitrixBleed to escalate access post-session-hijack.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** The payment‑API‑prod‑01 server is ranked highest because its publicly reachable Payment Handler is vulnerable to CVE‑SYN‑2026‑0010, which is actively exploited by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, the asset is critical for a customer‑facing payment processing service with a 1‑hour RTO, and it is in‑scope for PCI DSS, so the incident response control IR‑6(2) – Vulnerabilities Related to Incidents – is the recommended NIST control.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IR-6(2) — Vulnerabilities Related to Incidents** _(similarity 0.38)_: Report system vulnerabilities associated with reported incidents to [personnel or roles]....
  - **SC-7(25) — Unclassified National Security System Connections** _(similarity 0.37)_: Prohibit the direct connection of [unclassified national security system] to an external network without the use of [boundary protection device]....

---
