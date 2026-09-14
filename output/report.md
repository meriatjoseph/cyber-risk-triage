# TawasolPay — Top 5 Prioritised Cyber Risks

_Generated 2026-09-14 17:30 UTC — ranked by exposure, active exploitation, campaign match, business criticality, and missing controls (NOT CVSS alone)._

> **MDR Advisory — Risk level: HIGH.** Three active ransomware-associated campaigns have been observed exploiting vulnerabilities present in common fintech infrastructure. At least two of these campaigns have confirmed victims in the UAE this month.  
> Named campaigns: CrimsonJackal, RedMantis, SilentForge, IronVeil, WinterViper.

---

## #1 — load-balancer-prod-01 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-01 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Customer Login (owner: Chief Digital Officer) — Users cannot authenticate to the customer portal; all customer-facing transactions blocked. Customer-facing: Yes; compliance scope: GDPR; RTO: 1h
- **Why it ranks here:** Ranked #1 (score 94/100) because the vulnerable NetScaler ADC is directly reachable from the internet; CVE-2023-4966 is confirmed in the CISA Known Exploited Vulnerabilities catalog (added 2023-10-18); threat intel (High confidence) reports active exploitation in the wild by IronVeil/"CitrixBleed Exploitation".
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
- **Why it ranks here:** Ranked #2 (score 94/100) because the vulnerable NetScaler ADC is directly reachable from the internet; CVE-2023-4966 is confirmed in the CISA Known Exploited Vulnerabilities catalog (added 2023-10-18); threat intel (High confidence) reports active exploitation in the wild by IronVeil/"CitrixBleed Exploitation".
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
- **Why it ranks here:** Ranked #3 (score 94/100) because the vulnerable VPN Firmware is directly reachable from the internet; CVE-2024-21762 is confirmed in the CISA Known Exploited Vulnerabilities catalog (added 2024-02-09); threat intel (High confidence) reports weaponized exploit code in active use by CrimsonJackal/"Gateway Breaker".
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
- **Why it ranks here:** Ranked #4 (score 94/100) because the vulnerable VPN Firmware is directly reachable from the internet; CVE-2024-21762 is confirmed in the CISA Known Exploited Vulnerabilities catalog (added 2024-02-09); threat intel (High confidence) reports weaponized exploit code in active use by CrimsonJackal/"Gateway Breaker".
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **RA-5(10) — Correlate Scanning Information** _(similarity 0.38)_: Correlate the output from vulnerability scanning tools to determine the presence of multi-vulnerability and multi-hop attack vectors....
  - **SA-15(5) — Attack Surface Reduction** _(similarity 0.38)_: Require the developer of the system, system component, or system service to reduce attack surfaces to [thresholds]....

---

## #5 — payment-api-prod-01 · Payment API Insecure Direct Object Reference  (Risk score: 90/100)

- **Asset:** payment-api-prod-01 (API Server, Production, UAE) — owner: Payments Team; internet-exposed: Yes; EDR installed: Yes
- **Vulnerability:** Payment API Insecure Direct Object Reference (CVE-SYN-2026-0010, CVSS 9.1 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil also targeting payment API IDOR vulnerabilities in tandem with CitrixBleed to escalate access post-session-hijack.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** Ranked #5 (score 90/100) because the vulnerable Payment Handler is directly reachable from the internet; threat intel (High confidence) reports active exploitation in the wild by IronVeil/"CitrixBleed Exploitation"; "CitrixBleed Exploitation" (IronVeil) is a ransomware-associated campaign actively matching this CVE.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IR-6(2) — Vulnerabilities Related to Incidents** _(similarity 0.38)_: Report system vulnerabilities associated with reported incidents to [personnel or roles]....
  - **AC-25 — Reference Monitor** _(similarity 0.37)_: Implement a reference monitor for [access control policies] that is tamperproof, always invoked, and small enough to be subject to analysis and testing, the completeness of which can be assured....

---
