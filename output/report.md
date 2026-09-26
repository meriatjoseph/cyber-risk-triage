# TawasolPay — Top 5 Prioritised Cyber Risks

_Generated 2026-09-26 17:26 UTC — ranked by exposure, active exploitation, campaign match, business criticality, and missing controls (NOT CVSS alone)._

> **MDR Advisory — Risk level: HIGH.** Three active ransomware-associated campaigns have been observed exploiting vulnerabilities present in common fintech infrastructure. At least two of these campaigns have confirmed victims in the UAE this month.  
> Named campaigns: CrimsonJackal, RedMantis, SilentForge, IronVeil, WinterViper.

---

## #1 — load-balancer-prod-01 · Citrix ADC Session Token Leak (CitrixBleed)  (Risk score: 94/100)

- **Asset:** load-balancer-prod-01 (Load Balancer, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Citrix ADC Session Token Leak (CitrixBleed) (CVE-2023-4966, CVSS 9.4 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2023-10-18), **known ransomware campaign use**
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil group actively exploiting Citrix NetScaler CitrixBleed CVE-2023-4966 to harvest session tokens from load balancers protecting financial portals. Tokens used to bypass MFA.
- **Business service at risk:** Customer Login (owner: Chief Digital Officer) — Users cannot authenticate to the customer portal; all customer-facing transactions blocked. Customer-facing: Yes; compliance scope: GDPR; RTO: 1h
- **Same finding also on:** load-balancer-prod-02 (Production) — Payment Processing, compliance scope: PCI DSS (score 94/100)
- **Why it ranks here:** The Citrix ADC Session Token Leak (CVE‑2023‑4966) is ranked #1 because it is a publicly reachable, authentication‑less vulnerability that is actively exploited by a ransomware‑associated campaign (IronVeil/CitrixBleed), threatens a high‑criticality, customer‑facing login service with a 1‑hour RTO, is listed in the CISA Known Exploited Vulnerabilities catalog, and lacks any EDR protection, making it a top priority to remediate under NIST SP 800‑53 control IA‑13(3) – Token Management.
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

## #2 — vpn-edge-01 · Fortinet SSL-VPN Heap Buffer Overflow RCE  (Risk score: 94/100)

- **Asset:** vpn-edge-01 (VPN Gateway, Production, UAE) — owner: Network Team; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** Fortinet SSL-VPN Heap Buffer Overflow RCE (CVE-2024-21762, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-02-09), **known ransomware campaign use**
- **Threat intel match:** CrimsonJackal / "Gateway Breaker" (Weaponized, High confidence, ransomware-associated: Yes) — Active exploitation of Fortinet SSL-VPN CVE-2024-21762 observed against financial services and fintech firms in the Gulf region. Initial access leads to internal lateral movement and ransomware staging.
- **Business service at risk:** Remote Access (owner: CIO) — Remote employees and administrators lose secure network access. Customer-facing: No; compliance scope: ISO 27001; RTO: 2h
- **Same finding also on:** vpn-edge-02 (Production) — Remote Access, compliance scope: ISO 27001 (score 94/100)
- **Same finding also on:** vpn-staging (Staging) — Remote Access, compliance scope: ISO 27001 (score 90/100)
- **Why it ranks here:** The finding ranks #2 because the publicly reachable VPN firmware is a critical remote‑access asset with a CVE‑2024‑21762 heap buffer overflow that is exploitable without authentication, is confirmed in the CISA Known Exploited Vulnerabilities catalog, is actively weaponized by the ransomware‑associated “Gateway Breaker” campaign, and the 2‑hour RTO leaves virtually no downtime tolerance, making SI‑16 – Memory Protection – the recommended NIST control.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **SI-16 — Memory Protection** _(similarity 0.69)_: Implement the following controls to protect the system memory from unauthorized code execution: [controls]....
  - **SA-8(26) — Performance Security** _(similarity 0.54)_: Implement the security design principle of performance security in [systems or system components]....

---

## #3 — payment-api-prod-01 · Payment API Insecure Direct Object Reference  (Risk score: 90/100)

- **Asset:** payment-api-prod-01 (API Server, Production, UAE) — owner: Payments Team; internet-exposed: Yes; EDR installed: Yes
- **Vulnerability:** Payment API Insecure Direct Object Reference (CVE-SYN-2026-0010, CVSS 9.1 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **Threat intel match:** IronVeil / "CitrixBleed Exploitation" (Active Exploitation, High confidence, ransomware-associated: Yes) — IronVeil also targeting payment API IDOR vulnerabilities in tandem with CitrixBleed to escalate access post-session-hijack.
- **Business service at risk:** Payment Processing (owner: CFO) — Payments and fund transfers fail; PCI DSS breach obligations triggered. Customer-facing: Yes; compliance scope: PCI DSS; RTO: 1h
- **Why it ranks here:** The payment API’s publicly exposed handler, which is exploitable without authentication and is actively targeted by the ransomware‑associated IronVeil “CitrixBleed Exploitation” campaign, poses a critical threat to the customer‑facing payment processing service with a 1‑hour RTO, making it a #3 priority finding that requires the NIST SP 800‑53 control AC‑6 – Least Privilege.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **AC-6 — Least Privilege** _(similarity 0.69)_: Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks....
  - **AC-3 — Access Enforcement** _(similarity 0.66)_: Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies....

---

## #4 — teamcity-prod · JetBrains TeamCity Authentication Bypass  (Risk score: 90/100)

- **Asset:** teamcity-prod (Build Server, Production, UAE) — owner: DevOps; internet-exposed: Yes; EDR installed: No
- **Vulnerability:** JetBrains TeamCity Authentication Bypass (CVE-2024-27198, CVSS 9.8 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **CISA KEV:** confirmed actively exploited (added 2024-03-07), **known ransomware campaign use**
- **Threat intel match:** SilentForge / "Build Chain Theft" (Weaponized, High confidence, ransomware-associated: No) — SilentForge also exploiting JetBrains TeamCity CVE-2024-27198 authentication bypass to access build pipelines and extract secrets.
- **Business service at risk:** DevOps Platform (owner: VP Engineering) — Build, deploy and monitoring toolchain offline; operational visibility lost. Customer-facing: No; compliance scope: SOC 2; RTO: 12h
- **Why it ranks here:** The finding is ranked #4 because the publicly reachable TeamCity Authentication Handler is exploitable without authentication, is confirmed in the CISA Known Exploited Vulnerabilities catalog, and is actively weaponized by SilentForge’s “Build Chain Theft” campaign, yet the asset lacks EDR and is critical to the DevOps Platform, so the recommended NIST control IA‑2(6) – Access to Accounts — separate Device – is required to mitigate this risk.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **IA-2(6) — Access to Accounts —separate Device** _(similarity 0.67)_: Implement multi-factor authentication for [organization-defined parameter] access to [organization-defined parameter] such that:
(a) One of the factors is provided by a device separate from the system gaining access; and
(b) The device meets [strength of mechanism requirements]....
  - **IA-3 — Device Identification and Authentication** _(similarity 0.67)_: Uniquely identify and authenticate [devices and/or types of devices] before establishing a [organization-defined parameter] connection....

---

## #5 — partner-api-gateway-prod · Kong Gateway Admin API Exposed  (Risk score: 88/100)

- **Asset:** partner-api-gateway-prod (API Server, Production, UAE) — owner: Partnerships Team; internet-exposed: Yes; EDR installed: Yes
- **Vulnerability:** Kong Gateway Admin API Exposed (CVE-SYN-2026-0011, CVSS 9.3 Critical); exposure: Internet; auth required to exploit: No; patch available: Yes
- **Threat intel match:** WinterViper / "Kong Gateway Exploit" (Weaponized, High confidence, ransomware-associated: Yes) — WinterViper group targeting exposed API gateway admin interfaces, particularly Kong. Exploitation provides full control over all proxied routes, enabling traffic interception and partner impersonation.
- **Business service at risk:** Partner API Gateway (owner: VP Partnerships) — Bank and fintech partner integrations fail; SLA breach penalties apply. Customer-facing: Yes; compliance scope: PCI DSS, ISO 27001; RTO: 2h
- **Why it ranks here:** The finding ranks #5 because the publicly reachable Kong Gateway Admin API, which is exploitable without authentication and is actively weaponized by the ransomware-associated WinterViper campaign, exposes a critical customer‑facing partner API gateway that must remain online within a 2‑hour RTO, and the appropriate NIST control to mitigate this is SC‑2(1) – Interfaces for Non‑privileged Users.
- **NIST SP 800-53 Rev 5 guidance (retrieved via embeddings):**
  - **SC-2(1) — Interfaces for Non-privileged Users** _(similarity 0.64)_: Prevent the presentation of system management functionality at interfaces to non-privileged users....
  - **SC-7(15) — Networked Privileged Accesses** _(similarity 0.64)_: Route networked, privileged accesses through a dedicated, managed interface for purposes of access control and auditing....

---
