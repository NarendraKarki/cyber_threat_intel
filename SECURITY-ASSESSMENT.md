# Security Assessment — Cyber Threat Intelligence Agent

**Assessed by:** Narendra Karki · CAISP · CISSP · CISM · CISA  
**Assessment date:** 2026-06-26  
**Repository:** github.com/NarendraKarki/cyber_threat_intel  
**Methodology:** Static application security testing (SAST), dependency analysis, manual prompt-flow review  
**Frameworks:** OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) · OWASP LLM Top 10 · CWE  

---

## Executive Summary

A security assessment of the Cyber Threat Intelligence Agent identified three confirmed vulnerabilities and six lower-priority findings requiring no immediate action. The most significant finding was an indirect prompt injection path — classified as ASI01 (Agent Goal Hijack) under the OWASP Top 10 for Agentic Applications 2026 — where untrusted content from external threat intelligence feeds entered LLM prompts without sanitisation. All three confirmed vulnerabilities have been remediated and verified. The agent passed a post-remediation scan with no High severity findings.

This assessment was conducted as part of a structured AI security research programme, applying CAISP certification skills to a real production codebase rather than a synthetic exercise.

---

## What This Agent Does

The CTI Agent is an autonomous, multi-step AI pipeline that:

1. Collects raw threat intelligence from external sources (CISA Known Exploited Vulnerabilities catalogue, CISA Advisories, National Vulnerability Database, and ThreatFox)
2. Classifies each advisory by the business sector it most endangers — Financial, Healthcare, or Government
3. Enriches each threat with an LLM-generated analyst summary and recommended action
4. Produces an executive-level briefing per sector for security leadership

The agent runs against a local LLM (Ollama/Llama3) with no external API calls and no cloud data egress. At the time of assessment it processed 137 raw items per sweep across four intelligence sources.

---

## Threat Model

The agent's attack surface differs from a traditional web application in two important ways. First, the primary input channel is not a user typing into a form — it is machine-generated XML and JSON feeds from external threat intelligence sources. Second, the processing layer is a large language model that cannot reliably distinguish between data it is supposed to analyse and instructions it is supposed to follow. These two properties, combined, create an attack surface that standard application security tooling is only partially equipped to detect.

The relevant threat actor for this assessment is an adversary capable of influencing the content of one or more threat feeds that the agent consumes — either by submitting a malicious entry to a feed provider, compromising the feed at source, or positioning themselves to intercept and modify the feed in transit.

---

## Findings

### Finding 1 — Indirect Prompt Injection via Untrusted Threat Feed Content

**Severity:** High  
**Framework:** ASI01 — Agent Goal Hijack (OWASP Top 10 for Agentic Applications 2026) · LLM01 — Prompt Injection (OWASP LLM Top 10)  
**Status:** ✅ Remediated  

**What was found:**  
External threat feed content — specifically advisory titles and summaries retrieved from CISA and NVD — was embedded directly into LLM prompts across three separate pipeline stages (classification, enrichment, and executive briefing) with no sanitisation beyond length truncation. The system prompt provided role definition for the model but contained no explicit instruction to treat feed content as untrusted data or to resist embedded instructions.

**Why it matters:**  
A threat feed is an external, untrusted data source. An adversary capable of influencing a single advisory entry — whether by submitting content to a public feed, compromising a feed provider, or intercepting an unencrypted feed fetch — could embed prompt injection instructions within a title or description field. The LLM, receiving this content in the same context as its legitimate instructions, has no reliable mechanism to distinguish the two. In practice this could cause the agent to produce fabricated threat intelligence, suppress genuine advisories, or alter its classification and prioritisation behaviour in ways that serve an attacker's interests rather than a defender's.

This is specifically classified as ASI01 (Agent Goal Hijack) rather than a generic LLM prompt injection because the attack targets the agent's multi-step planning behaviour — not just a single model call, but the entire pipeline's classification and enrichment decisions downstream of the injected instruction.

**What was changed:**  
An injection-resistance instruction was added to the system prompt, explicitly directing the model to treat all feed content as untrusted data and to disregard any embedded instructions, role changes, or directives. A sanitisation function was introduced that strips known prompt injection trigger phrases from feed content before it enters any prompt construction step. This function is applied at all three pipeline stages — classification, enrichment, and briefing — so no path exists for unsanitised feed content to reach the model.

**Important limitation:**  
Prompt injection cannot be fully prevented at the input layer alone. The sanitisation function reduces the attack surface by removing known patterns, and the hardened system prompt reduces the model's compliance with injected instructions — but neither is a complete control. Human review of agent outputs, particularly for any unexpected or anomalous briefing content, remains an important compensating control. This reflects the principle of defence in depth rather than a claim that the vulnerability is eliminated.

---

### Finding 2 — XML External Entity Vulnerability in Threat Feed Parsing

**Severity:** Medium  
**Framework:** CWE-20 — Improper Input Validation · CWE-611 — Improper Restriction of XML External Entity Reference  
**Status:** ✅ Remediated  

**What was found:**  
The agent parsed RSS and Atom feeds from external threat intelligence sources using Python's standard XML parsing library, which is documented as vulnerable to XML External Entity (XXE) attacks when processing untrusted content.

**Why it matters:**  
An XXE attack embedded in a maliciously crafted XML feed could potentially cause the parser to read files from the local filesystem, make outbound network requests, or consume excessive resources. In the context of this agent, this finding is directly connected to Finding 1 — the XML parsing layer is the point at which external feed content first enters the system, and a successful XXE attack provides an additional mechanism for feed-level manipulation beyond prompt injection.

**What was changed:**  
The standard library XML parser was replaced with its security-hardened equivalent, which disables external entity processing and other known XML attack vectors by default. This is a single-line change that eliminates the XXE vulnerability entirely without affecting the agent's parsing behaviour for well-formed feeds.

---

### Finding 3 — Predictable Temporary File Path

**Severity:** Medium  
**Framework:** CWE-377 — Insecure Temporary File  
**Status:** ✅ Remediated  

**What was found:**  
A fixed, predictable path was used for caching report data in the system's temporary directory.

**Why it matters:**  
On a multi-user system, a predictable temporary file path can be exploited via a symlink attack — an adversary creates a symlink at the predicted path pointing to a sensitive file before the application writes to it, causing the application to overwrite the target file instead. The risk in this specific deployment context (a local single-user system) is low, but the pattern represents a security anti-pattern worth correcting regardless.

**What was changed:**  
The hardcoded path was replaced with a call to the system's secure temporary directory resolution function, which returns the appropriate temporary directory for the current platform and user context rather than assuming a fixed path.

---

## Accepted Risks

The following findings were identified, reviewed, and accepted as low-priority items that do not require remediation at this time. Each is documented here for transparency rather than left unaddressed.

| Finding | Severity | Reason accepted |
|---|---|---|
| URL scheme validation — 4 instances where HTTP calls are made without explicit scheme validation | Medium | All URLs originate from the application's own configuration file, not from external input. No path exists for an attacker to supply a URL to these call sites. |
| Subprocess module usage | Low | The subprocess call invokes a fixed curl command as a network fallback mechanism. No user-supplied or externally-influenced content appears in the command arguments. |
| Subprocess call without shell=True | Low | Related to the above. The command is constructed from a fixed argument list. Shell injection is not possible in this configuration. |

---

## What Standard Scanning Tools Caught — and What They Missed

This assessment used two automated SAST tools alongside manual review. The results are worth discussing honestly, because they illustrate a limitation relevant to any organisation assessing AI agent security.

**What automated SAST detected:**  
The XML parsing vulnerability (Finding 2) and the temporary file vulnerability (Finding 3) were both flagged by the automated scanner within seconds. These are well-understood vulnerability patterns with documented detection rules. The subprocess and URL findings (accepted risks above) were also correctly identified.

**What automated SAST missed:**  
Finding 1 — the indirect prompt injection path — was not detected by any automated tool. Both SAST tools returned zero findings related to it. The finding was identified through manual prompt-flow analysis: tracing the path from external feed retrieval through data transformation to LLM prompt construction, and identifying the points at which untrusted content entered the model's context window without sanitisation.

This is not a criticism of the tools. Prompt injection is not a pattern that static analysis was designed to detect — it requires understanding how data flows through an application's natural language layer, which is a different discipline from traditional code analysis. The practical implication is that AI agent security assessment cannot be reduced to running a scanner. Automated tooling is necessary but not sufficient. Manual review of how external data enters LLM prompts is required as a distinct assessment step.

**Custom rule gap identified:**  
A set of custom security rules written for a Flask-based LLM application returned zero findings when applied to this agent. This confirmed a gap in rule coverage for agentic architectures that differ structurally from web-framework-based LLM applications. Extending automated detection to cover prompt-flow patterns in agentic systems is an open problem in the field.

---

## The Broader Question

This assessment was conducted on a system built by the assessor — meaning the same person who wrote the code also reviewed it for vulnerabilities. That is not the ideal configuration for a security review, and findings identified by a third party would carry more weight. The honest rationale for conducting and publishing this self-assessment is that it demonstrates the methodology can find real vulnerabilities in real code, and that the vulnerabilities found were not obvious ones that a developer would catch in normal testing.

The more important question this assessment raises is one relevant to every organisation currently mandating AI adoption: when employees build AI agents and deploy them to automate internal processes, does that code go through the same security review as any other production software?

The vulnerabilities found here — prompt injection via untrusted data sources, insecure XML parsing, hardcoded paths — are not unusual or exotic. They are the kinds of mistakes any competent developer makes when building quickly and focused on functionality. The difference with AI agents is that the attack surface extends beyond what traditional application security tools were built to see. A developer who passes a standard SAST scan and considers the application secure would have missed Finding 1 entirely.

The OWASP Top 10 for Agentic Applications 2026 provides a starting framework for structured assessment of this class of system. It is not a complete answer, but it is a more precise starting point than applying web application security frameworks to agent architectures they were not designed to address.

---

## Post-Remediation Scan Results

| Tool | Pre-remediation | Post-remediation | Change |
|---|---|---|---|
| SAST — severity High | 0 | 0 | — |
| SAST — severity Medium | 6 | 4 | -2 |
| SAST — severity Low | 3 | 2 | -1 |
| SAST — severity Total | 9 | 6 | -3 |
| Custom AI security rules | 0 | 0 | — |
| Secrets / credentials scan | 0 | 0 | — |
| Remaining findings | — | 6 accepted risks (documented above) | — |

---

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- [MITRE CWE-377](https://cwe.mitre.org/data/definitions/377.html)
- [MITRE CWE-611](https://cwe.mitre.org/data/definitions/611.html)
- [defusedxml — Python secure XML parsing](https://pypi.org/project/defusedxml/)
- [Practical DevSecOps — CAISP certification](https://www.practical-devsecops.com)

---

*Assessment conducted as part of a structured AI security research programme.*  
*Assessor: Narendra Karki · CAISP · CISSP · CISM · CISA · 2026-06-26*
