# Netflix Audio Stream Exfiltration via Chrome DevTools Protocol Network Interception

**Disclosure Date:** 2026-09-16
**CVE Identifier:** Pending Assignment (submitted to MITRE 2026-09-16)
**CWE:** CWE-311 (Missing Encryption of Sensitive Data), CWE-693 (Protection Mechanism Failure)
**Severity:** Medium
**Status:** Unpatched (vendor notified)
**Affected Platform:** Netflix streaming platform (all regions, all subscription tiers)
**Attack Class:** Unprotected Media Stream Interception, DRM Policy Gap
**CPE:** cpe:2.3:a:netflix:netflix:*:*:*:*:*:web:*:*

---

## Authors

**Juan Mathews Rebello Santos**
Security Researcher
LinkedIn: https://www.linkedin.com/in/juan-mathews-rebello-santos-/
Website: http://juanmathewsrebellosantos.com/

**Jhonata Fernandes Cordeiro**
Security Researcher
LinkedIn: https://www.linkedin.com/in/jhonata-fernandes-cordeiro-a887bb293/

---

## CVSS Scoring

### CVSS v3.1

**Base Score: 5.0 (Medium)**
**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N`

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | Local (L) | Exploit requires process execution on the machine running the authenticated Chrome session |
| Attack Complexity (AC) | Low (L) | No race conditions, no timing requirements, no special configuration beyond CDP port exposure |
| Privileges Required (PR) | Low (L) | Standard local user account sufficient to launch narr.exe and access TCP port 9222 |
| User Interaction (UI) | Required (R) | A Netflix-authenticated user must navigate to and play the target title in Chrome |
| Scope (S) | Unchanged (U) | Impact is limited to the Netflix audio content accessible to the authenticated session |
| Confidentiality Impact (C) | High (H) | Full audio track of any accessible Netflix title is exfiltrated as cleartext fMP4 |
| Integrity Impact (I) | None (N) | No data is modified |
| Availability Impact (A) | None (N) | No denial of service condition |

**Score derivation:**

```
ISCBase        = 1 - [(1 - 0.56) * (1 - 0.00) * (1 - 0.00)] = 0.5600
ISC (Unchanged)= 6.42 * 0.5600 = 3.5952
Exploitability = 8.22 * AV(0.55) * AC(0.77) * PR(0.62) * UI(0.62) = 1.3382
BaseScore      = Roundup(min(3.5952 + 1.3382, 10)) = Roundup(4.9334) = 5.0
```

---

### CVSS v4.0

**Base Score: 4.8 (Medium)**
**Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | Local (L) | Requires local code execution on the target machine |
| Attack Complexity (AC) | Low (L) | No special exploit conditions required |
| Attack Requirements (AT) | None (N) | No prerequisites beyond Chrome with CDP enabled |
| Privileges Required (PR) | Low (L) | Standard local user access to run a process and open a TCP connection |
| User Interaction (UI) | Passive (P) | Target user must be passively engaged in normal Netflix playback activity |
| Vulnerable System Confidentiality (VC) | High (H) | Netflix audio content fully exposed in cleartext |
| Vulnerable System Integrity (VI) | None (N) | No modification of data on the vulnerable system |
| Vulnerable System Availability (VA) | None (N) | No availability impact |
| Subsequent System Confidentiality (SC) | None (N) | No lateral impact on other systems |
| Subsequent System Integrity (SI) | None (N) | No lateral impact |
| Subsequent System Availability (SA) | None (N) | No lateral impact |

**Equivalency Class (EQ) derivation:**

```
EQ1 (AV, PR, UI): AV:L, PR:L, UI:P -> Level 2 (none are :N)
EQ2 (AC, AT)    : AC:L, AT:N        -> Level 0 (most favorable attack conditions)
EQ3 (VC, VI, VA): VC:H              -> Level 0 (high confidentiality impact on vulnerable system)
EQ4 (SC, SI, SA): SC:N, SI:N, SA:N  -> Level 3 (no subsequent system impact)
EQ5 (E)         : E:P               -> Level 1 (public PoC exists, no active exploitation)
EQ6 (CR, IR, AR): defaults          -> Level 1 (medium baseline requirements)
MacroVector     : 2-0-0-3
BaseScore       : 4.8 (Medium)
```

**Supplemental Metrics:**

| Metric | Value |
|---|---|
| Exploit Maturity (E) | Proof of Concept (P) |
| Automatable (AU) | No |
| Recovery (R) | Automatic |
| Value Density (VD) | Diffuse |
| Vulnerability Response Effort (RE) | Low |
| Provider Urgency (U) | Clear |

---

## Weakness Classification

| CWE ID | Name | Applicability |
|---|---|---|
| CWE-311 | Missing Encryption of Sensitive Data | Audio adaptation sets are not marked for CENC encryption in the DASH manifest ContentProtection descriptor |
| CWE-693 | Protection Mechanism Failure | Widevine DRM is deployed for video but not applied to audio tracks, creating a policy gap in the content protection architecture |
| CWE-319 | Cleartext Transmission of Sensitive Information | Audio segment HTTP responses are served as cleartext fMP4 containers over unencrypted CDN delivery for the content payload |

---

## Abstract

This document describes a proof of concept (PoC) demonstrating the exfiltration of audio content streams from the Netflix platform by intercepting network responses through the Chrome DevTools Protocol (CDP). The vulnerability arises from an architectural gap in Netflix content protection: while video tracks are encrypted under Widevine DRM (Level 1 and Level 3), audio tracks are served as cleartext MPEG-4 Audio containers and can be downloaded in full without any decryption step.

The attack requires no exploitation of a memory corruption vulnerability, no kernel-mode driver, and no reverse engineering of proprietary binaries. It abuses a legitimate browser automation interface against a live authenticated Netflix session.

---

## Vulnerability Description

### Root Cause

Netflix delivers media through an adaptive bitrate streaming pipeline based on MPEG-DASH. Both video and audio segments are requested by the browser as HTTP range requests targeting CDN-hosted resources. The URL pattern for these segment requests is:

```
https://<cdn>.nflxvideo.net/...?nflx-...#/range/0-<N>
```

Video segments are encrypted with Widevine Content Encryption (CENC). The encryption keys are negotiated between the browser Widevine CDM (Content Decryption Module) and the Netflix license server via an EME (Encrypted Media Extensions) handshake. Decryption occurs inside a trusted execution environment within the browser, and plaintext frames are never exposed to the main process or to JavaScript.

Audio segments do not receive the same level of protection. The audio tracks delivered to the browser are either not encrypted or protected by a Widevine configuration that permits cleartext passthrough for the audio codec track (AAC, xHE-AAC). As a result, when the browser performs an HTTP GET for an audio segment, the raw audio bytes in the response are accessible to any observer with visibility into the browser network layer.

### Attack Surface

The Chrome DevTools Protocol provides a programmatic interface to Chrome internals. When Chrome is launched with the flag `--remote-debugging-port=9222`, it exposes a WebSocket endpoint that allows external processes to subscribe to browser events including the `Network.responseReceived` event. This event fires for every HTTP response the browser processes, including media segment fetches.

By attaching to CDP and subscribing to `Network.responseReceived`, an attacker with local access to the machine can observe all media URLs as they are requested by the Netflix player. Because audio segments are cleartext, the observed URLs can be independently fetched with a standard HTTP client, reconstructing the full audio track without any DRM bypass.

### Secondary Finding: Unauthenticated CDN Re-fetch

The CDN segment URLs observed via CDP do not require any Netflix session credential to re-fetch. An HTTP GET issued without any cookie, Authorization header, or session token returns the full audio segment with HTTP 200. This confirms that the CDN URL is the sole access control mechanism for audio content delivery, and that interception of the URL is sufficient for full content exfiltration.

---

## Proof of Concept

### Environment

| Component | Detail |
|---|---|
| Operating System | Windows 10/11 (x64) |
| Browser | Google Chrome 110 and above |
| CDP Port | 9222 (configurable) |
| Netflix Account | Any valid authenticated session |
| Dependencies | Go 1.24 (compilation only), Chrome |

### Attack Flow

```
[Attacker Process]
      |
      |-- Launch Chrome with --remote-debugging-port=9222
      |-- Authenticate to Netflix in the browser (user interaction)
      |-- Navigate browser to target Netflix title URL
      |
      v
[Chrome CDP WebSocket ws://127.0.0.1:9222]
      |
      |-- Subscribe: Network.enable
      |-- Subscribe: Network.responseReceived
      |
      v
[Netflix Player loads title]
      |-- Browser sends DASH manifest request
      |-- Browser sends range requests for video segments (Widevine encrypted)
      |-- Browser sends range requests for audio segments (cleartext)
      |
      v
[Network.responseReceived event fires for each segment]
      |
      |-- Filter URLs containing /range/0- pattern
      |-- Probe first 3000 bytes of response to identify codec (MPEG-4 Audio box parser)
      |-- If audio: download full response body, write to disk
      |-- If video: discard (Widevine-encrypted, unplayable without CDM keys)
```

### Key Source Files

The PoC implementation is located under `src/`. The critical components are:

**`src/nflx.go` -- CDP event subscription and URL interception**

The `isMediaURL` function identifies candidate URLs by matching the `/range/0-` path segment:

```go
func isMediaURL(u string) bool {
    return strings.Contains(u, "/range/0-")
}
```

The `Listen` method subscribes to `Network.responseReceived` and emits intercepted URLs onto a channel:

```go
responseReceived, err := c.Network.ResponseReceived(ctx)
// ...
if isMediaURL(ev.Response.URL) {
    events <- event{MediaUrlReceivedEvent, []byte(ev.Response.URL)}
}
```

**`src/queue.go` -- Audio/video discrimination and unauthenticated CDN download**

The downloader reads the first 3000 bytes of each intercepted stream and passes them to `probeFileFormat`. Audio streams are persisted; encrypted video streams are discarded:

```go
isAudio, fInfo, err := probeFileFormat(header)
if !isAudio {
    return nil  // video segments are Widevine-encrypted; discard
}
```

The re-fetch is performed without any Netflix session credential:

```go
resp, err := http.Get(srcURL)  // no cookies, no auth headers
```

**`src/probe.go` -- MPEG-4 container box parser**

Parses `ftyp`, `mdat`, and `moof` boxes from raw bytes to determine whether the container holds an audio or video track, and whether the codec is AAC or xHE-AAC.

---

## Impact

An attacker with local access to a machine running an authenticated Netflix session can silently exfiltrate all audio content from any Netflix title as cleartext MPEG-4 Audio, without triggering any client-side DRM enforcement and without leaving traces beyond normal playback telemetry.

The output files are valid MPEG-4 Audio containers (.mp4a / .m4a), directly playable in any standards-compliant media player.

**Scope of impact:**

- Full audio tracks of any Netflix title accessible to the authenticated account
- Audio quality matches the stream quality selected by the Netflix adaptive player
- No traces in Netflix account activity logs beyond normal playback telemetry
- Requires local machine access and an authenticated Netflix session (insider threat model)
- Intercepted CDN segment URLs are reusable by any process without re-authentication

---

## Reproducing the PoC

### Step 1: Launch Chrome with CDP

Execute `START.bat` or run from a terminal:

```powershell
powershell -ExecutionPolicy Bypass -File .\launch.ps1
```

The script performs the following automatically:

1. Terminates any existing Chrome instances.
2. Launches Chrome via the Windows Task Scheduler interactive session flag (`/it`) to ensure the browser window appears on the interactive desktop.
3. Polls `http://127.0.0.1:9222/json/version` until the CDP endpoint is ready.
4. Waits for the operator to authenticate to Netflix.
5. Accepts Netflix watch URLs from stdin in a loop and invokes `narr.exe` for each.

### Step 2: Authenticate

Log in to Netflix in the Chrome window that opens. No credentials are transmitted to or stored by the PoC tooling.

### Step 3: Provide Target URL

Paste a Netflix watch URL when prompted:

```
https://www.netflix.com/watch/<videoId>?trackId=<trackId>
```

### Step 4: Observe Output

Audio files are written to the `downloads\` directory with the naming convention:

```
<videoId>-<trackId>-<random>.aac.mp4a
```

Rename the `.mp4a` extension to `.m4a` for playback in standard media players.

---

## Technical Notes on DRM Architecture

Netflix implements Widevine at two levels depending on the client device:

| Level | Hardware TEE | Video protection | Audio protection |
|---|---|---|---|
| L1 | Required | AES-CBC CENC, decrypt in TEE | Cleartext passthrough |
| L3 | Software only | AES-CBC CENC, software CDM | Cleartext passthrough |

In both configurations, the audio track is delivered without CENC encryption, consistent with the behavior observed in this PoC across multiple titles and languages.

This is not a Widevine implementation flaw. Widevine correctly encrypts what Netflix instructs it to encrypt. The gap is in Netflix content protection policy: audio tracks are not marked for encryption in the DASH manifest `ContentProtection` descriptor for the audio adaptation set.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-09-16 | Vulnerability identified during security research |
| 2026-09-16 | PoC developed and validated against live Netflix platform |
| 2026-09-16 | Public PoC release with simultaneous vendor notification |
| Pending | CVE identifier assignment by MITRE |
| Pending | Vendor patch or official response |

---

## Remediation Recommendations

1. Apply CENC encryption to audio adaptation sets in the DASH manifest, using the same Widevine key system (`com.widevine.alpha`) already used for video.
2. Enforce EME-based decryption for audio tracks in the browser player, consistent with video track handling.
3. Implement server-side request signing or short-lived token binding on CDN media URLs to prevent independent re-fetching of intercepted segment URLs.
4. Audit CDP exposure policies: consider restricting or detecting unexpected CDP attachment to Chrome processes running authenticated streaming sessions.

---

## References

- Chrome DevTools Protocol specification: https://chromedevtools.github.io/devtools-protocol/
- MPEG-DASH standard: ISO/IEC 23009-1
- Widevine DRM: https://widevine.com
- Encrypted Media Extensions W3C spec: https://www.w3.org/TR/encrypted-media/
- CVSS v3.1 specification: https://www.first.org/cvss/v3-1/
- CVSS v4.0 specification: https://www.first.org/cvss/v4-0/
- CWE-311: https://cwe.mitre.org/data/definitions/311.html
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- PoC repository: https://github.com/azurejoga/nav
- Original upstream tool (narr): https://github.com/IljaN/narr
- Video walkthrough (Portuguese): https://www.youtube.com/@ohackercego
- Juan Mathews Rebello Santos: http://juanmathewsrebellosantos.com/

---

## Disclaimer

This research was conducted for informational and educational purposes under responsible disclosure principles. The PoC tooling is provided as technical evidence of the described vulnerability. Use against any system without explicit authorization is prohibited.
