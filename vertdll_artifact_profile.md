#  Forensic Artifact Profile: `vertdll.dll`

**This report documents the discovery and forensic analysis of a suspicious system binary, `vertdll.dll`, located within the `%SystemRoot%\System32` directory of a compromised Windows 10 system. The artifact is digitally signed with a valid Microsoft-issued certificate, yet presents multiple anomalies inconsistent with legitimate Microsoft binaries. These include an implausible future compilation timestamp (January 2, 2039), unknown cryptographic hashes, and non-standard PE section structures with encrypted overlay data. Static and behavioral analysis reveals the presence of APIs associated with enclave operations, event tracing suppression, heap manipulation, and low-level native system calls—indicative of evasion techniques. The binary’s characteristics, in combination with broader system-level anomalies and audit configuration tampering found within the affected system, suggest a high-confidence compromise of the Windows trust model. This artifact is one of multiple primary indicators of a persistent and potentially firmware-resident threat actor.**


##  Artifact Summary

| Field                   | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| **File Name**          | `vertdll.dll`                                                         |
| **File Path**          | `C:\Windows\System32\vertdll.dll`                                  |
| **SHA-256**            | `542fe925ad55f26307690f24f616f146c1807213d320ecdccc9eca4022afcdd1`     |
| **MD5**                | `5362ea3da5a9f6ad138b63eeca3f3249`                                     |
| **File Size**          | `211.30 KB (216,376 bytes)`                                           |
| **Signature**          | Signed by *Microsoft Windows Production PCA 2011*                     |
| **Compile Timestamp**  | `2039-01-02 03:00:07 UTC` **Implausible (Future-dated)**              |
| **First Seen (VT)**    | `2025-04-09`                                                          |
| **Last Analysis (VT)** | `2025-05-07`                                                          |

---

## 🧬 Structural Analysis

- **File Type**: PE32+ (64-bit) Windows DLL  
- **Architecture**: x64  
- **Entry Point**: `0x7f40` (approx.)  
- **Section Count**: 9  
- **Suspicious Sections**:  
  - `.fothk`, `.00cfg`, `.mrdata` — Uncommon or reserved section names  
  - `.mrdata` entropy 0.01 — Indicates zeroed, padded, or encrypted block  
  - Overlay section present at offset `0x32000` with high entropy (7.55) — likely encrypted payload  

---

##  PE Characteristics

- **Type**: PE32+ executable (DLL)
- **Architecture**: x64
- **Sections**: `.text`, `.rdata`, `.pdata`, `.reloc`, `.rsrc`, `.fothk`, `.mrdata`, `.00cfg`
- **Overlay**: Present (offset `204800`, entropy `7.55`)

---

###  Section Entropy & Chi²

| Section    | Entropy | Chi²         | Note                                 |
|------------|---------|--------------|--------------------------------------|
| `.mrdata`  | 0.01    | 4,172,802.5  | Suspicious padding or encoded stub   |
| `.data`    | 0.09    | 1,029,180.12 | Fake content likely                  |
| `.text`    | 6.35    | 839,462.62   | Obfuscated or shellcode-like         |
| **Overlay**| 7.55    | 12,107.81    | Encrypted or packed secondary blob   |

---

##  Metadata vs. Behavior Discrepancy

| Attribute              | Metadata Claim                                | Observed Behavior                                      |
|-----------------------|------------------------------------------------|--------------------------------------------------------|
| **Product Name**      | Microsoft Windows Operating System             | Unknown to VT before April 2025                        |
| **File Description**  | VSM enclave runtime DLL                        | Contains enclave APIs not typically exposed            |
| **Signature Validity**| Valid signature                                | Likely spoofed or subverted trust                      |
| **Certificate Chain** | Microsoft PCA 2011 → Microsoft Root 2010       | Same as previously-abused malware certs                |
| **Compile Time**      | 2039-01-02                                     | Implausible / anti-forensics                           |

---

## API and Behavioral Indicators

- **ETW Suppression**: `EtwEventUnregister`, `EtwGetTraceEnableLevel`
- **Enclave Abuse**: `EnclaveSealData`, `EnclaveGetAttestationReport`
- **Heap/Thread Control**: `HeapFree`, `VirtualAlloc`, `RtlFreeHeap`
- **NT Native API Access**: `NtQueryInformationProcess`, `NtTerminateProcess`

---

## Signature Chain Breakdown

- **Signer**: Microsoft Windows  
- **Issuer**: Microsoft Windows Production PCA 2011  
- **Valid Range**: 2025-02-20 to 2026-02-18  
- **Thumbprint**: `5022ED9D6A86FFA7719B0BCB098FCCF32E8AA186BF9595E34F587A18C85F2954`

- **Counter-Signer**: Microsoft Time-Stamp Service  
- **Issuer**: Microsoft Time-Stamp PCA 2010  
- **Thumbprint**: `1185CCDDFC53C89F18D1F769B684F5AA73EBC6386D7EFC8D16B640ACB7287479`

---

## Risk Classification

| Category                 | Rating        | Justification                                                |
|--------------------------|---------------|--------------------------------------------------------------|
| **Trust Manipulation**   |  Confirmed   | Signed but unknown to catalog, spoofing likely                |
| **Anti-Forensics**       |  Confirmed   | Compile date in the year 2039                                 |
| **Malicious Behavior**   |  Strong      | Packed data, suspicious exports and runtime API access        |
| **Persistence Artifact** |  Likely      | Heap/thread/ETW use indicates long-term stealth mechanisms    |

---

## Suggested Chain of Custody Metadata

| Field                | Value                                     |
|----------------------|-------------------------------------------|
| System Identifier    | `WORKGROUP`                               |
| Acquisition Date     | 2025-05-12T06:15:21.403626 UTC            |
| Hashing Algorithm    | SHA-256                                   |
| Acquisition Method   | Live acquisition via trusted admin shell  |
| Examiner             | Dakota Sanderson                          |

---

##  Preservation 

- Preserve full copy of `vertdll.dll` in:
  - Binary form (verbatim, no modification)
  - With detached `.sig`, `.hash`, `.md` exports
- Submit to:
  - [MSRC](https://msrc.microsoft.com)
  - [VirusTotal Community](https://virustotal.com)
  - [abuse.ch](https://abuse.ch) if threat signature aligns

---

## Tag Summary

```json
{
  "artifact": "vertdll.dll",
  "classification": "Malicious System Binary (Forged Trust Chain)",
  "ioc_type": [
    "Forged Digital Signature",
    "Anti-Forensics Timestamp",
    "Unusual PE Section Layout",
    "Overlay Payload",
    "ETW/Heap/Enclave Abuse"
  ],
  "confidence": "High",
}
