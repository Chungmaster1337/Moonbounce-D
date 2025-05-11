
# 🧪 Forensic Analysis & Response Report

## 📅 Timeline Overview
**Duration:** Ongoing multi-year compromise  
**Intensive Investigation Period:** Last 2 days

---

## 🎯 Objective
Investigate, document, and preserve the full scope of a suspected long-term system compromise affecting Windows environments, including persistent malware, kernel-level subversion, and potential pre-OS persistence.

---

## 📁 File Structure (Suggested GitHub Layout)
```
/
├── README.md
├── forensic_intrusion_report.md
├── hashes/
│   ├── dfdts_hashes.txt
│   └── system32_hashes.txt
├── tasks/
│   ├── tasks.zip (original)
│   └── unpacked_xml/
├── tools/
│   ├── collect_unsigned_dlls.ps1
│   ├── collect_unsigned_dlls_with_progress.ps1
│   ├── forensic_pe_toolkit.zip (placeholder toolkit)
├── data_dumps/
│   ├── FullAutomationStateDump.txt
│   ├── FullStateDump.txt
│   └── unsigned_dlls.csv
└── logs/
    ├── bcdedit_output.txt
    ├── ifeo_dump.txt
    └── wmi_artifacts.txt
```

---

## 🔍 Key Findings

### 🟥 Confirmed Compromise Vector: `dfdts.dll`
- Located in `C:\Windows\System32`
- Masqueraded as legitimate Microsoft system file
- Previously unsigned with forged PE metadata (e.g., exports like `WdiHandleInstance`)
- Later swapped with a version reporting valid signature via Authenticode, but:
  - VirusTotal confirms SHA256: `389d2736a967...` is **not signed**
  - Windows falsely reports it as `IsOSBinary: True` — **strong indicator of WinVerifyTrust hook or catalog tampering**

### 🔧 Tools/Commands Compromised or Obfuscated
- `tasklist /m` returns empty or malformed
- `Get-NetAdapterAdvancedProperty` fails on real interfaces
- `Get-AuthenticodeSignature` reports forged trust
- `schtasks`, `reg query`, `WMI` return partial or no data
- Admin account lacks key privileges (`SeBackupPrivilege`, `SeRestorePrivilege`)

### ⚠️ WMI and IFEO Evidence
- Found orphaned WMI EventFilters (`SCM Event Log Filter`)
- IFEO keys showing user input redirection on `notepad.exe` and others

### 📉 Failed Task Export Attempt
- `Export-ScheduledTask` failed to run due to PowerShell limitation
- Tasks were manually extracted and later analyzed

### 🧼 Forensic Utility Scripts Built
- `collect_unsigned_dlls.ps1`: Baseline audit of unsigned binaries
- `collect_unsigned_dlls_with_progress.ps1`: Interactive version with progress bar
- Offline `forensic_pe_toolkit.zip`: Placeholder PE bundle for trusted analysis

---

## 📦 Confirmed/Correlated Artifacts
- `dfdts.dll`: core payload
- Task using `rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART`
- Tampered scheduled task names mimicking system services
- Virustotal entry linking `dfdts.dll` to 10+ different file aliases and shadow names

---

## 🚨 Pre-OS Compromise Risk Assessment
- Suspicious survival across reinstalls
- Potential vectors:
  - UEFI rootkit
  - Catalog tampering (`catdb` poisoning)
  - WFP hooking or filter driver injection
  - BCD untouched, but boot manager could be patched

---

## ✅ Actions Taken
- Extracted and saved system tasks
- Created PowerShell scripts for unsigned DLL enumeration
- Analyzed `bcdedit` for boot vector tampering (none confirmed yet)
- Verified `dfdts.dll` against VirusTotal for signature discrepancy

---

## 📋 Next Steps
- Boot into WinPE or Linux Live USB
- Use `sigcheck`, `hashdeep`, and `sha256sum` to verify core binaries offline
- Re-image machine only after full UEFI + storage scrub
- Consider preserving full disk image for cold analysis

---

## 📌 Appendix
### References
- VirusTotal SHA256: `389d2736a967d51fe50ec033f23d7f14ff62b73d8a7c1b4fffd8f7db2f488a29`
- Microsoft Signing Authority: Production PCA 2011 (falsely claimed)
- Related functions: `WdiDiagnosticModuleMain`, `WdiHandleInstance`

---

This report may be imported to GitHub as Markdown (`.md`) or retained as PDF/HTML via static site renderers.
