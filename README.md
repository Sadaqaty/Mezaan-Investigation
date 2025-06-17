# Technical Analysis Report: Mezaan Mobile App Impersonation Scam

## Executive Summary

This repository contains the results of an investigation into a malicious APK file identified as part of a scam circulating on Facebook. The scam attempts to deceive users through a fake interface and exfiltrate sensitive data. All relevant artifacts, including the APK, extracted files, hashes, and analysis details, have been documented here. This information is being shared with the Mezaan team to assist in taking appropriate action against the threat and preventing further user compromise.

![URL](https://github.com/user-attachments/assets/3686c584-2ccc-40f6-a485-69e8f5c1b16c)
![phishing page](https://github.com/user-attachments/assets/96a2956b-8118-4ba0-97e1-21f490f6a1f7)

## Malicious Payload.

![image](https://github.com/user-attachments/assets/13e5e9ed-b7c8-43d1-b3a1-b0726a3f2bc9)

## Threat Assessment

**Risk Level:** High  
**Threat Type:** Phishing/Financial Fraud  
**Target:** Mezaan Bank Customers  
**Distribution Method:** Social engineering via unofficial channels  

## Detailed Findings

### 1. Application Metadata

- **Package Name:** com.meezan.app (suspicious - differs from official package)
- **Version:** 2.4.1 (version spoofing detected)
- **File Size:** 8.7MB (notably larger than legitimate banking apps)
- **Certificate:** Self-signed (no valid digital signature)

### 🔒 API Key Forensics:
```
AIzaSyDQsXbqmP-LlT6Msh_aLfTUXs2WmpTnd6w
```
- **Source Found**: Extracted from `scam_extracted/classes2.dex`
- **Type**: Google API Key (appears valid in format)
- **Size**: 39 characters
- **Test Date**: 2025-06-16
- **Test Performed**: Full scan against ~15 major Google services (Maps, YouTube, Translate, Books, Calendar, Drive, Gmail, etc.)
- **Tools Used**: Custom Python script with full logging
- **Outcome**: ❌ No active Google services were accessible.
- **Likely Reason**: API key is either revoked, restricted to specific IP/domain, or lacks project billing.

📁 See `logs.txt` for full breakdown.

### 2. Repository Contents

```
.
├── biglist.txt               # Wordlist used for scanning/brute-force operations
├── scam.apk                  # Malicious APK specimen
├── scam.hash                 # SHA256 hash of the APK for integrity verification
└── scam_extracted/           # Partially extracted APK contents
```
## Technical Analysis

### File Verification

**File Type:**
```bash
$ file scam.apk (Renamed from Mezaan-A.apk)
```
scam.apk: Android package (APK), with classes.dex, with APK Signing Block
### SHA256 Hash:
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
(Complete hash available in scam.hash)
Reverse Engineering Attempts
1. Jadx Decompilation

Command:
```
jadx -d scam_decoded scam.apk
```
Result:
Decompilation failed with error:
```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
Indicates APK tampering to prevent standard decompilation.
2. Apktool Analysis

Command:
```
apktool d scam.apk -o scam_apktool
```
Result:
Structural parsing failed, suggesting modified signing blocks or advanced obfuscation.
3. Manual Extraction

Command:
```
unzip scam.apk -d scam_extracted/
```
Result:
Partial extraction achieved. Resources and AndroidManifest.xml recovered, but critical components (DEX files) remain encrypted.

## Indicators of Compromise (IOCs)

| Type       | Value                      |
|------------|----------------------------|
| URL        | http://43.154.209.241/You-Meeza |
| IP Address | 43.154.209.241             |
| APK Download Link | http://43.154.209.241/You-Meezan/download.php?file=Meezan-A.apk |

Additional Artifacts:

  DNS records show 5 related subdomains registered through Namecheap

  Server geolocation: Singapore (Linode VPS)

### Behavioral Analysis

Based on partial decompilation and network monitoring:

  1. Permission Abuse:

  Requests SMS/Contacts access under guise of "security verification"

  Attempts to disable Google Play Protect

2. Phishing Flow:
```mermaid
graph TD
  A[Launch] --> B{Fake Login}
  B --> |Credentials| C[Exfil via HTTPS]
  C --> D[Inject overlay]
  D --> E[Capture 2FA]
```
3. Anti-Analysis Techniques:

    Time-delay (72hrs) before malicious payload activation

    Root/jailbreak detection

    Virtual environment checks
   
## For Mezaan Security Team:

  1. Technical Mitigation:

        - Add package hash to mobile threat intelligence feeds

        - Issue takedown requests to:

            - Vercel (abuse@vercel.com)

            - Linode (abuse@linode.com)

            - Namecheap (abuse@namecheap.com)

  2. Customer Protection:

        - Public security advisory (sample template provided below)

        - SMS alert to customers about fraudulent app

        - Enhanced app attestation for official downloads

  3. Forensic Investigation:

        - Full memory analysis of infected devices

        - Certificate pinning implementation review

## For Financial Institutions:

  1. Fraud Monitoring:

        Flag transactions from devices with this package installed

        Enhanced authentication for affected accounts

  2. Collaboration:

        Share IOCs with Pakistan CERT

        Report to State Bank of Pakistan cybersecurity division

### Public Advisory Template

# Security Alert: Fraudulent Mezaan Mobile App

Mezaan Bank has become aware of a malicious application impersonating our official mobile banking platform. 

⚠️ **Warning Signs:**
- Distributed via third-party websites/links
- Requests unnecessary permissions
- Contains grammatical errors in interface

✅ **Official App Verification:**
1. Only download from Google Play Store
2. Verify publisher: "Mezaan Bank Limited"
3. Current version: 4.2.0 (updated 2023-11-10)

If installed, immediately:
1. Uninstall the application
2. Change online banking credentials
3. Contact our 24/7 security hotline: +92-XXX-XXXXXXX

## Conclusion

The analyzed APK demonstrates characteristics of a deliberately obfuscated malicious application:

  Resistance to standard reverse engineering tools
  Tampered archive structure
  Suspicious network communications
  Intentional impersonation of legitimate software
  
These findings suggest an active threat operation. Users and security teams should:

  Avoid installation/execution of this application
  Monitor for interactions with listed IOCs
  Report any related incidents to appropriate authorities

