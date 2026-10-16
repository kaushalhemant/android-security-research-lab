# Android Application Security Assessment

> **Portfolio demonstration — intentionally vulnerable training app.**
> This is an automated lab report, not a client assessment. Findings require independent validation; no claim of exploitability is made.


- **Application:** Diva
- **Package:** jakhar.aseem.diva
- **Assessment status:** Draft; findings require validation

## Summary

| Severity | Count |
|---|---:|
| High | 5 |
| Warning | 7 |
| Info | 2 |

## Findings

### 1. Android aar jar debug enabled

- **Severity:** High
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

Debug configuration enabled. Production builds must not be debuggable.

**Evidence**

```text
Rule: android_aar_jar_debug_enabled
Affected files and lines:
- jakhar/aseem/diva/BuildConfig.java: 4,7
cwe: CWE-919: Weaknesses in Mobile Applications
owasp-mobile: M1: Improper Platform Usage
masvs: MSTG-RESILIENCE-2
cvss: 5.4
ref: https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04c-Tampering-and-Reverse-Engineering.md#debugging-and-tracing
```

**Suggested remediation**

Disable debugging in production builds. Use a release build variant, inspect the final merged manifest, and verify that debug-only settings are absent from the distributed APK.

---

### 2. App can be installed on a vulnerable unpatched Android version 4.0.3-4.0.4, [minSdk=15]

- **Severity:** High
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security updates from Google. Support an Android version => 10, API 29 to receive reasonable security updates.

**Evidence**

```text
Rule: vulnerable_os_version; Component: ["4.0.3-4.0.4", "15"]
```

**Suggested remediation**

Review the minimum supported Android API level against security and compatibility requirements. Raise it when justified, test supported devices, and document any legacy support exceptions.

---

### 3. Application signed with debug certificate

- **Severity:** High
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

Application signed with a debug certificate. Production application must not be shipped with a debug certificate.

**Suggested remediation**

Verify the release APK signing configuration. Use the intended release signing process, protect signing credentials, and confirm the certificate and signature schemes meet release requirements.

---

### 4. Application vulnerable to Janus Vulnerability

- **Severity:** High
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

Application is signed with v1 signature scheme, making it vulnerable to Janus vulnerability on Android 5.0-8.0, if signed only with v1 signature scheme. Applications running on Android 5.0-7.0 signed with v1, and v2/v3 scheme is also vulnerable.

**Suggested remediation**

Verify the release APK signing configuration. Use the intended release signing process, protect signing credentials, and confirm the certificate and signature schemes meet release requirements.

---

### 5. Debug Enabled For App [android:debuggable=true]

- **Severity:** High
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes.

**Evidence**

```text
Rule: app_is_debuggable
```

**Suggested remediation**

Disable debugging in production builds. Use a release build variant, inspect the final merged manifest, and verify that debug-only settings are absent from the distributed APK.

---

### 6. Activity (jakhar.aseem.diva.APICreds2Activity) is not Protected. An intent-filter exists.

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.

**Evidence**

```text
Rule: exported_intent_filter_exists; Component: ["Activity", "jakhar.aseem.diva.APICreds2Activity"]
```

**Suggested remediation**

Review whether the component or file must be accessible to other apps. Restrict access where appropriate, enforce permissions, and validate incoming intents and data.

---

### 7. Activity (jakhar.aseem.diva.APICredsActivity) is not Protected. An intent-filter exists.

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

An Activity is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the Activity is explicitly exported.

**Evidence**

```text
Rule: exported_intent_filter_exists; Component: ["Activity", "jakhar.aseem.diva.APICredsActivity"]
```

**Suggested remediation**

Review whether the component or file must be accessible to other apps. Restrict access where appropriate, enforce permissions, and validate incoming intents and data.

---

### 8. Android read write external

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

App can read/write to External Storage. Any App can read data written to External Storage.

**Evidence**

```text
Rule: android_read_write_external
Affected files and lines:
- jakhar/aseem/diva/InsecureDataStorage4Activity.java: 25
cwe: CWE-276: Incorrect Default Permissions
owasp-mobile: M2: Insecure Data Storage
masvs: MSTG-STORAGE-2
cvss: 5.5
ref: https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#external-storage
```

**Suggested remediation**

Avoid storing sensitive application data in shared external storage. Prefer app-private internal storage or another suitable protected storage mechanism.

---

### 9. Android sql raw query

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.

**Evidence**

```text
Rule: android_sql_raw_query
Affected files and lines:
- jakhar/aseem/diva/InsecureDataStorage2Activity.java: 3,21,32
- jakhar/aseem/diva/NotesProvider.java: 10,11,12,46,47,48,49,50,51,52,53
- jakhar/aseem/diva/SQLInjectionActivity.java: 4,36
cwe: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
owasp-mobile: M7: Client Code Quality
cvss: 5.9
ref: https://github.com/MobSF/owasp-mstg/blob/master/Document/0x04h-Testing-Code-Quality.md#injection-flaws-mstg-arch-2-and-mstg-platform-2
```

**Suggested remediation**

Use parameterized SQLite queries or selection arguments instead of concatenating untrusted input into SQL. Review affected database queries and content-provider operations.

---

### 10. Android temp file

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

App creates temp file. Sensitive information should never be written into a temp file.

**Evidence**

```text
Rule: android_temp_file
Affected files and lines:
- jakhar/aseem/diva/InsecureDataStorage3Activity.java: 26
cwe: CWE-276: Incorrect Default Permissions
owasp-mobile: M2: Insecure Data Storage
masvs: MSTG-STORAGE-2
cvss: 5.5
```

**Suggested remediation**

Avoid writing sensitive information to temporary files. If temporary files are necessary, use app-private storage, restrict access, minimize retention, and remove files when no longer needed.

---

### 11. Application Data can be Backed up [android:allowBackup=true]

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.

**Evidence**

```text
Rule: app_allowbackup
```

**Suggested remediation**

Review whether application data needs backup. Configure Android backup and data-extraction rules for supported Android versions, and test backup and restore behaviour.

---

### 12. Content Provider (jakhar.aseem.diva.NotesProvider) is not Protected. [android:exported=true]

- **Severity:** Warning
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

A Content Provider is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device.

**Evidence**

```text
Rule: explicitly_exported; Component: ["Content Provider", "jakhar.aseem.diva.NotesProvider"]
```

**Suggested remediation**

Review whether the component or file must be accessible to other apps. Restrict access where appropriate, enforce permissions, and validate incoming intents and data.

---

### 13. Android logging

- **Severity:** Info
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

The App logs information. Sensitive information should never be logged.

**Evidence**

```text
Rule: android_logging
Affected files and lines:
- jakhar/aseem/diva/AccessControl1Activity.java: 26
- jakhar/aseem/diva/AccessControl2Activity.java: 30
- jakhar/aseem/diva/InsecureDataStorage2Activity.java: 23,35
- jakhar/aseem/diva/InsecureDataStorage3Activity.java: 35
- jakhar/aseem/diva/InsecureDataStorage4Activity.java: 36
- jakhar/aseem/diva/LogActivity.java: 24
- jakhar/aseem/diva/SQLInjectionActivity.java: 28,48
cwe: CWE-532: Insertion of Sensitive Information into Log File
masvs: MSTG-STORAGE-3
cvss: 7.5
ref: https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs
```

**Suggested remediation**

Remove passwords, authentication tokens, personal information, and other sensitive values from logs. Disable verbose logging in production and review the affected logging statements.

---

### 14. Signed Application

- **Severity:** Info
- **Status:** Needs review
- **Confidence:** Not provided

**Description**

Application is signed with a code signing certificate

**Suggested remediation**

Verify the release APK signing configuration. Use the intended release signing process, protect signing credentials, and confirm the certificate and signature schemes meet release requirements.

---

## Limitations

- Automated findings may contain false positives or miss vulnerabilities.
- Validate findings against source code, application behaviour, and the release APK.
- Confirm remediation with retesting before marking an issue as resolved.
- Suggested remediation is a starting point, not a substitute for developer review.
