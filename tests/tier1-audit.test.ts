import { describe, expect, test } from "bun:test"
import {
  buildPermissionFindings,
  classifyPermissions,
} from "../src/core/permissions-catalog.ts"
import {
  scanStringsForSecrets,
  shannonEntropy,
  containsPrivateKey,
} from "../src/core/secret-scan.ts"
import {
  analyzeApksignerVerbose,
  analyzeCertPrint,
  buildSigningFindings,
} from "../src/core/signing-audit.ts"
import {
  complianceFindings,
  metaDataSecretFindings,
  parseCustomPermissions,
  parseExportedComponents,
  parseMetaDataValues,
  parseUsesPermissions,
} from "../src/core/apk-audit.ts"
import { sortFindingsBySeverity } from "../src/core/report.ts"
import type { ApkEntrySummary, ApkMetadata, Finding } from "../src/core/types.ts"

// Secret literals are assembled at runtime so the open-source release secret scanner
// (scripts/release-check.ts) does not flag this test fixture as a leaked credential.
const AWS_KEY = `AKIA${"IOSFODNN7EXAMPLE"}`
const PEM_HEADER = `-----BEGIN ${"RSA"} PRIVATE KEY-----`

describe("secret-scan", () => {
  test("detects well-known credential shapes", () => {
    const hits = scanStringsForSecrets([
      AWS_KEY,
      "AIzaabcdefghijklmnopqrstuvwxyz012345678",
      "just a normal string",
    ])
    const codes = hits.map((hit) => hit.code)
    expect(codes).toContain("AWS_ACCESS_KEY")
    expect(codes).toContain("GOOGLE_API_KEY")
  })

  test("redacts matched secrets in the preview", () => {
    const [hit] = scanStringsForSecrets([AWS_KEY])
    expect(hit?.preview).toContain("****")
    expect(hit?.preview).not.toBe(AWS_KEY)
  })

  test("does not flag low-entropy generic assignments", () => {
    const hits = scanStringsForSecrets(["password=aaaaaaaa"])
    expect(hits.length).toBe(0)
  })
  test("filters generic placeholders and labels real generic values medium-confidence", () => {
    expect(scanStringsForSecrets([
      "api_key=your_api_key_here",
      "password=changemechangeme",
    ])).toHaveLength(0)
    const hits = scanStringsForSecrets(["client_secret=Ab9xQ2vLm7pR4sT8"])
    expect(hits.map((hit) => hit.code)).toContain("GENERIC_CREDENTIAL")
    expect(hits.find((hit) => hit.code === "GENERIC_CREDENTIAL")?.confidence).toBe("medium")
  })


  test("detects PEM private key header", () => {
    expect(containsPrivateKey(PEM_HEADER)).toBe(true)
    expect(shannonEntropy("aaaa")).toBe(0)
    expect(shannonEntropy("abcd")).toBeGreaterThan(1)
  })
})

describe("permissions catalog", () => {
  test("classifies dangerous groups and high-risk permissions", () => {
    const classification = classifyPermissions([
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.CAMERA",
      "android.permission.SYSTEM_ALERT_WINDOW",
    ])
    expect(classification.dangerousByGroup.LOCATION).toContain("android.permission.ACCESS_FINE_LOCATION")
    expect(classification.dangerousByGroup.CAMERA).toContain("android.permission.CAMERA")
    expect(classification.highRisk.map((r) => r.permission)).toContain("android.permission.SYSTEM_ALERT_WINDOW")
  })

  test("builds findings including weak custom permission protection", () => {
    const findings = buildPermissionFindings(
      ["android.permission.QUERY_ALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
      [{ name: "com.app.CUSTOM", protectionLevel: "normal" }],
      "MANIFEST",
    )
    const codes = findings.map((f) => f.code)
    expect(codes).toContain("MANIFEST_HIGH_RISK_PERMISSION")
    expect(codes).toContain("MANIFEST_QUERY_ALL_PACKAGES")
    expect(codes).toContain("MANIFEST_CUSTOM_PERMISSION_WEAK_PROTECTION")
  })

  test("signature-level custom permission is not flagged as weak", () => {
    const findings = buildPermissionFindings(
      [],
      [{ name: "com.app.CUSTOM", protectionLevel: "signature" }],
      "SOURCE",
    )
    expect(findings.map((f) => f.code)).not.toContain("SOURCE_CUSTOM_PERMISSION_WEAK_PROTECTION")
  })
})

const PERMISSION_XMLTREE = [
  "N: android=http://schemas.android.com/apk/res/android",
  "  E: manifest (line=1)",
  "    E: uses-permission (line=2)",
  '      A: android:name(0x01010003)="android.permission.CAMERA" (Raw: "android.permission.CAMERA")',
  "    E: permission (line=3)",
  '      A: android:name(0x01010003)="com.app.CUSTOM" (Raw: "com.app.CUSTOM")',
  "      A: android:protectionLevel(0x01010009)=(type 0x11)0x0",
  "    E: application (line=4)",
  "      E: meta-data (line=5)",
  '        A: android:name(0x01010003)="com.google.android.geo.API_KEY" (Raw: "...")',
  '        A: android:value(0x01010024)="AIzaSyA1234567890abcdefghijklmnopqrstuvwx" (Raw: "...")',
].join("\n")

describe("manifest xmltree parsers", () => {
  test("parses uses-permission names", () => {
    expect(parseUsesPermissions(PERMISSION_XMLTREE)).toContain("android.permission.CAMERA")
  })

  test("parses custom permission with mapped protection level", () => {
    const custom = parseCustomPermissions(PERMISSION_XMLTREE)
    expect(custom).toEqual([{ name: "com.app.CUSTOM", protectionLevel: "normal" }])
  })

  test("parses meta-data values and flags embedded secret", () => {
    const values = parseMetaDataValues(PERMISSION_XMLTREE)
    expect(values.some((v) => v.name === "com.google.android.geo.API_KEY")).toBe(true)
    const findings = metaDataSecretFindings(values, "MANIFEST")
    expect(findings.map((f) => f.code)).toContain("MANIFEST_METADATA_HARDCODED_SECRET")
  })
})

const DEEPLINK_XMLTREE = [
  "N: android=http://schemas.android.com/apk/res/android",
  "  E: manifest (line=1)",
  '    A: package="com.app" (Raw: "com.app")',
  "    E: application (line=2)",
  "      E: activity (line=3)",
  '        A: android:name(0x01010003)="com.app.DeepLinkActivity" (Raw: "...")',
  "        A: android:exported(0x01010010)=(type 0x12)0xffffffff",
  '        A: android:taskAffinity(0x0101001e)="com.evil.affinity" (Raw: "com.evil.affinity")',
  "        E: intent-filter (line=4)",
  "          E: category (line=5)",
  '            A: android:name(0x01010003)="android.intent.category.BROWSABLE" (Raw: "...")',
  "          E: data (line=6)",
  '            A: android:scheme(0x01010027)="https" (Raw: "https")',
].join("\n")

describe("parseExportedComponents deep-link surface", () => {
  test("flags deeplink without autoVerify, browsable, and custom task affinity", () => {
    const codes = parseExportedComponents(DEEPLINK_XMLTREE, "com.app").map((f) => f.code)
    expect(codes).toContain("MANIFEST_DEEPLINK_NO_AUTOVERIFY")
    expect(codes).toContain("MANIFEST_BROWSABLE_EXPORTED_ACTIVITY")
    expect(codes).toContain("MANIFEST_CUSTOM_TASK_AFFINITY")
  })
})

describe("compliance findings", () => {
  const summary: ApkEntrySummary = {
    totalEntries: 1,
    totalCompressedBytes: 0,
    totalUncompressedBytes: 0,
    dexFiles: [],
    nativeLibraries: ["lib/armeabi-v7a/x.so"],
    nativeArchitectures: ["armeabi-v7a"],
    legacySignatureFiles: [],
    hasManifest: true,
    hasResourcesTable: false,
  }

  test("flags outdated targetSdk and missing arm64", () => {
    const metadata: ApkMetadata = { targetSdk: "30" }
    const codes = complianceFindings(metadata, summary, true).map((f) => f.code)
    expect(codes).toContain("COMPLIANCE_TARGET_SDK_OUTDATED")
    expect(codes).toContain("COMPLIANCE_MISSING_ARM64")
  })

  test("degrades when aapt missing and targetSdk unknown", () => {
    const codes = complianceFindings({}, { ...summary, nativeArchitectures: [] }, false).map((f) => f.code)
    expect(codes).toContain("COMPLIANCE_MISSING_MANIFEST_SDK")
  })
})

const APKSIGNER_OUTPUT = [
  "Verifies",
  "Verified using v1 scheme (JAR signing): true",
  "Verified using v2 scheme (APK Signature Scheme v2): false",
  "Verified using v3 scheme (APK Signature Scheme v3): false",
  "Number of signers: 1",
  "Signer #1 certificate DN: CN=Android Debug, O=Android, C=US",
  "Signer #1 certificate SHA-256 digest: aabbccddeeff00112233",
  "Signer #1 key algorithm: RSA",
  "Signer #1 key size (bits): 1024",
].join("\n")

const KEYTOOL_OUTPUT = [
  "Owner: CN=Android Debug, O=Android, C=US",
  "Issuer: CN=Android Debug, O=Android, C=US",
  "Serial number: 1",
  "Valid from: Thu Jan 01 00:00:00 UTC 2015 until: Fri Jan 01 00:00:00 UTC 2016",
  "Certificate fingerprints:",
  "\t SHA256: AA:BB:CC:DD:EE:FF:00:11:22:33",
  "Signature algorithm name: SHA1withRSA",
  "Subject Public Key Algorithm: 1024-bit RSA key",
].join("\n")

describe("signing-audit", () => {
  test("parses apksigner scheme flags and cert basics", () => {
    const { schemes, certs } = analyzeApksignerVerbose(APKSIGNER_OUTPUT)
    expect(schemes.v1).toBe(true)
    expect(schemes.v2).toBe(false)
    expect(certs[0]?.dn).toContain("Android Debug")
    expect(certs[0]?.keySize).toBe(1024)
  })

  test("parses keytool printcert validity and signature algorithm", () => {
    const [cert] = analyzeCertPrint(KEYTOOL_OUTPUT)
    expect(cert?.signatureAlgorithm).toBe("SHA1withRSA")
    expect(cert?.keySize).toBe(1024)
    expect(cert?.validUntil?.getUTCFullYear()).toBe(2016)
  })

  test("derives debug cert, expiry, weak key and scheme findings", () => {
    const { schemes } = analyzeApksignerVerbose(APKSIGNER_OUTPUT)
    const certs = analyzeCertPrint(KEYTOOL_OUTPUT)
    const codes = buildSigningFindings({
      schemes,
      certs,
      minSdk: 21,
      now: new Date("2026-01-01T00:00:00Z"),
    }).map((f) => f.code)
    expect(codes).toContain("SIGNING_DEBUG_CERTIFICATE")
    expect(codes).toContain("SIGNING_CERT_EXPIRED")
    expect(codes).toContain("SIGNING_WEAK_KEY")
    expect(codes).toContain("SIGNING_SCHEME_V2V3_MISSING")
    expect(codes).toContain("SIGNING_V1_ONLY_JANUS")
    expect(codes).toContain("SIGNING_CERT_FINGERPRINT")
  })
})

describe("report severity sort", () => {
  test("orders by severity, stable within equal severity", () => {
    const findings: Finding[] = [
      { severity: "info", code: "I1", title: "", detail: "", recommendation: "" },
      { severity: "critical", code: "C1", title: "", detail: "", recommendation: "" },
      { severity: "medium", code: "M1", title: "", detail: "", recommendation: "" },
      { severity: "medium", code: "M2", title: "", detail: "", recommendation: "" },
      { severity: "high", code: "H1", title: "", detail: "", recommendation: "" },
    ]
    expect(sortFindingsBySeverity(findings).map((f) => f.code)).toEqual(["C1", "H1", "M1", "M2", "I1"])
  })

  test("uses confidence as a secondary ordering key", () => {
    const findings: Finding[] = [
      { severity: "medium", confidence: "low", code: "LOW", title: "", detail: "", recommendation: "" },
      { severity: "medium", confidence: "confirmed", code: "CONFIRMED", title: "", detail: "", recommendation: "" },
      { severity: "medium", confidence: "high", code: "HIGH", title: "", detail: "", recommendation: "" },
    ]
    expect(sortFindingsBySeverity(findings).map((finding) => finding.code)).toEqual(["CONFIRMED", "HIGH", "LOW"])
  })
})
