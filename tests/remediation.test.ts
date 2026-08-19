import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { writeRemediationBundle } from "../src/core/remediation.ts"
import type { Finding } from "../src/core/types.ts"

describe("remediation bundle", () => {
  test("generates reviewable NSC/backup templates and a machine-readable plan", async () => {
    const findings: Finding[] = [
      {
        severity: "high",
        code: "NSC_CLEARTEXT_PERMITTED",
        title: "cleartext",
        detail: "test",
        recommendation: "disable cleartext",
      },
      {
        severity: "medium",
        code: "BACKUP_NO_EXCLUSION_RULES",
        title: "backup",
        detail: "test",
        recommendation: "exclude secrets",
      },
      {
        severity: "medium",
        code: "MANIFEST_EXPORTED_COMPONENT_UNPROTECTED",
        title: "component",
        detail: "test",
        recommendation: "set exported=false",
        evidence: ".ExportedActivity",
      },
    ]
    const reportDirectory = await mkdtemp(path.join(tmpdir(), "droidseal-remediation-"))
    const bundle = await writeRemediationBundle(reportDirectory, findings)
    expect(bundle).toBeDefined()

    const nsc = await readFile(
      path.join(bundle!.directory, "templates/res/xml/network_security_config.xml"),
      "utf8",
    )
    const backup = await readFile(
      path.join(bundle!.directory, "templates/res/xml/data_extraction_rules.xml"),
      "utf8",
    )
    const plan = JSON.parse(await readFile(bundle!.plan, "utf8"))
    const guide = await readFile(path.join(bundle!.directory, "README.md"), "utf8")

    expect(nsc).toContain('cleartextTrafficPermitted="false"')
    expect(nsc).toContain('<certificates src="system"')
    expect(backup).toContain('<exclude domain="sharedpref" path="."')
    expect(plan.mode).toBe("reviewable-templates")
    expect(plan.actions.find((action: { findingCode: string }) =>
      action.findingCode === "MANIFEST_EXPORTED_COMPONENT_UNPROTECTED").automation).toBe("manual-review")
    expect(guide).toContain("不会覆盖项目源码")
  })
})
