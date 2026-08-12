import { buildZip, inflateEntry, parseRawZip, type OutEntry } from "./harden-manifest.ts"

async function readWholeFile(apkPath: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(apkPath).arrayBuffer())
}

// Copy every ZIP entry verbatim (compressed bytes + crc/sizes/method/flags) except the
// named entries, then write a normalized ZIP. No recompression, length-preserving per entry.
// Returns the list of entries actually removed. Writes nothing extra when nothing matched.
export async function stripApkEntries(
  inputApk: string,
  outputApk: string,
  names: readonly string[],
): Promise<{ removed: string[] }> {
  const removalSet = new Set(names)
  const bytes = await readWholeFile(inputApk)
  const entries = parseRawZip(bytes)
  const removed: string[] = []
  const kept: OutEntry[] = []
  for (const entry of entries) {
    if (removalSet.has(entry.name)) {
      removed.push(entry.name)
      continue
    }
    kept.push({
      name: entry.name,
      method: entry.method,
      crc32: entry.crc32,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      flags: entry.flags,
      data: entry.data,
    })
  }
  if (removed.length === 0) return { removed }
  await Bun.write(outputApk, buildZip(kept))
  return { removed }
}

// Read the plaintext bytes of a single named ZIP entry (inflating deflate as needed).
// Returns undefined when the entry is absent.
export async function extractApkEntryBytes(apkPath: string, name: string): Promise<Uint8Array | undefined> {
  const bytes = await readWholeFile(apkPath)
  const entries = parseRawZip(bytes)
  const entry = entries.find((candidate) => candidate.name === name)
  if (!entry) return undefined
  return inflateEntry(entry)
}
