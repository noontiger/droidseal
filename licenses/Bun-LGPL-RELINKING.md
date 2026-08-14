# Bun LGPL-linked components: source and relinking information

This notice applies to the official Windows x64 DroidSeal executable produced by `scripts/build.ts`.
It is engineering compliance material, not a substitute for legal advice in a distributor's jurisdiction.

## Distributed combination

- DroidSeal source license: MIT
- Bun runtime version: 1.3.14
- Bun source tag: https://github.com/oven-sh/bun/tree/bun-v1.3.14
- Bun license at that tag: https://raw.githubusercontent.com/oven-sh/bun/bun-v1.3.14/LICENSE.md
- Bun-pinned WebKit revision: `5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b`
- Patched WebKit source: https://github.com/oven-sh/WebKit/tree/5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b
- Standard LGPL-2.0-only text distributed with DroidSeal: `licenses/LGPL-2.0-only.txt`
- Bun-pinned TinyCC revision: `12882eee073cfe5c7621bcfadf679e1372d4537b`
- Patched TinyCC source: https://github.com/oven-sh/tinycc/tree/12882eee073cfe5c7621bcfadf679e1372d4537b
- TinyCC LGPL-2.1 text distributed with DroidSeal: `licenses/TinyCC-12882eee-COPYING`

Bun's tag-specific license states that Bun itself is MIT-licensed, that it statically links
JavaScriptCore/WebKit under LGPL-2 and TinyCC under LGPL-2.1, and that users must have an opportunity
to modify and relink the LGPL libraries. The same Bun license lists its other statically linked
libraries and their licenses.

## Corresponding source and build material

The public DroidSeal repository provides the application source, exact lockfile, build script and
the unmodified command that creates the executable. The exact upstream revisions above provide the
Bun runtime source and the patched JavaScriptCore/WebKit and TinyCC sources used by Bun 1.3.14.

For each binary release, the distributor must keep every exact source location above available for at least
as long as that binary is offered. If relying on an upstream URL is not acceptable for the chosen
distribution channel or jurisdiction, mirror the Bun tag and pinned WebKit and TinyCC revisions as release assets
and provide equivalent download access next to the binary. Do not publish a binary if those exact
sources and this repository revision cannot be obtained.

## Relinking procedure

1. Check out DroidSeal at the source revision identified by the npm/GitHub Release tag.
2. Check out Bun at `bun-v1.3.14`.
3. Check out `oven-sh/WebKit` at `5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b` and `oven-sh/tinycc` at
   `12882eee073cfe5c7621bcfadf679e1372d4537b` in the locations expected by Bun's dependency build.
4. Modify JavaScriptCore/WebKit under LGPL-2.0-only and/or TinyCC under its LGPL-2.1 terms.
5. Build Bun using the tag's build instructions and the locally modified dependency source. Bun's
   tag-specific license describes the JavaScriptCore build/relink route; its build scripts pin the
   WebKit and TinyCC revisions. For TinyCC, preserve the local modification by pointing
   `scripts/build/deps/tinycc.ts` at the modified source/fork before rebuilding Bun.
6. In the DroidSeal checkout, install the exact dependencies from `bun.lock` and run the locally built
   Bun executable against `scripts/build.ts`. This repeats the bundle, Terser minification and
   `bun build --compile` stages with the modified runtime.
7. The resulting `dist/droidseal.exe` is the relinked executable. Its SHA-256 and runtime package
   inventory are regenerated in `dist/droidseal-build.json` and `dist/third-party/`.

The build must not use a different Bun version silently. `scripts/build.ts` and the release checker
fail when the executable builder does not match `packageManager: bun@1.3.14` or when the pinned Bun
license/relinking files are absent.

## Distributor checklist

- Include `licenses/Bun-1.3.14-LICENSE.md` without character corruption.
- Include `licenses/LGPL-2.0-only.txt`, `licenses/TinyCC-12882eee-COPYING` and this file.
- Include the generated exact bundle inventory, SBOM, notices and copied npm license texts.
- Keep the DroidSeal source revision, Bun tag, WebKit commit and TinyCC commit available next to the binary.
- Repeat the review whenever Bun, WebKit, TinyCC, OpenTUI or the binary build method changes.

This review concludes that the engineering package exposes the exact sources and a reproducible
relink path. A distributor that needs a formal legal opinion must obtain one before representing the
package as legally certified or before using a distribution channel with additional requirements.
