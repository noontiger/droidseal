# Third-party software, tools, and services

DroidSeal source code, documentation and examples are MIT-licensed unless a file says otherwise.
Third-party components keep their own licenses, notices, service terms and redistribution conditions.
DroidSeal does not relicense those components.

## Exact executable inventory

The release build does not rely on a manually maintained list of runtime JavaScript packages.
`Bun.build({ metafile: true })` records every input that enters the executable. The build then:

1. maps each `node_modules` input to its exact package and version;
2. adds explicitly embedded native runtime packages, including `@opentui/core-win32-x64`;
3. requires a declared license and a package LICENSE/COPYING/NOTICE file;
4. copies those license files into `dist/third-party/licenses/`;
5. generates `bundle-components.json`, `bundle-sbom.cdx.json` and
   `THIRD_PARTY_NOTICES.generated.md`;
6. records every compliance artifact's size and SHA-256 in `droidseal-build.json`.

`bun run release:check` fails if a package lacks license evidence, if the generated inventory is
missing, or if any generated artifact no longer matches its recorded hash. Build-only tools that do
not enter the executable remain documented here and in the repository `licenses/` directory.

## Direct application and build components

| Component | Pinned version | Role | License |
| --- | ---: | --- | --- |
| Bun | 1.3.14 | bundler, compiler and embedded runtime | Bun is MIT; linked libraries are listed by Bun; JavaScriptCore/WebKit is LGPL-2.0-only; Bun-pinned TinyCC is LGPL-2.1-only |
| `@opentui/core` | 0.4.5 | terminal UI runtime and Windows native core | MIT |
| `@opentui/solid` | 0.4.5 | Solid renderer and build plugin | MIT |
| `solid-js` | 1.9.12 | reactive UI runtime | MIT |
| `terser` | 5.49.0 | release minifier and Web asset processing | BSD-2-Clause |
| `@types/bun` | 1.3.14 | development type declarations | MIT |
| TypeScript | 5.9.3 | development compiler | Apache-2.0 |

Pinned repository copies:

- `licenses/Bun-1.3.14-LICENSE.md`
- `licenses/Bun-LGPL-RELINKING.md`
- `licenses/LGPL-2.0-only.txt`
- `licenses/TinyCC-12882eee-COPYING`
- `licenses/OpenTUI-MIT.txt`
- `licenses/SolidJS-MIT.txt`
- `licenses/Terser-BSD-2-Clause.txt`

The generated release inventory is authoritative for code that actually enters a particular
executable. `bun.lock` remains authoritative for the broader development dependency graph.

## Bun and LGPL review

Bun 1.3.14's official license states that Bun itself is MIT-licensed and statically links
JavaScriptCore/WebKit under LGPL-2. It also states that users must have an opportunity to modify and
relink that library. The release material therefore pins:

- Bun tag `bun-v1.3.14`;
- WebKit commit `5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b`, taken from that Bun tag's build scripts;
- the standard LGPL-2.0-only text;
- TinyCC commit `12882eee073cfe5c7621bcfadf679e1372d4537b`, taken from that Bun tag's build scripts, and its LGPL-2.1 license text;
- public DroidSeal source, lockfile and executable build script;
- a step-by-step modified-runtime relink procedure.

See `licenses/Bun-LGPL-RELINKING.md`. A distributor must keep the exact DroidSeal, Bun, WebKit and TinyCC
sources available for as long as it offers the binary. If upstream URLs are not sufficient for its
channel or jurisdiction, it must mirror the exact source revisions next to the release. Changing Bun,
WebKit, TinyCC or the executable build method requires a new review.

This is an engineering compliance review, not a legal certification. A distributor that requires a
formal opinion must obtain one for its jurisdiction and distribution channel.

## Optional external Android tools

DroidSeal may discover, download, install or invoke Bun, a JDK and `keytool`, Android SDK command-line
tools and Build Tools, `aapt`, `aapt2`, `zipalign`, `apksigner`, Gradle and a target project's Gradle
Wrapper. These tools are not covered by DroidSeal's MIT license.

The repository and npm package do not redistribute a JDK or Android SDK. `bundle-toolchain.ts` lets a
user fetch and verify tools on its own authorized machine. Eclipse Temurin is GPLv2 with Classpath
Exception. Android SDK components remain subject to Google's terms and normally must not be
redistributed as part of DroidSeal.

The generated local `dependencies/` and `droidseal-bundle/` directories are ignored and are not part
of the public source repository or npm package.

## Community documents and trademarks

`CODE_OF_CONDUCT.md` is adapted from Contributor Covenant 2.1 under CC BY 4.0. Android, Java, Gradle,
Bun, OpenTUI, Solid and other third-party names and marks belong to their respective owners. Their
appearance only describes compatibility or technical use and does not imply endorsement.
