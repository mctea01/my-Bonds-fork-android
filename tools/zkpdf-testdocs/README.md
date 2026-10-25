# Reproducible synthetic zkPDF documents (M3d)

All names, identifiers, dates and QR contents are fictional. The PDFs visibly
identify themselves as synthetic. They must never be used as official documents.
No private user documents or personal data are inputs to this generator.

The generator is `SyntheticDocuments.kt` under
`test-servers/src/test/kotlin/diw/testservers/zkpdf/`. It writes one-page Word-like
content streams with one `BT /Tf /Tm /TJ /ET` sequence per displayed run. The
student document uses WinAnsi ASCII digits and Type0 Identity-H Chinese; the
travel document encodes all text, including digits, with Type0 CIDs. Both have a
public ToUnicode CMap. The student page has a real, deterministic QR image
encoding a fictional URL under the reserved `.invalid` domain.

## Generate and check

From the repository root, with JDK 21 and Android SDK 36 configured:

```sh
DIW_ZKPDF_WRITE_FIXTURES=1 ./gradlew :test-servers:test --tests '*SyntheticDocumentsTest'
./gradlew :test-servers:test --tests '*SyntheticDocumentsTest' --rerun
```

The first command writes the PDFs and public test root into
`test-servers/src/test/resources/zkpdf/`. Normal tests never rewrite committed
files. The second command checks the committed files against freshly generated
bytes. Each generation test also produces a second independent PKI and compares
all output bytes. Tests validate P3 signatures, WP2 text runs and digit maps,
empty-password RC4, negative fixture structure and PDFBox page rendering.

The fixed signing time is 2026-10-16T00:00:00Z. Test key material is derived from
public fixed seeds using the JDK SHA1PRNG and Bouncy Castle 1.85, with P-256 keys,
fixed certificate serials and 2020-2040 validity. It is loaded using the existing
`TestPki.create(directory)` path. Temporary key files are removed after loading;
only the public root certificate is committed. The CMS signer uses deterministic
ECDSA. These intentionally predictable test keys must never be reused in any
real service. No network time-stamp authority is contacted.

PDFBox 3.0.8 handles fixed-ID external-signing PDF serialization, and the existing
core `DocumentSigning.cms` produces and self-verifies the PAdES CMS signature.
Core intentionally refuses encrypted input in `signPdf`, and its incremental
writer randomizes the second document ID. This fixture-only container avoids
changing either production behavior. PDF document IDs and signature dates are fixed.

## Font subset

The committed subset allows fixture generation without Python or a font download.
To rebuild it, install `requirements.txt` in a virtual environment, then run:

```sh
python3 -I tools/zkpdf-testdocs/subset_font.py /path/to/NotoSansCJK-Regular.ttc
```

Source: Noto CJK `Sans2.004`, `Sans/OTC/NotoSansCJK-Regular.ttc`, face 2
(`NotoSansCJKsc-Regular`). `fonts/mapping.json` records the source SHA-256,
subset SHA-256 and exact CID/width mapping. The script preserves timestamps;
fontTools is pinned to 4.61.1. The raw CID-keyed CFF subset is embedded as CIDFontType0C in the Type0
font and remains licensed under OFL-1.1; see `fonts/OFL.txt` and the root NOTICE.
The standard-14 Helvetica resource supplies WinAnsi text without redistributing
any Helvetica font program. No new application or native dependency is added.

## Scope

These fixtures provide M3d inputs for Z1-Z14. They do not implement a prover or
claim that Z8/Z12 are already rejected by a full zkPDF circuit. Circuit acceptance
belongs to M3b/M3c, and production public-input binding belongs to WP4. The
post-signature revision is deliberately a valid incremental update that changes
page content; its earlier signature remains cryptographically intact while P3
reports `LaterChanges.OTHER`.
