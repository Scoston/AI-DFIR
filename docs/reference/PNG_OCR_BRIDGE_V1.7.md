# Bounded PNG OCR bridge (v1.7)

`v17_png_ocr.py` adds one narrowly defined visible-input format without adding a
second native renderer to the host. It accepts only the same bounded 8-bit
grayscale PNG profile already validated by `v17_pdf_render.png_dimensions`, wraps
the validated PNG predictor stream deterministically as a one-page PDF image
XObject, and sends that derived PDF through the existing isolated PDF renderer.

This is an explicit bridge, not a claim that arbitrary images are safe to parse.
RGB/RGBA, indexed-color, 16-bit, interlaced, malformed, trailing-data, excessive,
and unsupported PNGs fail before Docker is invoked.

## Why use a bridge

The project already has a qualified container boundary for Poppler rasterization
and English Tesseract OCR. Reusing it avoids introducing a second host-native image
library or a second Docker-control implementation. The host performs only the
existing bounded grayscale PNG validation and deterministic PDF object assembly.
The original compressed IDAT stream is embedded as a PDF `/FlateDecode` image with
PNG predictor parameters; Poppler performs the native decode/raster operation
inside the isolated container.

The bridge preserves two identities:

- the exact original PNG SHA-256, byte size, width and height; and
- the exact deterministic bridge-PDF SHA-256 and byte size.

A successful capture also retains the isolated raster observation, OCR text,
renderer image ID, worker/package/model/font hashes, tool versions, isolation
observations, and cleanup result.

## Fixed profile

| Boundary | Requirement |
| --- | --- |
| Source | One regular non-symlink PNG snapshot, at most 5 MiB |
| PNG profile | 8-bit grayscale, non-interlaced, 1-2,048 pixels per side, bounded zlib expansion, only IHDR/optional pHYs/IDAT/IEND chunks |
| Bridge | Deterministic one-page PDF; original validated IDAT bytes embedded with PNG predictor 15 |
| Native execution | Existing pinned isolated PDF renderer container; no host-native image decoder |
| OCR | Existing Tesseract English profile; at most 16 KiB UTF-8 text |
| Custody | Original `source.png`, exact `bridge.pdf`, `observed.png`, `visible.txt`, and final `png-ocr.json` receipt |
| Claims | Source authenticity false; complete visible rendering false; OCR accuracy false; collection completeness unknown |

The output directory uses mode 0700 and artifacts use exclusive mode-0600 writes.
The completion receipt is written last. Existing destinations are not replaced.

## Operator workflow

Build and qualify the renderer image exactly as described in
[Isolated PDF rendering](ISOLATED_PDF_RENDERING_V1.7.md), then use its immutable
local image ID:

```sh
python scripts/qualify_png_ocr_v17.py \
  --image-id sha256:REPLACE_WITH_64_HEX_DIGITS \
  --out-dir /new/png-qualification

python v17_png_ocr.py /evidence/image.png \
  --image-id sha256:REPLACE_WITH_64_HEX_DIGITS \
  --out-dir /new/png-observation
```

No image is pulled automatically. Docker daemon access, the host kernel, the
selected image, and its distribution packages remain operator-controlled trusted
infrastructure.

## Native qualification

The existing `Isolated PDF Rendering` GitHub workflow now runs the PNG bridge
regression suite and a separate actual PNG qualification against the same built
image. The native PNG qualification uses only deterministic synthetic material:

- a high-contrast grayscale bitmap spelling `HUMAN RESOURCES`, which must survive
  bridge construction, isolated rasterization, and OCR;
- a blank grayscale image, which must remain without OCR text;
- malformed input, which must fail before native execution; and
- an RGB PNG, which is deliberately outside the supported profile and must fail
  before native execution.

The workflow retains the synthetic PNG qualification artifacts for 14 days.
Passing this profile proves only that the tested image and host completed these
bounded cases. It does not prove OCR accuracy for arbitrary images, arbitrary PNG
compatibility, source authenticity, production suitability, or complete rendering.

## Remaining work

JPEG, color PNG, screenshots with alpha/transparency, additional OCR languages,
more layouts/fonts, and other image/document formats remain separate qualification
items. Any expansion should preserve explicit format limits, original/derived byte
bindings, actual target-runtime acceptance, and conservative evidence claims.
