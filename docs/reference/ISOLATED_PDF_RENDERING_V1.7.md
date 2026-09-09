# Isolated PDF rendering and OCR (v1.7)

`v17_pdf_render.py` is an optional, explicit PDF raster-to-OCR capture adapter.
Its dedicated GitHub workflow must qualify actual rendering on a Linux x86-64,
cgroup-v2 Docker host. The ordinary selftest and regression suite use synthetic
protocol replies and do **not** qualify native rendering. See the workflow and
its retained `qualification.json` for observations from a particular image.

## Operator workflow

Build `deploy/render/Dockerfile` with an approved, digest-pinned Debian Python
base using the same `PYTHON_IMAGE` build argument as the production image. The
build installs Poppler, Tesseract with the English model, and Liberation fonts.
Network access is required during image construction. Review and qualify each
rebuilt image; distribution package versions can change even with a pinned base.

```sh
docker build --build-arg "PYTHON_IMAGE=$PYTHON_IMAGE" --file deploy/render/Dockerfile --tag ai-dfir-render:local .
docker image inspect --format '{{.Id}}' ai-dfir-render:local
python scripts/qualify_pdf_render_v17.py --image-id sha256:REPLACE_WITH_64_HEX_DIGITS --out-dir /new/synthetic-qualification
python v17_pdf_render.py /evidence/input.pdf --image-id sha256:REPLACE_WITH_64_HEX_DIGITS --out-dir /new/render-observation
```

Supply the exact local image ID, never the tag. Rendering does not pull an image.
The local Docker daemon at `/var/run/docker.sock`, its host kernel, the Docker
executable, and the selected image are trusted operator infrastructure. Image
labels and self-reported hashes are not signatures or independent attestation.
Docker daemon access is privileged; use an appropriate dedicated analysis host.
The adapter does not manage daemon installation or grant that access.

## Fixed execution profile

| Boundary | Required limit or control |
| --- | --- |
| Input | Regular non-symlink PDF snapshot, at most 8 MiB; at most four unencrypted pages |
| Raster | Poppler P5 grayscale raster, fixed worker PNG encoding, 144 DPI with longest side capped at 2,048 pixels; 5 MiB per image |
| OCR | Tesseract English, OEM 1, PSM 6; at most 16 KiB UTF-8 text across pages |
| Container | UID/GID 65532, all capabilities dropped, no new privileges, built-in seccomp, read-only root |
| Namespaces | No network, no host mounts, private cgroup namespace, no shared IPC or PID namespace |
| Resources | 512 MiB memory, no swap, one CPU rate, 64 PIDs; 64 MiB noexec/nosuid/nodev temporary filesystem |
| Process limits | Zero core files, 8 MiB file writes, 30 CPU seconds per process, 64 open files |
| Deadlines | 60 seconds for the attached container; bounded setup, inspection, cleanup and individual native commands |
| Response | 32 MiB wire cap before host reads; strict JSON, source/image/text hashes, bounded PNG decompression; 256 KiB receipt |

Docker enforces the container controls; the worker checks kernel observations
before reading evidence or invoking a native parser. The parent inspects daemon
capabilities, the exact image, container configuration, exit status and OOM state,
and removes its uniquely named container after every attempted execution. A
cleanup failure cannot produce a successful report. If cleanup fails, the error
retains that container's name for operator diagnosis.

The PNG reader on the host accepts a narrow grayscale profile and bounds zlib
decompression. Inside the container the worker validates Poppler's exact P5
header and pixel count and encodes grayscale PNG with the standard library;
Poppler's own PNG mode can emit RGB despite its grayscale option. Native PDF and
image parsing remain inside the container. Docker
isolation reduces exposure but shares the host kernel; this is not a claim of
perfect isolation or a replacement for deployment security review. Docker's
[container options](https://docs.docker.com/reference/cli/docker/container/run/),
[default seccomp profile](https://docs.docker.com/engine/security/seccomp/), and
[network-none driver](https://docs.docker.com/engine/network/drivers/none/)
describe the controls used here. The fixed OCR options follow
[Tesseract's command-line documentation](https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html).

## Retained observation and failure behavior

A successful capture creates a new private directory containing the exact
`source.pdf`, `page-NNN.png` images, `visible.txt`, and a final `render.json` receipt.
Files use exclusive creation, mode 0600 and fsync; the directory is mode 0700.
Existing output directories or source files are never replaced. The receipt is
written last. A partial directory without a valid complete receipt is incomplete.
The receipt binds the source, each image and OCR text, exact image ID, tool versions,
worker source, installed package inventory, English model and font hashes.

Success means a bounded raster/OCR observation was obtained. It does not establish
source authenticity, complete visible rendering, OCR accuracy, or collection
completeness. Those claims remain false or unknown. Unsupported inputs, malformed
responses, resource failures, and unavailable controls produce a high-severity
`pdf_rendering_incomplete` result. After a failed start, `rendering_performed` is
null because partial rendering may have occurred. Unavailable results never carry
an apparently complete set of artifacts. The command exits nonzero on failure.

To compare a retained OCR observation with a separately obtained machine-text
observation, supply `visible.txt` to the existing bounded representation comparator.
The comparison does not authenticate either source and does not replace review.
The adapter is explicit; it does not automatically promote evidence-gate decisions.

## Qualification and security review

`Isolated PDF Rendering` builds the image from the repository's configured pinned
base and now exercises ten available synthetic PDFs plus two rejection cases.
The available corpus includes baseline visible text, render-mode hidden machine
text, two pages, blank output, white-on-white source text, off-page source text,
clipped source text, a two-column layout, a 90-degree page rotation, and the
four-page upper boundary. Malformed and five-page PDFs must remain unavailable.

The three added representation-hostile cases deliberately retain machine-readable
source text that should not appear in the raster/OCR observation. Qualification
checks that the machine string remains present in the source bytes, absent from
`visible.txt`, and produces the existing critical representation divergence when
compared with the visible observation. Layout/boundary cases prove bounded native
processing and custody without turning OCR success into an accuracy claim. The
workflow also checks retained images/text/source hashes, expected baseline OCR
phrases, kernel isolation observations, and cleanup. Synthetic artifacts are
retained for 14 days. A failing or skipped actual-render step is not qualification.
Export the qualification artifacts and retain the image if longer-term
reproducibility is needed. No real evidence is uploaded by the workflow.

The focused suite covers forged claims and hashes, malformed PNGs and excessive
inflation, missing isolation controls, command failures and interruption, cleanup,
bounded CLI output, strict P5 encoding, and exclusive evidence storage. Only
fixed worker failure-stage names cross the failed-command boundary; native error
text and document metadata are discarded. The security review assumes
the parent code, daemon and pinned image are trusted; it makes no authenticity
claim for a compromised renderer. Languages beyond English, broader layouts and
fonts, additional document formats, larger curated corpora, other architectures,
rootless daemons, alternate kernels, and production deployment remain separately
qualified work.

The optional image introduces native components and their distribution license
notices; it does not add them to default Python requirements or vendor their
binaries. Retain and review the image's `/usr/share/doc/*/copyright` notices,
`/opt/ai-dfir/packages.txt`, and upstream licensing before redistributing an image.
[Poppler](https://poppler.freedesktop.org/) and
[Tesseract](https://tesseract-ocr.github.io/tessdoc/) are independently maintained.
