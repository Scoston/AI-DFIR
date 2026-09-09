# Third-Party Dependency Notice

AI-DFIR does not vendor these packages in the source archive. They are installed
separately by the operator. The list below is an operational inventory, not a
substitute for the upstream license text.

| Dependency | Role | Typical upstream license | Default? |
|---|---|---|---|
| cryptography | signatures, X.509, AES-GCM | Apache-2.0 OR BSD-3-Clause | yes |
| requests | HTTP provider collection | Apache-2.0 | yes |
| PyJWT | OIDC/JWT verification | MIT | yes |
| rfc8785 | A2A JCS canonicalization | Apache-2.0 | yes |
| asn1crypto | RFC 3161 request/response ASN.1 parsing | MIT | yes |
| OpenSSL 3 executable | offline timestamp signature and certificate-chain verification | Apache-2.0 | operator-installed for timestamps |
| fontTools | font/glyph analysis | MIT | yes |
| defusedxml | bounded DOCX XML parsing | PSF License | yes |
| tinycss2 | bounded static CSS syntax parsing | BSD-3-Clause | yes |
| NumPy | numeric analysis | BSD-3-Clause | yes |
| pandas | data analysis | BSD-3-Clause | yes |
| scikit-learn | statistical/ML analysis | BSD-3-Clause | yes |
| Matplotlib | charts | Matplotlib/PSF-style | yes |
| huggingface_hub | model artifact acquisition | Apache-2.0 | yes |
| safetensors | model artifact parsing | Apache-2.0 | yes |
| PyTorch | model/activation analysis | BSD-3-Clause | model profile |
| Transformers | model/activation analysis | Apache-2.0 | model profile |
| Accelerate | model loading/runtime | Apache-2.0 | model profile |
| Psycopg 3 | PostgreSQL metadata | LGPL-3.0-only | enterprise profile |
| boto3 | AWS collection/KMS/S3 | Apache-2.0 | enterprise profile |
| Azure Identity | Azure authentication | MIT | enterprise profile |
| Azure Key Vault Keys | Azure KMS adapter | MIT | enterprise profile |
| Google Cloud KMS | Google KMS adapter | Apache-2.0 | enterprise profile |
| PyMuPDF | optional PDF extraction | **AGPL or commercial** | **optional only** |
| Poppler distribution packages | isolated PDF raster/OCR image | review exact installed copyright notices | optional image only |
| Tesseract and English OCR model | isolated PDF raster/OCR image | Apache-2.0; review exact distribution notices | optional image only |
| Liberation fonts | isolated PDF raster/OCR image | SIL Open Font License 1.1 | optional image only |

The renderer's native packages are inventoried in `/opt/ai-dfir/packages.txt`
inside the image, with notices under `/usr/share/doc/`. The Python inventory
command below does not inventory native packages. See the upstream
[Tesseract license](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE)
and [Liberation font license](https://github.com/liberationfonts/liberation-fonts/blob/main/LICENSE),
and the [optional renderer guide](docs/reference/ISOLATED_PDF_RENDERING_V1.7.md).

Always verify the license metadata for the exact version you distribute. Use:

```bash
python scripts/license_inventory.py
```
