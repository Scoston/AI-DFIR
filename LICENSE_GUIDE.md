# AI-DFIR Licensing Guide

## Project license

AI-DFIR source code and project-authored documentation are released under the
**Apache License 2.0** unless a file explicitly states otherwise. The complete
license text is in `LICENSE`.

The Apache license covers AI-DFIR's original source. It does **not** change the
license of optional Python packages, provider SDKs, models, datasets, test
artifacts, standards, or external services.

## Important optional PDF dependency

`evil_font_forensics.py` can use PyMuPDF (`fitz`) when it is installed, but the
module degrades safely when it is absent. PyMuPDF is offered by Artifex under
AGPL and commercial licensing. For that reason AI-DFIR does **not** install it
in the default requirements.

Install the PDF extra only after reviewing your use case:

```bash
pip install -r requirements-pdf-agpl.txt
```

If AGPL obligations do not fit your distribution or hosted-service model, use
an independently licensed PDF rendering/extraction pipeline and feed its output
into `representation_differential.py`, or obtain an appropriate commercial
license from the dependency vendor.

## Enterprise optional dependencies

The enterprise profile uses provider SDKs and PostgreSQL drivers. Their licenses
remain their own. In particular, Psycopg 3 is distributed under LGPL-3.0-only.
AI-DFIR does not vendor Psycopg source into this repository.

## Models and data

AI-DFIR does not grant rights to AI model weights, provider telemetry, customer
content, logs, prompts, or datasets analyzed with the platform. Confirm that
collection and processing are authorized by your organization and applicable
law/policy.

## Release review

Before a public or commercial release:

1. run `python scripts/license_inventory.py`;
2. review `THIRD_PARTY_NOTICES.md`;
3. review optional extras actually shipped in your deployment image;
4. have organizational counsel or your open-source program office review any
   distribution-specific obligations.

This document describes the project's intended licensing structure; it is not
legal advice.
