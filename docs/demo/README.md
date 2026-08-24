# AI-DFIR v1.6 Demo

The demo is built entirely from synthetic evidence. It does not require production credentials, a cloud tenant, or customer data.

## Reproduce the demo

```bash
./install.sh default
source .venv/bin/activate
python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
python tests/run_synthetic_scenarios.py
python v16_selftest.py --out /tmp/ai-dfir-v16-demo
```

Watch/download the captioned demo: [`AI-DFIR-v1.6.0-demo.mp4`](AI-DFIR-v1.6.0-demo.mp4).

See `DEMO_SCRIPT.md` for the walkthrough narrative. Regenerate the video with:

```bash
python scripts/generate_demo_case.py
python scripts/make_demo_video.py
```

The video generator requires Pillow and FFmpeg. It does not require production credentials or network access.

## What the demo shows

1. install and synthetic test generation;
2. 111-pack evidence-quality validation;
3. EvilFont/representation-integrity detection;
4. A2A/runtime trust and temporal authority;
5. read-only Analyst Workbench;
6. Production Platform Assurance;
7. human-in-the-loop decision gates;
8. production-readiness distinction.

## Accessibility

A matching subtitle file is included: [`AI-DFIR-v1.6.0-demo.srt`](AI-DFIR-v1.6.0-demo.srt).
