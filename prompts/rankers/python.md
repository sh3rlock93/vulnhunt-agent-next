---
language: python
---

Boost files that:
- Register HTTP routes (FastAPI APIRouter, Flask Blueprint, Django urls).
- Call `requests.*`, `httpx.*`, or similar with non-constant URLs.
- Use `pickle`, `yaml.load`, `subprocess` with `shell=True`, `eval`, `exec`.
- Handle auth: JWT encode/decode, session cookies, OAuth callbacks.
- Talk to cloud providers (boto3, google.cloud, azure) with dynamic creds.
