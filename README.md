# SafeInbox AI URL & Email Threat Engine

Manifest V3 browser extension and cloud intelligence backend for real-time URL and webmail threat inspection in Chrome, Edge, and Brave.

## Architecture

- **URL analysis**: `extension/src/url/urlThreatParser.js`
- **Email URL/domain extraction and shared text heuristics**: `extension/src/email/urlCandidateExtractor.js` and `extension/src/email/emailTextAnalyzer.js`
- **Email normalization, threat rules, and WordPiece tensors**: `extension/src/utils/textParser.js`
- **MV3 storage/cache, analysis bridge, and optional cloud sync**: `extension/src/background/serviceWorker.js`
- **URL inference worker**: `extension/src/ml/workers/urlInferenceWorker.js`
- **Optional off-thread email classifier**: `extension/src/ml/textMlWorker.js`
- **General page-link scanner and supported webmail integration**: `extension/src/content/urlLinkScanner.js` and `extension/src/content/contentScript.js`
- **Native Chrome Side Panel and its controller**: `extension/sidepanel.html` and `extension/src/ui/sidepanelController.js`
- **Content scripts load only on their relevant page types**; the webmail integration calls the same email-text analyzer used by the Side Panel.
- **The latest open webmail message is handed to the Side Panel** through temporary session storage and removed after scanning. The panel separates Summary, URL Scanner, and Context Scanning; it shows the arithmetic mean of text risk and average URL risk while retaining each URL's separate score.

Email analysis covers sender/recipient metadata, subject, and body with local heuristics. The WordPiece and ONNX pipeline is ready for a compatible local model and matching vocabulary, but neither trained text weights nor a tokenizer vocabulary are included. The scanner inspects URL text only. It never fetches a submitted URL, resolves its destination, or makes an SSRF probe. Analysis includes IDN/homograph and brand similarity signals, typosquatting/DGA characteristics, redirects, private/local IPs (including browser-canonicalized alternate IPv4 forms), encoded injection and traversal markers, and inline URL credentials.

The extension includes ONNX Runtime Web/WASM, but **does not include trained model weights**. Until a trained compatible model is supplied, the results explicitly use heuristics only. See [`extension/models/README.md`](extension/models/README.md) for the model input/output contract. Heuristics are indicators, not a guarantee of safety.

## Load in Chrome

1. Open `chrome://extensions` and enable **Developer mode**.
2. Select **Load unpacked** and choose [`extension/`](extension/).
3. Click the extension icon to open the Side Panel. Scan a URL or active-page links there; keep the panel open to see each supported webmail email analyzed as you open it. The panel refreshes when the active email changes or you switch tabs.

Chrome requires a user gesture to open a native Side Panel. It cannot be forced open merely because an email was opened. If you reload the extension in `chrome://extensions`, also refresh the Gmail/Outlook/Yahoo tab so its content script reconnects.

The locally packaged ONNX runtime assets are already in `extension/vendor/`; Python or a running server is not required.

## Backend & Cloud Architecture (FastAPI + Google Cloud Run)

The project includes an optional asynchronous Python/FastAPI backend in `backend/` designed for containerized deployment on **Google Cloud Run** and backed by **PostgreSQL** (with pgvector support for future threat embeddings).

### Key Backend Capabilities
- **Zero-PII Privacy Boundary**: Email text and email addresses are never persisted. Only SHA-256 digests, threat vectors, risk scores, and sanitized IOCs are stored in the audit trail.
- **Dual-Engine Persistence**: Automatically translates connection strings to `postgresql+asyncpg://` in production while falling back to zero-config `sqlite+aiosqlite:///./safeinbox.db` during local testing.
- **Database Migrations**: Managed via Alembic (`backend/alembic/`).
- **Google Cloud Run Ready**: Multi-stage unprivileged `Dockerfile`, autoscaling from 0 to 10 instances, with CI/CD via GitHub Actions (`.github/workflows/deploy-cloud-run.yml`).

### Running Backend Locally

Option A — With Docker Compose (includes PostgreSQL 16):
```bash
docker compose up --build
```

Option B — With Python Virtual Environment:
```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Run Backend Tests:
```bash
pytest backend/tests -v
```

### Connecting the Browser Extension to the Cloud Backend

1. In the extension Side Panel, click **Cloud Threat Intel**.
2. Enter your backend URL (`http://localhost:8080` for local dev or your Cloud Run URL `https://safeinbox-api-xxx.a.run.app`).
3. Click **Connect**. The badge will indicate live connectivity and global IOC synchronization.
4. *Autonomy Guarantee*: If the cloud backend is offline, unreachable, or unconfigured, the extension transparently falls back 100% to client-side heuristics and ONNX runtime without blocking the user.

## Test and update runtime assets

Requires Node.js 20 or later:

```powershell
npm install
npm test
npm run check:email-demo
npm run setup:email-demo
npm run sync:onnx-runtime
```

`npm run sync:onnx-runtime` copies the installed ONNX Runtime Web JS/WASM files into the loadable extension directory. Email body URLs, hyperlink targets, and bare domains are normalized and deduplicated before sequential analysis. Safe/Threat feedback labels are stored locally (bounded to 100 samples per type) for possible future training; they do not train or change the current model. A trained ONNX model is still required for learned predictions; the current package uses parser heuristics.

See [`docs/url-threat-engine.md`](docs/url-threat-engine.md) and [`docs/email-text-engine.md`](docs/email-text-engine.md) for architecture, implementation plans, and model contracts, and [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) for the project change log.
