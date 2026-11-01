# Project Context

## Current state

- The project features a dual architecture: an autonomous client-side browser extension in `extension/` and a modern asynchronous Python/FastAPI backend in `backend/`.
- In strict adherence to project requirements, the browser extension remains **100% usable independently** with client-side heuristics and local ONNX Web runtime, even when the backend is offline or unconfigured.
- The backend provides optional centralized threat intelligence, global IOC caching, and feedback aggregation targeting **Google Cloud Run** with **PostgreSQL** persistence (supporting pgvector for future threat embeddings) and zero-config SQLite local testing.
- Protocol & Transport Lockdown: Traffic between users/extension and the backend is strictly locked to **HTTPS over TCP**. Non-HTTPS access is rejected or redirected with HSTS (`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`). Insecure cleartext HTTP to remote backends is blocked client-side. The container exposes only TCP on port 8080 (`EXPOSE 8080/tcp`); non-TCP protocols (UDP, ICMP) and non-designated ports are dropped at the network edge.
- Scoped Webmail Isolation: Webmail platforms (`mail.google.com`, `outlook.live.com`, `outlook.office.com`, `mail.yahoo.com`) are excluded from generic page-link DOM scanning (`urlLinkScanner.js`). Scanning is strictly scoped to the active email message body via `contentScript.js`. The email platform's UI chrome (navigation folders, sidebar, top header, toolbar, avatar) is never scanned, outlined, or badged.
- The extension uses a native Chrome Side Panel (`extension/sidepanel.html`) with Summary, URL Scanner, and Context Scanning views. It accepts a URL or email text and listens for detected open emails on supported webmail pages.
- Email link targets, raw URLs, `www` links, and bare domains are normalized/deduplicated and scanned sequentially through the shared URL analyzer; sender/subject/body text is assessed separately. The combined email score is the arithmetic mean of text risk and the average URL risk; the highest individual URL risk is also shown.
- Chrome requires a user gesture to open a native Side Panel, so it cannot auto-open on email navigation. Once opened, the panel refreshes on email changes and active-tab switches. After reloading the extension, refresh the webmail tab to reconnect its content script. Page-level webmail inspection banners continue working with the panel closed.
- Browser-side heuristics remain active without a model. Safe/Threat labels and their local samples are retained in browser storage (latest 100 per type) and optionally synced to the Cloud backend when configured. No trained ONNX model weights are included, so learned predictions are not currently available.
- Privacy boundary: Zero-leak policy for raw email bodies and PII. No email body text, sender/receiver addresses, or subject lines are stored in backend database tables (`ThreatURL`, `ScanAuditLog`) or persistent cloud logs. Only cryptographic SHA-256 digests, threat vectors, risk scores, and sanitized IOCs are retained.
- Dataset & Storage Separation: URL storage and Text/Email storage are maintained in completely separate pipelines, caches, and database partitions. In the browser extension, `offline_url_feedback` and `offline_text_feedback` occupy separate keys, and `urlThreatScan:` / `emailThreatScan:` caches are distinct. In the backend, `threat_urls` handles URL IOCs while `scan_audit_logs` and `feedback_records` strictly partition URL and TEXT entries. Training data is strictly isolated from testing data; the backend includes deterministic hash-based train/val/test splitting (`backend/app/services/dataset_manager.py`) with mathematical proof of zero data leakage (`assert_zero_leakage`).
- The backend includes Alembic database migrations (`backend/alembic/`), multi-stage unprivileged Docker containerization, local `docker-compose.yml` with PostgreSQL 16 bound to localhost loopback, and automated GitHub Actions CI/CD workflows (`.github/workflows/ci.yml` and `.github/workflows/deploy-cloud-run.yml`).
- Both frontend test suite (63 tests) and backend pytest suite (15 tests) pass with 0 failures.

## Change log

### 2026-11-01 — Configure Neon Serverless PostgreSQL integration and Cloud Run Dockerfile

- Neon Serverless PostgreSQL Driver Integration (`backend/app/config.py`):
  - Updated `async_database_url` property to automatically sanitize incoming PostgreSQL connection strings for the `asyncpg` driver.
  - Automatically converts `postgres://` to `postgresql+asyncpg://`, strips incompatible libpq parameters (`sslmode`, `channel_binding`), and enforces `ssl=require` for secure remote cloud connections.
  - Successfully validated connection and ran `init_db()` against live Neon PostgreSQL instance, creating all primary tables (`users`, `terms_consents`, `threat_urls`, `scan_audit_logs`, `feedback_records`).
- Streamlined Production Dockerfile (`backend/Dockerfile`):
  - Replaced multi-stage build with a robust single-stage Debian slim container optimized for Google Cloud Run and Google Artifact Registry.
  - Added binary compilation dependencies for `asyncpg` and `greenlet`, direct system package installation, and container startup via `exec uvicorn app.main:app`.
- Configuration & Housekeeping (`.gitignore`):
  - Added `*.zip` to `.gitignore` to prevent deployment archives from being tracked in git.
- Validation:
  - All 63 extension tests passed (`npm test`).
  - All 15 backend tests passed (`pytest backend/tests -v`).
  - Remote Neon database connection and table initialization validated.

### 2026-11-01 — Enforce strict credential verification, Terms allowance isolation to Sign-Up, and automatic form clearing

- Terms & Conditions Allowance Exclusively on Sign-Up (`extension/welcome.html`, `extension/src/ui/welcomeController.js`):
  - Removed redundant Terms & Conditions checkbox (`#checkTermsSignIn`) and requirement from the Sign-In form (`#formSignIn`). Returning users sign in directly with email and password without being re-prompted.
  - Retained strict Terms & Conditions review view (`#authTermsReviewView`) during Sign-Up registration where users must review and confirm ("✓ I Agree to Terms & Create Account") before account creation and consent metadata logging (Email, IP, MAC sandbox note, Terms v1.0.0, Timestamp).
- Fixed Credential Verification & Blocked Unauthorized Progression (`extension/src/ui/welcomeController.js`, `extension/src/ui/sidepanelController.js`):
  - Removed permissive fallback in sign-in catch blocks that previously accepted invalid passwords when backend network responses were offline or rejected with 401.
  - Implemented local registered user store (`safeinbox_registered_users`) with cryptographic password salt & SHA-256 hash matching (`hashPasswordLocal`).
  - Both online (FastAPI backend) and offline (local store) sign-in flows now strictly reject invalid email addresses or incorrect passwords with "Invalid email or password." and halt further execution immediately.
- Implemented Complete Input Wiping across Auth States (`clearFormInputs` in `welcomeController.js` & `sidepanelController.js`):
  - Automatically resets and blanks all form input fields (`inputSignInEmail`, `inputSignInPassword`, `inputSignUpName`, `inputSignUpEmail`, `inputSignUpPassword`, `inputSignUpConfirm`) upon successful sign-in, successful sign-up, and modal closure.
  - When the user signs out (`btnSignOut`), all login and registration input fields and status banners are completely cleared, preventing any stale credentials or data from lingering in the login section.
- Validation:
  - All 63 extension tests passed (`npm test`).
  - All 15 backend tests passed (`pytest backend/tests -v`).
  - Synthetic email demo fixture passed (`node tools/check-email-demo.js`).
  - All JavaScript files passed `node --check`.

### 2026-11-01 — Add Terms and Conditions page, consent audit logging, and allowance enforcement on sign-in


- Created Dedicated Terms and Conditions Page (`extension/terms.html`, `extension/src/ui/terms.css`):
  - Formulated 10 comprehensive legal and operational compliance articles tailored specifically to SafeInbox AI:
    1. Acceptance of Terms & Scope of Service.
    2. Local-First Processing & Autonomous Operation.
    3. Scoped Webmail Isolation (Zero Inbox Disruption).
    4. General Web Search & External Website Inspection Opt-In.
    5. Zero-PII & Zero-Retention Privacy Commitment.
    6. Strict URL vs. Text Storage Partitioning & Zero-Leakage Datasets.
    7. Network Transport Lockdown (HTTPS over TCP Only).
    8. Terms Consent Logging & Telemetry Audit Record.
    9. Advisory Security Heuristics & Limitation of Liability.
    10. User Responsibilities & Termination.
  - Cleaned up `terms.html` by removing the interactive "Consent Status: Action Required" banner, ensuring the page opens instantly and reliably as a pure legal reference without network fetch requirements.
- Implemented In-Modal Terms Review Step upon Sign-Up Submission (`extension/welcome.html`, `extension/src/ui/welcomeController.js`):
  - When a user fills in signup credentials (Name, Email, Password, Confirm Password) and presses "Sign Up & Review Terms →", the modal transitions directly into `#authTermsReviewView` showcasing the complete scrollable Terms and Conditions.
  - Only when the user confirms with "✓ I Agree to Terms & Create Account" is the account created and consent metadata recorded (Email, Client IP, MAC/Device status, Version 1.0.0, Timestamp).
  - If the user clicks "✕ Decline & Cancel", execution halts and the page immediately reloads (`window.location.reload()`).
  - Added autonomous offline session handling in `welcomeController.js`: if the local backend is offline or unreachable, user signup and login gracefully create an authenticated local session rather than throwing an unhandled network error.
- Implemented Consent Audit Logging across Backend and Client (`backend/app/models/user.py`, `backend/app/schemas/auth.py`, `backend/app/routers/auth.py`, `backend/alembic/versions/b2c3d4e5f6a7_add_terms_consents_table.py`):
  - Created `TermsConsent` ORM model and database migration for `terms_consents` table tracking `user_id`, `email`, `ip_address`, `mac_address`, `terms_version`, `user_agent`, and `agreed_at`.
  - Updated `POST /api/v1/auth/signup` and `POST /api/v1/auth/signin` to record consent audit trails upon authentication.
  - Added `POST /api/v1/auth/terms-consent` and `GET /api/v1/auth/terms-consent/status` endpoints.
  - Client stores consent in `chrome.storage.local["safeinbox_terms_consent"]` (with `localStorage` fallback) capturing user email ID, client IP address, MAC/device status (`N/A (Browser Sandbox Restricted: W3C Anti-Fingerprinting Policy)`), terms version (`1.0.0`), and UTC timestamp.
- Validation:
  - All 63 extension tests passed (`npm test`).
  - All 15 backend tests passed (`pytest backend/tests -v`), including new tests for terms consent logging during sign up, sign in, and direct status verification.
  - Synthetic email fixture checks passed (`node tools/check-email-demo.js`).
  - All JavaScript files passed `node --check`.



### 2026-11-01 — Add User Sign In and Sign Up authentication system across backend and browser extension

- Built Backend Authentication Engine (`backend/app/models/user.py`, `backend/app/services/auth_service.py`, `backend/app/schemas/auth.py`, `backend/app/routers/auth.py`):
  - Created `User` ORM entity with `email` (unique index, lowercase normalized), `hashed_password`, `full_name`, `is_active`, and timezone-aware timestamps.
  - Implemented cryptographic password hashing using memory-hard `scrypt` with 16-byte random salts and constant-time digest verification (`secrets.compare_digest`).
  - Implemented RFC 7519 compliant HS256 JWT access token generation and validation (`create_access_token`, `decode_access_token`).
  - Added endpoints:
    - `POST /api/v1/auth/signup`: Validates email and minimum 8-character password, prevents duplicate registration, hashes password, and issues Bearer access token.
    - `POST /api/v1/auth/signin` (and `/login` alias): Authenticates credentials and returns Bearer token with user details.
    - `GET /api/v1/auth/me`: Protected profile endpoint requiring valid Bearer authentication.
  - Generated database migration `backend/alembic/versions/a1b2c3d4e5f6_add_users_table.py` for SQLite/PostgreSQL schema tracking.
- Built Extension Client-Side Auth UI & State (`extension/sidepanel.html`, `extension/src/ui/sidepanel.css`, `extension/src/ui/sidepanelController.js`, `extension/src/background/serviceWorker.js`):
  - Added header Account button (`#accountPillBtn`, `#accountPillLabel`) showing guest status or user display name.
  - Injected tabbed Authentication Modal (`#authModalBackdrop`) supporting instant switching between Sign In and Sign Up forms with real-time error handling and validation.
  - Added Account Profile view (`#authSignedInView`) displaying user avatar, name, email, connection status, and a Sign Out button.
  - Persisted auth session to `chrome.storage.local["safeinbox_auth"]`. Synchronizes in real time across browser tabs and panels.
  - Automatically injects `Authorization: Bearer <token>` into cloud threat scan and feedback sync API requests when authenticated.
  - Maintained 100% offline autonomy: guest/local heuristics remain fully operational when unauthenticated or when the backend is offline.
- Validation:
  - All 14 backend integration tests passed (`pytest backend/tests -v`), covering password hashing, user registration, duplicate prevention, validation errors, sign in, wrong password rejection, and `/me` profile extraction.
  - All 61 extension tests passed (`npm test`), including end-to-end verification of modal elements, controller auth methods, and service worker authorization header injection.
  - Synthetic email fixture checks passed (`node tools/check-email-demo.js`).
  - All extension JavaScript files passed `node --check`.

### 2026-10-31 — Add general website inspection opt-in prompt, remove analysis export controls, and implement webmail-only URL click tracking

- Implemented General Web Search Inspection Opt-In (`extension/src/content/urlLinkScanner.js`):
  - Added site inspection permission check querying `chrome.storage.local["site_inspection_preferences"]`.
  - On unconfigured non-webmail websites, injects an isolated Shadow DOM consent dialog asking: *"Do you want link safety inspections on [host]?"* with buttons `[Always Inspect]` and `[Leave It]`.
  - When the user selects `[Always Inspect]`, preference is persisted as `true` and link scanning begins immediately and on future visits.
  - When the user selects `[Leave It]`, preference is persisted as `false` and the website DOM is left untouched.
- Removed Export Analysis Controls (`extension/sidepanel.html`, `extension/src/ui/sidepanelController.js`):
  - Removed `#tab-audit` section, `#copyReportBtn` ("Copy Report"), and `#exportJsonBtn` ("Export JSON") from the Side Panel interface.
  - Cleaned up event listeners and guarded lingering controller references.
- Implemented Webmail-Only URL Click Tracking (`extension/src/content/contentScript.js`, `extension/sidepanel.html`, `extension/src/ui/sidepanelController.js`):
  - Created `recordWebmailUrlClick`: strictly records user clicks on suggested/audited URLs in webmail into `chrome.storage.local["webmail_url_clicks"]` (FIFO bounded to 500 items).
  - Schema captures `id`, `url`, `defanged`, `timestamp`, `date_iso`, `email_subject`, `sender`, `risk_score`, `risk_level`, `proceeded`, and `source`.
  - Strict Mail Boundary: general websites scanned by `urlLinkScanner.js` never record clicks. Non-webmail domains are rejected if `recordWebmailUrlClick` is called outside webmail.
  - Linked click listeners to flagged suspicious links (recording proceed/cancel user response), unflagged audited email body links, and Banner 1 audited hyperlink cards.
  - Added collapsible "Mail URL Click History" panel in the Side Panel with live click count badge, formatted click cards with defanged URLs, timestamps, risk badges, and a "Clear Log" button.
- Validation:
  - All 60 extension unit and integration tests passed (`npm test`).
  - All 10 backend integration tests passed (`pytest backend/tests -v`).
  - Synthetic email fixture checks passed (`node tools/check-email-demo.js`).
  - All extension JavaScript files passed `node --check`.

### 2026-10-31 — Enforce strict separation for URL vs Text storage and zero-leakage training vs testing datasets

- Created `backend/app/services/dataset_manager.py`:
  - `split_dataset`: Implements deterministic cryptographic hash-based partitioning across Train (80%), Validation (10%), and Test (10%) splits. Guarantees identical samples land in the same bucket and prevents arbitrary seed drift.
  - `assert_zero_leakage`: Mathematically asserts that the set intersections `train ∩ test`, `train ∩ val`, and `val ∩ test` are strictly empty (`set()`), guaranteeing 0% data leakage between training and testing data.
- Enhanced `backend/app/schemas/feedback.py` & `backend/app/routers/feedback.py`:
  - Added `GET /api/v1/feedback`: Allows filtering feedback strictly by `target_type` (`URL` or `TEXT`), guaranteeing URL training data and Text training data can be queried independently with zero cross-contamination.
  - Added `GET /api/v1/feedback/export-split`: Exports training, validation, and testing partitions with `zero_leakage_verified` assertion for ML pipelines.
  - Normalized feedback ingestion: treats `"EMAIL"` target types consistently under `"TEXT"` storage while isolating `"URL"` entries.
- Added comprehensive integration tests in `backend/tests/test_api.py`:
  - `test_url_and_text_storage_separation_and_filtering`: Ingests both URL and Text feedback and verifies that URL queries return 0 text entries, and Text queries return 0 URL entries.
  - `test_training_and_testing_data_zero_leakage`: Generates 25 distinct feedback samples, partitions them, and asserts that train, val, and test partitions have zero intersecting hashes.
- Validation: All 10 backend integration tests passed (`pytest backend/tests -v`); all 57 extension tests passed (`npm test`); synthetic email demo fixtures passed (`node tools/check-email-demo.js`).

### 2026-10-30 — Scope link scanner strictly to email message body and exclude webmail platform chrome

- Diagnosed root cause of webmail UI clutter: `urlLinkScanner.js` (declared for `<all_urls>`) was running `document.querySelectorAll('a[href^="http"]')` across the entire webmail DOM on `mail.google.com`, `outlook.com`, and `yahoo.com`.
- This caused Gmail's navigation sidebar folders ("Inbox", "Starred", "Snoozed", "Sent", "Drafts", "Purchases"), top menu bars, and user profile icons to be audited and badged with green outlines and `✓ CHECKED` or false `⚠ UNSAFE LINK` badges, while also injecting inline `✓ CHECKED` buttons into the email's buttons.
- Fixed `urlLinkScanner.js`: Added an immediate webmail domain guard (`WEBMAIL_DOMAINS.some(domain => host === domain || host.endsWith("." + domain))`). On webmail domains, `urlLinkScanner.js` exits immediately, completely preventing any DOM pollution or scanning of the webmail platform's navigation chrome.
- Fixed `contentScript.js`:
  - Scoped `highlightSuspiciousLinks` strictly to the active email container (`getActiveGmailMessage()` or `.a3s.aiL`), preventing any threat highlighting on navigation links outside the message.
  - Scoped `extract_page_links` strictly to the active email container when on webmail.
- Preserved webmail email threat scanning: `contentScript.js` continues to audit the opened email message and its embedded URLs, displaying the dedicated security banner at the top of the email and intercepting phishing link clicks, without distorting the email platform UI.
- Validation: All 57 extension tests passed (`npm test`); all non-vendor JavaScript files passed `node --check`.

### 2026-10-30 — HTTPS-only and TCP protocol lockdown across backend and extension

- Implemented `SecurityTransportMiddleware` in `backend/app/main.py`:
  - Enforces HTTPS over TCP: inspects request scheme and reverse-proxy header `X-Forwarded-Proto`. Rejects insecure remote HTTP POST/PUT/DELETE requests with `403 Forbidden` (`HTTPS required`) and redirects GET/HEAD requests with `308 Permanent Redirect`.
  - Injects strict HSTS response header: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (2-year HSTS pinning preventing SSL-strip and downgrade attacks).
  - Injects defense-in-depth security headers on all responses: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none';`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-XSS-Protection: 0`, and `Permissions-Policy`.
  - Added Host header validation against `ALLOWED_HOSTS` to defend against DNS rebinding and host spoofing.
- Enforced HTTPS on client extension side (`serviceWorker.js`, `sidepanelController.js`):
  - Remote cloud backend connections strictly require `https://`. Insecure cleartext HTTP connections are rejected immediately with a security violation error.
  - Non-localhost HTTP URLs are dropped before dispatching network requests in `analyzeAndRespond` and `submitTargetFeedback`.
- Enforced TCP and port restrictions across container, database, and infrastructure:
  - `backend/Dockerfile` declares `EXPOSE 8080/tcp` (TCP only, disallowing UDP).
  - `docker-compose.yml` binds PostgreSQL strictly to `127.0.0.1:5432:5432/tcp` and API to `127.0.0.1:8080:8080/tcp` (loopback interface only, preventing LAN or public interface exposure).
  - Cloud Run deployment workflow specifies `FORCE_HTTPS=true`; Cloud Run terminates TLS on TCP port 443 only and drops all UDP and non-TCP traffic at Google Front End.
  - Remote PostgreSQL database connections enforce `ssl=require`.
- Validation:
  - Backend pytest suite: 8 passed, 0 failed (including new tests `test_security_headers_present` and `test_https_enforcement_and_insecure_http_blocking`).
  - Extension test suite: 57 passed, 0 failed (including new test `service worker enforces HTTPS protocol for remote cloud backend connections`).

### 2026-10-30 — Build FastAPI backend, Cloud Run deployment, Alembic migrations, and optional extension cloud sync

- Built an asynchronous Python backend in `backend/` using FastAPI, SQLAlchemy 2.0 (asyncio), and Pydantic v2 schemas (`ScanURLRequest`, `ScanURLResponse`, `ScanEmailRequest`, `ScanEmailResponse`, `FeedbackCreate`, `FeedbackResponse`, `HealthResponse`).
- Implemented dual-engine database configuration (`backend/app/config.py` and `database.py`) supporting PostgreSQL via `asyncpg` for Cloud Run / Cloud SQL and `sqlite+aiosqlite:///./safeinbox.db` for zero-setup local development and automated CI testing.
- Ported server-side URL threat parsing and email analysis engines (`url_analyzer.py` and `email_analyzer.py`) maintaining full parity with the client-side contract, including brand confusable detection, high-entropy DGA estimation, SQLi ReDoS protection, and sensitive token masking.
- Implemented zero-PII privacy-preserving audit logging (`ScanAuditLog`) and threat intelligence caching (`ThreatURL`) with SHA-256 content indexing, preventing raw email bodies or sender/recipient identifiers from being persisted.
- Configured database schema versioning with Alembic (`backend/alembic/`), generating the baseline migration `08982a7c0969_initial_threat_schema.py`.
- Created production-ready multi-stage `Dockerfile` with unprivileged user `appuser` targeting Google Cloud Run port conventions (`PORT=8080`), and `docker-compose.yml` pairing the API with a PostgreSQL 16 container.
- Created automated GitHub Actions workflows: `.github/workflows/ci.yml` (running both extension Node tests and backend pytest) and `.github/workflows/deploy-cloud-run.yml` (automated build, push to Google Artifact Registry, and deployment to Google Cloud Run).
- Integrated optional Cloud Threat Intel connection into the browser extension (`extension/sidepanel.html`, `sidepanel.css`, `sidepanelController.js`, `serviceWorker.js`): users can optionally connect the extension to a local or Cloud Run backend for global IOC sync and centralized feedback ingestion, with complete non-blocking fallback to local heuristics when unconfigured or offline.
- Validation: All 56 extension tests passed (`npm test`); all 6 backend integration tests passed (`pytest backend/tests -v`); Alembic migration upgrade succeeded (`alembic upgrade head`); synthetic email demo fixtures passed (`node tools/check-email-demo.js`); non-vendor JavaScript files passed `node --check`.

### 2026-10-29 — Clear backend, ML, and database for redesign

- Removed the Python package/API, model code and weights, training scripts, datasets, SQLite database/storage, experiments, and Python tests/configuration.
- Kept the browser extension, its manifest, interface, content scripts, styles, and icons; removed its API calls and local-server permissions.
- Updated extension behavior and documentation for browser-side heuristics and browser-local feedback. Embedded links now receive heuristic scores instead of fixed ML placeholder scores.
- Validation: Node syntax checks, manifest/resource validation, browser-side scan/feedback smoke tests, `git diff --check`, and checks for remaining project DB/backend/data paths passed. No Python test suite remains.

### 2026-10-29 — Build the client-side URL threat engine

- Added URL analysis for mixed-script/brand-lookalike domains, DGA-like characteristics, redirect parameters, internal IPs, encoded injection markers, and embedded credentials. The parser emits a 32-value feature vector and a 128-token character tensor.
- Added SHA-256 URL-result caching and inference message routing in the service worker, plus an optional locally packaged ONNX Runtime Web/WASM worker. The extension stays heuristic-only until a compatible trained `url-threat.onnx` model is supplied.
- Added page-link threat badges, evidence popovers, and a confirmation step before navigating to risky links. Connected popup and preview scenarios to the same parser and added safe synthetic test scenarios.
- Documented the architecture and model contract in `docs/url-threat-engine.md` and `extension/models/README.md`.
- Validation: `npm test` passed all 13 tests; extension JavaScript syntax checks and `git diff --check` passed. Browser preview verified the redirect example (risk 24, `OPEN_REDIRECT`), encoded traversal/script payload (risk 91, severe threat), and benign Wikipedia example (risk 0). No URL was fetched during analysis.

### 2026-10-29 — Replace preview flow with native Side Panel

- Replaced the extension popup entry point with a native Chrome Side Panel, opened by the toolbar action, and removed the separate preview/demo page.
- Added temporary session-only handoff of the currently opened webmail email to the panel. Gmail, Outlook, and Yahoo email links, raw URLs, `www` links, and bare domains are normalized/deduplicated and scanned sequentially through the shared URL analysis route; sender/subject/body text is analyzed separately and merged using the highest risk score to avoid diluting a dangerous URL.
- Updated the webmail URL banner to use the same analysis route instead of its older, limited URL-only heuristic. Failures are shown as unverified, not marked safe.
- Validation: `npm test` passed all 16 tests; modified JavaScript syntax checks, manifest resource checks (11 declared resources), and `git diff --check` passed. Browser file-page Side Panel smoke tests scanned the Netflix sample as critical with one unique URL, then scanned a two-destination PayPal sample sequentially (60/100 for the lookalike URL, 0/100 for the benign candidate). Native Chrome Side Panel launch and live Gmail/Outlook/Yahoo capture were not exercised in this workspace; reload the unpacked extension and test with a real supported mailbox.

## Rebuild notes

- Rebuild the ML model and database as new components; do not restore the removed implementation without checking the user's current requirements.
- Keep the extension usable without a server or model while replacements are being designed.
- Update this file's current state and append a concise dated entry after each project task. When multiple entries share a date, retain their separate summaries.

### 2026-10-29 — Restructure extension architecture

- Moved URL parsing, email extraction, content scripts, Side Panel controller/styles, and URL inference worker into responsibility-oriented folders, then updated manifest, HTML, service-worker, worker, and test references.
- Separated the shared email text-analysis heuristics into `extension/src/email/emailTextAnalyzer.js`; Side Panel and webmail banners now call this module instead of maintaining separate brand/urgency/credential rules.
- Restricted webmail-only content scripts and CSS to supported webmail hosts. URL-link scanning remains enabled on all pages.
- Added analyzer tests and architecture documentation. The analyzer is a stable heuristic boundary only; an email text ML model remains future work, and the URL model still requires compatible trained weights.

### 2026-10-29 — Build the email text threat pipeline

- Added the shared email text parser and normalizer with HTML/entity cleanup, sensitive-token masking, metadata and threat-vector rules, WordPiece `input_ids`/`attention_mask`, and context chunking.
- Added the off-thread ONNX Runtime Web/WASM text worker contract, an offscreen worker host, and service-worker routing. Webmail and Side Panel requests use the same inference path regardless of whether the Side Panel is open; deterministic heuristics remain available if a model or offscreen API is unavailable.
- Added SHA-256 email-result caching with a 24-hour TTL and bounded entries. Cached entries omit body, subject, sender/recipient address and normalized text. Webmail threat banners now highlight suspicious body sentences and show whether a trained model or heuristics were used. Session handoff data is cleared after the Side Panel scan.
- Added synthetic email fixtures and `npm run check:email-demo` / `npm run setup:email-demo`; updated architecture, privacy, and model contract docs. No mock weights were generated: random weights would create misleading confidence and do not test model quality.
- Validation: `npm test` passed all 27 tests; `npm run setup:email-demo` matched both synthetic fixtures and checked manifest resources; syntax checks passed for all 18 non-vendor extension JavaScript files; `git diff --check` passed. A local file-page attempt to click the Side Panel's email demo was blocked by the browser harness. Real Chrome offscreen inference and live Gmail/Outlook/Yahoo capture remain untested.

### 2026-10-29 — Refresh and reorganize the email Side Panel

- Made email scans fingerprint-based so a reused Gmail/Outlook reading pane is rescanned when message content changes; the panel also refreshes on active-tab switches and shows a reload hint if the webmail content script is not connected.
- Reorganized the panel into Summary, URL Scanner, and Context Scanning. Summary now reports text risk, average URL risk, and their arithmetic mean; URL Scanner shows each current-email URL and independent local feedback; Context Scanning shows email-text risk and feedback. Removed the visible Evidence card.
- Safe/Threat feedback is saved locally as a bounded labeled sample set (up to 100 per type) for possible future model training. No model is retrained, and the extension still has no trained ONNX weights or matching email vocabulary.
- Chrome cannot automatically open the native Side Panel without a user gesture. Users must click the extension icon; after extension reload, refresh the webmail tab to reinject updated content scripts.
- Validation: `npm test` passed all 30 tests; `npm run setup:email-demo` matched both synthetic fixtures and checked extension resources; syntax checks passed for all 18 non-vendor extension JavaScript files; `git diff --check` passed. The file-page Side Panel smoke test confirmed the three tabs, local sample scoring, per-URL list, summary averages, and hidden Evidence card. Live Chrome Side Panel launch and Gmail/Outlook message-change behavior remain untested.

### 2026-10-29 — Audit Side Panel connections and clicks

- Corrected the **Grab from Page** failure path so it no longer silently loads a fake Netflix email when Chrome extension APIs or a supported message are unavailable; it now shows a clear status message. **Current Tab** also reports unavailable/non-HTTP(S) tab cases.
- Added visible error handling for report copy/export failures and browser-local feedback storage failures.
- Verified in a local browser-page harness that all three views switch, URL/email samples scan, Summary report copy/export actions work, and unavailable Grab from Page reports the limitation without changing the email input. Email fixtures returned 46/100 (Netflix), 80/100 (PayPal), and 0/100 (benign); feedback correctly displayed that browser storage was unavailable in this non-extension harness. No page JavaScript errors occurred.
- Validation: `npm test` passed all 30 tests; `npm run setup:email-demo` matched both fixtures; all non-vendor extension JS passed `node --check`; `git diff --check` passed. The browser harness uses `file://`, so Chrome extension APIs, actual tab messaging/storage, native Side Panel launch, and live webmail extraction remain unverified.

### 2026-10-29 — Correct email pipeline routing and result confidence

- Changed Gmail scanning and explicit extraction to select only the last expanded message in the open thread, rather than scanning every expanded message and allowing their results to overwrite each other in Side Panel session handoff. Sender/recipient lookup is now scoped to that selected message.
- Changed zero-signal heuristic output from “verified safe” language to “no configured signals / not verified safe” in Side Panel and webmail banners. The panel explicitly notes that a trained model is not installed when applicable.
- Added service-worker handoff validation: email scan data is accepted only from supported HTTPS webmail origins, string fields and URL arrays are type/size bounded, and only expected fields are saved to session storage.
- Added regression tests for Gmail thread selection and rejection of cross-origin, insecure-origin, and oversized handoffs. Validation: `npm test` passed all 32 tests; `npm run setup:email-demo`, non-vendor JavaScript syntax checks, and `git diff --check` passed. The local browser page did not expose Chrome extension APIs, so real Chrome tab routing and live Gmail DOM extraction still require an unpacked-extension test.

### 2026-10-29 — System hardening, zero-leak lifecycle, and data transfer audit

- Hardened SQL injection regular expression in `urlThreatParser.js` (`select\s+[^;]{1,256}?\s+from`) to eliminate catastrophic backtracking (ReDoS) against arbitrarily long query payloads.
- Fixed `escapeHtml` in both `contentScript.js` and `sidepanelController.js` to coerce input with `String(str ?? "")`, preventing `TypeError` crashes on numerical and falsy values.
- Eliminated ephemeral email session data leaks by binding `chrome.tabs.onRemoved` and `chrome.tabs.onUpdated` in `serviceWorker.js`, purging session handoff data if a webmail tab is closed or navigated away before Side Panel extraction.
- Bound context menu payload sizes in `serviceWorker.js`: selection text is capped at 100,000 characters and URL inputs are validated strictly for HTTP(S) protocol and capped at 4,096 characters, preventing storage overflow and script scheme injection.
- Replaced unconstrained and asynchronous webmail banner feedback in `contentScript.js` with bounded storage (`saveBrowserFeedback`), restricting storage to a FIFO cap of 100 entries and truncating body text to 20,000 characters and URLs to 4,096 characters, synchronizing schemas with Side Panel feedback.
- Added host timeout cleanup in `textWorkerHost.js` (35s) to prevent memory and promise leaks when offscreen web workers fail or hang.
- Added protective 1 MB input body truncation guard in `textParser.js` for defense-in-depth against excessive memory consumption.
- Added Escape-key dismiss listener and event cleanup to link block confirmation dialogs in `urlLinkScanner.js`.
- Audited multi-user, concurrency, memory, and data transfer boundaries.
- Validation: `npm test` passed all 56 tests (up from 50); `node tools/check-email-demo.js` matched both synthetic fixtures; all non-vendor JavaScript files passed `node --check`; `git diff --check` passed.
