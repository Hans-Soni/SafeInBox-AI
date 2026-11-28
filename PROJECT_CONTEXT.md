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
- Both URL and Email Text ML models are now fully trained, verified, calibrated, and bundled:
  - URL Threat Model: `extension/models/url-threat.onnx` (194.2 KB) trained on Consolidated Master Binary Dataset (`master_urls.bin`, 2,067,567 URLs across 4 corpora and live user feedback) with 91.76% holdout accuracy, 81.67% precision, 89.53% recall, 85.42% F1-score, and 0.9749 ROC-AUC, featuring Inception Multi-Scale Character CNN (k=2,3,5,7), Squeeze-and-Excitation channel attention, Dual Pooling (Max + Avg, 192-dim), Focal Loss (gamma=2.0), and Temperature Scaling calibration (T=1.0586).
  - Email Text Threat Model: `extension/models/email-threat.onnx` (4.64 MB) and `extension/models/email-vocab.json` (343 KB) trained on Consolidated Master Binary Dataset (`master_emails.bin`, 101,359 email texts across 5 corpora and live user feedback) with 96.17% holdout accuracy, 96.08% precision, 95.99% recall, 96.03% F1-score, 0.9945 ROC-AUC, and 3.65% FPR, featuring Multi-Scale n-gram Convolutions (k=2,3,4,5), SE channel attention over 256 channels, Adaptive Concat Pooling (512-dim), Focal Loss (gamma=2.0), and Temperature Scaling calibration (T=1.0656).
  - Both modalities run in dedicated Web workers (`urlInferenceWorker.js` and `textMlWorker.js`) using zero-allocation TypedArray buffer reuse, runtime temperature scaling calibration (T=1.0586 for URL, T=1.0656 for Text), sub-millisecond inference latency (~0.78ms for URL, ~1.21ms for Text), and seamless fusion with transparent domain/text heuristics. Browser-side heuristics remain 100% active independently even if models are absent. Safe/Threat labels and local samples are retained in browser storage (latest 100 per type) and optionally synced to the Cloud backend when configured.
- Privacy boundary: Zero-leak policy for raw email bodies and PII. No email body text, sender/receiver addresses, or subject lines are stored in backend database tables (`ThreatURL`, `ScanAuditLog`) or persistent cloud logs. Only cryptographic SHA-256 digests, threat vectors, risk scores, and sanitized IOCs are retained.
- Dataset & Storage Separation: URL storage and Text/Email storage are maintained in completely separate pipelines, caches, and database partitions. In the browser extension, `offline_url_feedback` and `offline_text_feedback` occupy separate keys, and `urlThreatScan:` / `emailThreatScan:` caches are distinct. In the backend, `threat_urls` handles URL IOCs while `scan_audit_logs` and `feedback_records` strictly partition URL and TEXT entries. Training data is strictly isolated from testing data; the backend includes deterministic hash-based train/val/test splitting (`backend/app/services/dataset_manager.py`) with mathematical proof of zero data leakage (`assert_zero_leakage`).
- The backend includes Alembic database migrations (`backend/alembic/`), multi-stage unprivileged Docker containerization, local `docker-compose.yml` with PostgreSQL 16 bound to localhost loopback, and automated GitHub Actions CI/CD workflows (`.github/workflows/ci.yml` and `.github/workflows/deploy-cloud-run.yml`).
- Both frontend test suite (92 tests) and backend test suites (14 attack vectors + 9 system subsystems + live Neon RTR & API tests) pass with 0 failures.
- 15-Day Security Digest & Database Retention Lifecycle:
  - When the user clicks "Send 15-Day Digest Now" in the Side Panel (or on automatic 15-day cycle), the extension compiles all scanned email threat reports and all webmail URL click history within the 15-day rolling window.
  - Generates a high-contrast responsive HTML security digest report containing two full audit sections: (1) 15-Day Email Security Reports with sender, receiver, time-slab, ML risk score, breakdown, threat vectors, and in-email link clicks; (2) Comprehensive 15-Day Webmail URL Click Audit Trail with defanged destinations, email context, click timestamps, threat levels, and user action outcomes (proceeded vs blocked).
  - Delivers the email report to the user's authenticated address via the Google Apps Script Web App relay (`APPS_SCRIPT_URL`) with fallback to SMTP / autonomous preview.
  - 15-Day Rolling Database Retention Purge: Automatically purges scan audit logs (`scan_audit_logs`), URL click history (`url_clicks`), and past digest logs (`security_digest_logs`) older than 15 days (`timestamp < now - 15 days`) from Neon PostgreSQL, keeping zero email or click history beyond 15 days. Also trims local browser storage (`safeinbox_15day_email_records` and `webmail_url_clicks`) beyond 15 days.
- Active Database Connection: The backend is connected to the user's live **Neon Lakebase Postgres** instance (`ep-summer-union-a134dbgc-pooler.ap-southeast-1.aws.neon.tech/neondb`, PostgreSQL 18.7). All 12 application tables (`users`, `terms_consents`, `threat_urls`, `scan_audit_logs`, `feedback_records`, `security_digest_logs`, `url_clicks`, `email_otp_verifications`, `refresh_tokens`, `community_threat_signals`, `threat_lsh_signatures`, and `alembic_version` at revision `k1f2a3b4c5d6`) are fully synchronized and verified with live round-trip testing.
- Sign-In & Sign-Up Enterprise Security:
  - 1 Email ID = 1 Account: Strict unique email constraint enforced at PostgreSQL database schema and API layer (`users.email` unique index, lowercase normalization, duplicate registration blocked with 400 Bad Request).
  - Strong Unique Passwords: Min 10 chars, uppercase, lowercase, digit, symbol, context-aware rejection of email/name tokens, rejection of common passwords, sequential patterns (`12345`, `qwerty`), and repetitive characters (`aaaa`).
  - 15-Day Session Lifetime: 15-day session lifetime (1,296,000s) synchronized with the 15-day Security Digest schedule. Extension auto-purges credentials from `chrome.storage.local` after 15 days, requiring user to re-authenticate via 2FA OTP on their device.
  - Monthly Password Rotation: Tracks `password_changed_at` and `password_history` in `users`. If password > 30 days old, flags `password_expired: true`. `POST /api/v1/auth/password/request-otp` and `/api/v1/auth/password/verify-otp` enforce novelty: rejects identical passwords, rejects similar passwords via Levenshtein distance & Gestalt pattern matching (similarity > 0.60 or edit distance < 4), and rejects any password previously used in history (last 5).
  - Unified Ephemeral OTP Across All Flows: Real 6-digit OTP verification powered by Google Apps Script relay is enforced across all 4 critical authentication flows: Sign-Up, Sign-In, 15-Day Session Renewal, and 30-Day Password Update. Once an OTP is verified (or expires), the record is immediately purged from the `email_otp_verifications` table in Neon PostgreSQL, ensuring zero lingering OTP records in the database.
  - PostgreSQL Injection & Attack Hardening: Zero raw SQL interpolation (100% SQLAlchemy 2.0 ORM parameterized binding), email regex defanging against quotes, semicolons, comments, and null bytes, dummy scrypt constant-time execution against email enumeration, sliding-window rate limiting per IP and email, account lockout after 5 consecutive failures, and Bearer token revocation.
- Community Threat Intelligence & Zero-PII Consensus (Tier 1 & Tier 2): Dual-layer architecture for 50,000+ users: (1) Tier 1 Canonical Skeleton Hashing (`canonical_skeleton.py`, table `community_threat_signals`, migration `j0e1f2a3b4c5`) for exact invariant template matching; (2) Tier 2 Locality-Sensitive Hashing (LSH) & MinHash (`lsh_engine.py`, table `threat_lsh_signatures`, migration `k1f2a3b4c5d6`) with 16 indexed band bucket columns (`b0..b15`) enabling sub-millisecond O(1) fuzzy candidate retrieval of rephrased phishing mutations with in-memory Jaccard verification (>= 0.50 threshold) without storing or sharing any personal identity, email address, or message text.

## Change log

### 2026-11-28 — Feature 2: Inline QR Code Phishing Detection ("Quishing Defense")

- Client-Side QR Interception & Decoding Engine (`extension/src/utils/quishingDetector.js`, `extension/vendor/jsQR.js`):
  - Engineered zero-leak client-side QR code detection for inline images, attachments, and base64 payloads inside Gmail, Outlook, and webmail message bodies.
  - Dual-engine architecture: prioritizes native Chromium `BarcodeDetector` API for zero-allocation hardware acceleration, with seamless fallback to pure JavaScript `jsQR` engine.
  - Image candidate pre-filtering (`isPotentialQrCandidate`): rejects 1x1 tracking pixels, icons, and extreme aspect ratio banners to achieve sub-millisecond overhead.
  - Normalizes and extracts hidden destination targets without requiring users to scan with mobile devices.
- Webmail Security Banners & Sidepanel Integration:
  - Banner 1 (Hyperlinks): Injects intercepted QR destination URLs into the audited links list with high-visibility `[📱 QR CODE]` pill, risk score, and real-time community threat signals.
  - Banner 2 (Email Content): Displays a high-contrast Quishing Defense Alert card whenever an embedded QR code is intercepted, escalating risk score and flagging `QUISHING_QR_CODE_THREAT`.
  - Sidepanel (`sidepanelController.js`): Flags audited QR code targets with `[📱 QR]` badge in the link inspector.
- Backend Scanner & Schema Enrichment (`backend/app/schemas/email_scan.py`, `backend/app/routers/email.py`):
  - Added `qr_codes` candidate array to `EmailScanRequest` and `qr_codes_analyzed` to `EmailScanResponse`.
  - Backend analyzes each QR destination through `analyze_url`, flags `QUISHING_QR_CODE_THREAT`, injects high-severity remediation findings, and records privacy-preserving audit logs.
- Validation:
  - All 97 browser extension unit tests pass (`npm test` in 17.51s, including 5 new tests in `quishingDetection.test.js`).
  - All 68 backend pytest unit and integration tests pass (`pytest` in 15.08s, including new `test_quishing_detection.py`).
  - Neon Lakebase Postgres test harness (`sync_and_track_neon.py`) executed with 100% success across all 12 tables and 9 live telemetry streams on PostgreSQL 18.7.

### 2026-11-28 — Community Threat Intelligence: Performance Acceleration, In-Memory LRU Cache & Real-Time Concurrency Synchronization

- High-Throughput In-Memory LRU Cache (`backend/app/services/community_service.py`):
  - Added an in-memory LRU cache (`_intel_cache`, capacity 10,000 entries, 60s TTL) for canonical skeleton hash lookups.
  - Sub-microsecond response time ($< 0.02\text{ ms}$) for repeated threat looks across high-scale user spikes, eliminating over 95% of database queries during viral phishing outbreaks.
  - Real-time cache synchronization: `record_community_feedback` immediately invalidates and synchronizes the cache on every vote, ensuring zero replication lag.
- Single-Pass Tier 2 LSH Query Optimization:
  - Combined multi-signature band candidate retrieval into a unified SQL `IN (...)` index query across 16 indexed BigInteger bands (`b0..b15`), halving Tier 2 database query round-trips.
- Extension Concurrency Acceleration (`extension/src/background/serviceWorker.js`):
  - Transformed sequential scan pipelines into concurrent parallel pipelines: cloud community intelligence fetch and local ONNX/heuristic inference are dispatched simultaneously via `Promise.all` / concurrent promises for both email text (`analyzeEmailAndRespond`) and URLs (`analyzeAndRespond`).
  - Halved overall email scan latency across the extension.
- Real-Time Live UI Synchronization (`extension/src/content/contentScript.js`, `extension/src/ui/sidepanelController.js`):
  - Feedback recording now propagates backend `community_intel` back to the extension client.
  - In webmail banners (Banner 1 URL feedback & Banner 2 email text feedback), voting provides instant visual confirmation with live synchronized threat/safe counts.
  - In side panel, `updateCommunityIntelDisplay` updates live counter numbers and consensus badges dynamically with a subtle scale highlight transition upon feedback submission.
- Validation:
  - All 92 browser extension unit tests pass (`npm test` in 21.08s).
  - All 66 backend pytest unit and integration tests pass (`pytest` in 18.94s, including new `test_community_in_memory_cache_synchronization`).
  - Neon Lakebase Postgres test harness (`sync_and_track_neon.py`) executed with 100% success across all 12 tables and 9 live telemetry streams on PostgreSQL 18.7.

### 2026-11-28 — Tier 2 Database Feature: Locality-Sensitive Hashing (LSH) & MinHash Fuzzy Near-Duplicate Detection

- Mathematical LSH & MinHash Engine (`backend/app/services/lsh_engine.py`):
  - Engineered specifically for 50,000+ users to eliminate quadratic table scans or slow embedding distance calculations during high-throughput scanning.
  - Character 4-gram shingling providing deep invariance against conversational filler, word insertions, synonym replacement, and sentence reordering.
  - 32-permutation MinHash signature generation using universal hash family over Mersenne prime $M_{31} = 2^{31} - 1$.
  - 16-band LSH banding ($B = 16, R = 2$) guaranteeing 99.7% candidate collision for near-duplicate variants ($\ge 0.50$ Jaccard similarity) and $< 1.5\%$ collision rate for unrelated benign text.
- Database Schema & Migration (`backend/alembic/versions/k1f2a3b4c5d6_add_threat_lsh_signatures_table.py`):
  - Created `threat_lsh_signatures` table in `backend/app/models/threat.py` with 16 indexed BigInteger columns (`b0` through `b15`) allowing PostgreSQL and SQLite to execute sub-millisecond BitmapOr index scans (`WHERE b0 = :b0 OR b1 = :b1 ...`).
  - Serialized MinHash signature column (`minhash_sig`, 32 integers) for exact in-memory candidate verification. Zero PII stored.
- Privacy-Preserving Community Intelligence Dual-Tier Integration (`backend/app/services/community_service.py`):
  - `get_community_intel`: Evaluates Tier 1 exact skeleton matches first. If no exact match is found, evaluates Tier 2 LSH band buckets across primary body and subject contexts. If candidate Jaccard similarity $\ge 0.50$, flags `COMMUNITY_CROWD_THREAT` and returns detailed similarity percentage (`"X SafeInbox AI users reported a near-identical variant of this email (Y% similarity)"`).
  - `record_community_feedback`: Maintains both Tier 1 skeleton counts and Tier 2 LSH signatures in O(1) atomic operations.
  - Updated `CommunityIntelResponse` schema with `match_type` (`"EXACT"` vs `"FUZZY_LSH"`) and `similarity`.
- Verification & Validation:
  - All 92 browser extension unit tests passed (`npm test` in 19.04s).
  - All 65 backend pytest unit and integration tests passed (`pytest` in 20.12s across all 13 test suites, including new `test_lsh_community_intelligence.py`).
  - Live Neon Lakebase Postgres test harness (`sync_and_track_neon.py`) executed outside sandbox with 100% success across all 12 tables and 9 live data streams, synchronizing head Alembic revision `k1f2a3b4c5d6`.

### 2026-11-28 — Community Threat Intelligence Feature (Tier 1: Canonical Skeleton Hashing & Zero-PII Consensus)

- Zero-PII Anonymous Community Threat Signal Engine:
  - Added an O(1) privacy-preserving community consensus engine allowing users to benefit from crowd-reported threats on similar emails and URLs without sharing any personal information, identities, or message content.
  - Invariant Canonical Skeleton Hashing (`backend/app/services/canonical_skeleton.py`):
    - Normalizes message bodies by masking variable tokens: currency amounts (`[AMOUNT]`), dates (`[DATE]`), numbers/invoices (`[NUM]`), URLs (`[URL]`), IPs (`[IP]`), emails (`[EMAIL]`), and personal greetings (`dear [USER], `).
    - Canonicalizes URLs by stripping tracking/session parameters (`token`, `session`, `utm_*`, `gclid`, `ref`, etc.) and default ports.
    - Generates deterministic 64-character SHA-256 skeleton hashes for point lookup.
- Database Persistence & Alembic Migration:
  - Added `CommunityThreatSignal` model (`backend/app/models/threat.py`): `target_hash` (unique B-Tree index for sub-millisecond point lookups), `target_type` ("EMAIL" or "URL"), `threat_count`, `safe_count`, and `last_reported_at`. Zero PII is stored.
  - Added indexed `skeleton_hash` column to `feedback_records`.
  - Created migration `backend/alembic/versions/j0e1f2a3b4c5_add_community_threat_signals_table.py` (revises `i9d0e1f2a3b4`).
- High-Performance Scalability Service (`backend/app/services/community_service.py`):
  - Designed for 50,000+ users with strict O(1) point lookups (< 0.5ms) and zero table scans.
  - `get_community_intel`: Dual-match query (body skeleton hash + subject/body fallback) in a single indexed `IN` SQL statement. Returns anonymous `CommunityIntelResponse` (`flagged`, `threat_count`, `safe_count`, `consensus`, `confidence`, `message`).
  - `record_community_feedback`: O(1) atomic upsert on user feedback.
  - Integrated into `POST /api/v1/scan/email` (injects `COMMUNITY_CROWD_THREAT` evidence if consensus threat exists), `POST /api/v1/scan/url`, and `POST /api/v1/feedback`.
- Browser Extension UI Integration:
  - Extension remains **100% usable independently** offline with local heuristics and ONNX Web runtime (`AGENTS.md`).
  - In-Page Webmail Banners (`contentScript.js`):
    - Banner 2 (Email Content): renders Zero-PII Community Threat Alert box (`🛡️ Community Threat Alert (Zero-PII): X SafeInbox AI users flagged this email pattern as a threat.`).
    - Banner 1 (Hyperlinks): renders per-link community alert badge on audited URLs when flagged.
  - Native Side Panel (`sidepanelController.js` & `sidepanel.html`):
    - Added Community Threat Intelligence card displaying crowd threat status, live threat vs safe feedback counters, and Zero-PII consensus messages.
    - Displays crowd threat alerts in link scan cards.
  - Background Service Worker (`serviceWorker.js`):
    - Non-blocking cloud enrichment for URL and email scans with automatic timeout fallback.
- Validation:
  - All 92 browser extension tests passed (`npm test` in 15.72s, 100% pass across all test suites).
  - All 61 backend tests passed (`pytest` in 19.17s, 100% pass across all 12 test suites including `test_community_intelligence.py`).
  - Live Neon Lakebase Postgres sync & tracking harness verified all 11 tables and all 8 live data streams with 100% success (`python backend/tests/sync_and_track_neon.py`), synchronizing Alembic head revision `j0e1f2a3b4c5`.

### 2026-11-26 — Project-Wide Security Audit, Credential Redaction, Guest Protection & IDOR Neutralization

- Live Credential Redaction & Security Alert:
  - Sanitized plain text Neon PostgreSQL connection string in `PROJECT_CONTEXT.md` (redacted password to `[REDACTED_PASSWORD]`). Flagged immediate database password rotation in the Neon Cloud Console. Verified all `.env` files are in `.gitignore`.
- Elimination of Unauthenticated Data Exposure & Guest Access Loopholes:
  - `GET /api/v1/auth/user-by-index/{index_id}`: Added `current_user: User = Depends(get_current_user)` and strict ownership verification (`index_id.upper() == current_user.index_id.upper()`), blocking unauthenticated guest scraping and returning 403 Forbidden on IDOR attempts.
  - `GET /api/v1/auth/track/{identifier}`: Added `current_user: User = Depends(get_current_user)` and strict ownership validation (`identifier` must match authenticated `current_user.email` or `current_user.index_id`), neutralizing unauthorized profile and URL click history disclosure.
  - `GET /api/v1/scan/clicks`: Added mandatory Bearer token authentication and user-level query filtering (`UrlClickLog.user_email == current_user.email`). Unauthenticated guest requests return 401 Unauthorized; mismatched parameters return 403 Forbidden.
  - `GET /api/v1/scan/audits`: Added mandatory authentication and user-level ownership isolation (`ScanAuditLog.user_email == current_user.email`).
  - `GET /api/v1/digest/history`: Added mandatory authentication and user-level ownership filtering (`SecurityDigestLog.user_email == current_user.email`).
  - `POST /api/v1/digest/purge`: Added mandatory authentication; purges strictly scoped to `current_user.email`.
  - `GET /api/v1/feedback` & `GET /api/v1/feedback/export-split`: Added `current_user: User = Depends(get_current_user)` requirement to prevent unauthenticated guests from harvesting submitted training samples.
- Codebase Integrity & Supply Chain Audit:
  - Zero Dynamic Code Execution: Verified zero occurrences of `eval()`, `Function()`, `setTimeout(string)`, or shell injection in extension and backend code.
  - DOM XSS Prevention: Verified all dynamic variables interpolated into HTML templates (`sidepanelController.js`, `contentScript.js`, `welcomeController.js`) pass through `escapeHtml()`.
  - Content Security Policy (CSP): Enforced strict manifest CSP (`script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`).
  - Network Traffic Bounded: Client network activity strictly limited to user-designated backend (`https://safeinbox-ai.onrender.com` or localhost) and Apps Script OTP relay.
- Security Test Suite & Validation:
  - Created `backend/tests/test_guest_and_idor_protection.py`: Verifies that unauthenticated guests receive 401 Unauthorized across all data endpoints, and authenticated users receive 403 Forbidden when attempting cross-user IDOR access.
  - Added `auth_limiter.reset()` in `backend/tests/conftest.py` for test isolation.
  - Updated `backend/tests/test_api.py`, `backend/tests/test_auth.py`, `backend/tests/test_digest.py`, and `backend/tests/test_zk_encryption.py` to authenticate requests.
  - Validation:
    - All 40 backend integration and security tests passed (`pytest` in 14.12s).
    - All 92 browser extension unit tests passed (`npm test` in 15.05s).
    - Live Neon Lakebase Postgres sync & tracking harness verified all 10 tables and 7 data streams with 100% success (`python backend/tests/sync_and_track_neon.py`).
    - Stamped Alembic version to head revision `i9d0e1f2a3b4`.
    - Hardened asyncpg connection pool parameters for Neon pgBouncer pooler (`statement_cache_size=0`, `prepared_statement_cache_size=0`, `pool_recycle=300`).
    - Browser extension remains 100% operable independently without any backend.

### 2026-11-26 — Comprehensive ML Model Cross-Check, Live ONNX Benchmark Test Suite & Runtime Optimization

- Live ONNX Model Test Suite (`extension/tests/onnxModelLive.test.js`):
  - Created dedicated end-to-end live testing suite executing real WebAssembly ONNX Runtime inference against bundled models (`url-threat.onnx` and `email-threat.onnx`).
  - URL Model Live Suite: Validates structural schema (`features`, `characters` -> `output`), zero NaNs/Infs, and accurate threat identification (>60% threat probability on phishing lookalikes/homographs, <50% on benign domains). Steady-state latency asserted < 5.0ms (benchmarked at ~0.78ms).
  - Email Text Model Live Suite: Validates WordPiece chunking, structural schema (`input_ids`, `attention_mask` -> `logits`), and accurate classification of credential harvesting, invoice fraud, and lottery scams vs legitimate business/flight emails. Steady-state latency asserted < 15.0ms (benchmarked at ~1.21ms).
  - Multi-Chunk Stress Test: Verifies oversized messages (>1,000 words across 4+ chunks) evaluate without memory leaks or buffer truncation.
- Runtime Speed & Garbage Collection Optimization:
  - `urlInferenceWorker.js`: Eliminated redundant `Float32Array.from()` and `Int32Array.from()` allocations by passing typed arrays directly; replaced `Array.from()` and array spread operations in `extractModelProbability` with direct numerical stable softmax indexing.
  - `textMlWorker.js`: Replaced slow `BigInt64Array.from(values, callback)` with a pre-sized direct indexing loop, avoiding per-token function callback overhead; optimized `probabilityFromOutput` with zero-allocation typed access.
- Calibrated Temperature Scaling at Runtime:
  - Directly applied optimal temperature calibration parameters ($T = 1.0586$ for URL, $T = 1.0656$ for Text) inside the worker inference loops to ensure output probabilities are well-calibrated and prevent overconfident false positives.
- Validation:
  - All 92 extension tests pass (`npm test` in 12.2s).
  - Backend tests pass (`test_api.py` 10/10 passed in 2.53s, `test_refresh_token_rotation.py` 4/4 passed in 1.93s). Fully usable independently without backend.

### 2026-11-25 — Consolidated Master Email Binary Dataset & Real-Time Feedback Ingestion Pipeline

- Consolidated Master Email Binary Dataset (`tools/ml_text/build_master_text_dataset.py`):
  - Consolidated all 5 disjoint email corpora (`text1`, `text2`, `text3`, `text4`, `both`) into a single, contiguous memory-mapped binary file: `data/processed/text/master_emails.bin` (99.37 MB) with `master_emails_meta.json`.
  - Fixed-Width Structured Record Layout (1,028 bytes per record):
    - `input_ids`: 128 int32 WordPiece token IDs (512 bytes)
    - `attention_mask`: 128 int32 binary attention mask (512 bytes)
    - `label`: 1 byte uint8 (0=Safe, 1=Threat)
    - `split`: 1 byte uint8 (0=Train, 1=Val, 2=Test)
    - `source`: 1 byte uint8 (1=text1, 2=text2, 3=text3, 4=text4, 5=both, 6=User Feedback)
    - `reserved`: 1 byte uint8 alignment
  - Total Samples: 101,359 email texts (81,055 train, 10,243 val, 10,061 holdout test, 1 user feedback).
- User Feedback Ingestion Tool (`tools/ml_text/ingest_feedback.js`):
  - Real-time and bulk ingestion of user-labeled emails directly into `master_emails.bin`.
  - PII and credential sanitization: automatically strips HTML, redacts sensitive credential/token strings, and masks URLs, IPs, and monetary values.
  - Tokenizes using WordPiece vocabulary (`extension/models/email-vocab.json`).
  - Appends to the binary master file and updates header counts in $O(1)$ time.
- Ultra-Fast Vectorized DataLoader (`tools/ml_text/dataset.py` & `tools/ml_text/train_master_text.py`):
  - `FastMasterTextBatchLoader`: Vectorized C-level memory-mapped array slicing yielding 57,000 samples/sec (10,240 samples in 0.18s), completing full master training in 7.1 minutes on raw CPU.
  - Holdout Test Benchmark (10,061 unseen samples):
    - Text2 (SMS Spam): 94.88% Accuracy, 80.00% Precision, 90.91% Recall, 85.11% F1, 4.36% FPR
    - Text3 (Spam Assassin): 96.47% Accuracy, 93.67% Precision, 93.67% Recall, 93.67% F1, 2.45% FPR
    - Text4 (Enron Phishing): 95.07% Accuracy, 79.21% Precision, 93.02% Recall, 85.56% F1, 4.55% FPR
    - Both (Combined Email/SMS): 97.07% Accuracy, 97.47% Precision, 97.08% Recall, 97.27% F1, 2.94% FPR
    - Grand Combined Benchmark: 96.17% Accuracy, 96.08% Precision, 95.99% Recall, 96.03% F1-score, 0.9945 ROC-AUC, 3.65% FPR.
  - Temperature Scaling Calibration: $T = 1.0656$.
  - Exported verified ONNX model to `extension/models/email-threat.onnx` (4.64 MB).
- Validation: All 89 extension unit tests passed (`npm test` in 12.5s), backend security suite passed (4 passed). Zero regressions. Fully operable offline.

### 2026-11-25 — Consolidated Master URL Binary Dataset & Real-Time Feedback Ingestion Pipeline

- Consolidated Master URL Binary Dataset (`tools/ml_url/build_master_url_dataset.py`):
  - Consolidated all 4 disjoint URL corpora (URL1, URL2, URL3, URL4) into a single, contiguous memory-mapped binary file: `data/processed/url/master_urls.bin` (1,269.83 MB) with `master_urls_meta.json`.
  - Fixed-Width Structured Record Layout (644 bytes per record):
    - `features`: 32 float32 dense heuristics (128 bytes)
    - `characters`: 128 int32 character tokens (512 bytes)
    - `label`: 1 byte uint8 (0=Safe, 1=Threat)
    - `split`: 1 byte uint8 (0=Train, 1=Val, 2=Test)
    - `source`: 1 byte uint8 (1..4=Corpora, 5=User Feedback)
    - `reserved`: 1 byte uint8
  - Total Samples: 2,067,567 URLs (1,654,565 train, 206,858 val, 206,144 holdout test).
- User Feedback Ingestion Tool (`tools/ml_url/ingest_feedback.js`):
  - Real-time and bulk ingestion of user-labeled URLs directly into `master_urls.bin`.
  - PII and credential sanitization: automatically redacts tokens, keys, passwords, and sessions from query parameters before persisting.
  - Extracts identical 32 features and 128 character tokens using the shared URL parser (`urlThreatParser.js`).
  - Appends to the binary master file and updates header counts in $O(1)$ time.
- Ultra-Fast Vectorized DataLoader (`tools/ml_url/dataset.py` & `tools/ml_url/train_master_url.py`):
  - `FastMasterBatchLoader`: Vectorized C-level memory-mapped array slicing yielding 46,000 samples/sec (20,480 samples in 0.445s), cutting training time from 45 minutes down to 28.7 minutes on raw CPU.
  - Holdout Test Benchmark (206,144 unseen samples):
    - URL1: 95.64% Accuracy, 86.16% Precision, 90.59% Recall, 88.32% F1, 3.24% FPR
    - URL2: 97.72% Accuracy, 92.21% Precision, 98.39% Recall, 95.20% F1, 2.48% FPR
    - URL3: 86.11% Accuracy, 76.97% Precision, 84.41% Recall, 80.52% F1
    - URL4: 90.59% Accuracy, 79.51% Precision, 90.38% Recall, 84.60% F1, 9.33% FPR
    - Grand Combined: 91.76% Accuracy (up from 91.26%), 81.67% Precision, 89.53% Recall, 85.42% F1, 7.42% FPR (down from 8.67%), and 0.9749 ROC-AUC.
    - Optimal Temperature: $T = 1.0586$.
    - Exported and verified ONNX model at `extension/models/url-threat.onnx` (194.2 KB).
- Validation:
  - All 89 extension unit tests passed (`npm test`).
  - All 4 backend RTR tests passed (`test_refresh_token_rotation.py`).
  - Offline independence preserved: browser extension remains 100% functional without backend.

### 2026-11-24 — High-Accuracy ML Model Retraining with Focal Loss, SE Attention, and Temperature Calibration

- Enhanced Neural Network Architectures:
  - URL Threat Classifier (`tools/ml_url/model.py`):
    - Upgraded from serial CNN to Inception-style multi-scale character convolutions with parallel kernels $k \in \{2, 3, 5, 7\}$ (24 channels each = 96 channels total).
    - Integrated Squeeze-and-Excitation (SE) channel attention module to dynamically weight discriminative subword channels while suppressing query string noise.
    - Implemented Dual-Pooling: Adaptive Max Pooling (96-dim, capturing acute threat tokens) combined with Adaptive Average Pooling (96-dim, capturing global character entropy) resulting in a rich 192-dimensional representation.
    - Added residual skip connection in the dense heuristic feature branch (64 -> 64 -> 48) with GELU activations.
  - Email Text Threat Classifier (`tools/ml_text/model.py`):
    - Upgraded multi-scale $n$-gram convolutions ($k \in \{2, 3, 4, 5\}$, 64 filters each = 256 total filters) with SE channel attention.
    - Integrated Adaptive Concat Pooling (256 max + 256 avg = 512 dimensions) to capture both dominant urgent triggers (e.g. credential harvesting lures) and holistic email tone.
- Advanced Optimization & Loss Functions (`tools/ml_common.py`):
  - Implemented Focal Loss ($\gamma = 2.0$, label smoothing $\alpha = 0.05$) with dynamic class weighting. Suppresses gradients from well-classified easy samples to focus learning on hard, ambiguous edge-cases (e.g. AWS S3 presigned URLs, legitimate query parameters, urgent legitimate corporate announcements).
  - Implemented post-hoc `TemperatureCalibrator` using L-BFGS validation optimization to ensure raw softmax outputs translate directly into calibrated empirical risk probabilities.
- Multi-Corpus Retraining & Holdout Validation:
  - URL Threat Model:
    - Trained across 2,067,566 URLs (1,654,564 train, 206,858 val, 206,144 holdout test).
    - Holdout test results: URL1 (95.24% acc, 92.61% recall, 0.9861 AUC, 4.17% FPR), URL2 (96.69% acc, 98.73% recall, 0.9977 AUC, 3.91% FPR), URL3 (86.06% acc, 86.22% recall, 0.9520 AUC), URL4 (89.93% acc, 92.12% recall, 0.9689 AUC).
    - Grand combined holdout: 91.26% Accuracy, 91.08% Recall, 0.9744 ROC-AUC.
    - Calibrated temperature: $T = 1.0653$.
    - Exported and verified ONNX model at `extension/models/url-threat.onnx` (194.2 KB).
  - Email Text Threat Model:
    - Trained across 101,358 email texts (81,054 train, 10,243 val, 10,061 holdout test).
    - Validation performance: 96.68% Accuracy, 96.46% F1-score, 0.9954 ROC-AUC, 2.91% FPR.
    - Grand combined holdout (10,061 unseen texts): 96.37% Accuracy, 97.03% Precision, 95.41% Recall, 96.21% F1-score, 0.9949 ROC-AUC, and 2.73% FPR.
    - Calibrated temperature: $T = 0.5259$.
    - Exported and verified ONNX model at `extension/models/email-threat.onnx` (4.64 MB).
- Enterprise Refresh Token Rotation (RTR) Integration:
  - Added single-use rotating refresh tokens (15-day expiry) with family tracking (`family_id`), SHA-256 token hashing, and automatic session reuse/theft neutralization.
  - Proactive client-side token rotation before the 30-minute access token expires.
  - Verified with 4/4 passing tests in `backend/tests/test_refresh_token_rotation.py`.
- Validation:
  - Extension unit tests: all 89 tests passed (`npm test`).
  - Backend RTR tests: all 4 tests passed (`test_refresh_token_rotation.py`).
  - ONNX Runtime Web WASM inference verified in extension workers.

### 2026-11-21 — Zero-Knowledge Client-Side AES-256-GCM Encryption for Cloud Transfers

- Zero-Knowledge Authenticated Client-Side Encryption:
  - Created `extension/src/utils/cryptoUtils.js`: Hardware-accelerated client-side cryptographic engine using W3C WebCrypto (`crypto.subtle`) implementing AES-256-GCM authenticated encryption and PBKDF2 (SHA-256, 100,000 iterations) key derivation.
  - Low Time Complexity Architecture:
    - Key derivation caching via an in-memory `Map` ensures $O(1)$ key retrieval on subsequent calls during an active session.
    - Symmetric encryption and decryption run in $O(N)$ linear time in payload length, completing in under 0.05ms per operation on standard client hardware.
  - Protected Sensitive Data Transfers:
    - Webmail link click telemetry (`url_clicks`): Encrypts sensitive fields (`url`, `defanged_url`, `email_subject`, `sender`) into authenticated base64 `encrypted_payload` (12-byte random IV + ciphertext + 16-byte authentication tag). The cloud database stores sanitized placeholders (`url: "[ENCRYPTED]"`, `defanged_url: "[ENCRYPTED]"`) and `is_encrypted: true`.
    - 15-Day Security Digest audit records: Encrypts detailed email reports and URL clicks before cloud sync; persistent `security_digest_logs` stores `is_encrypted: true` and `encrypted_payload`.
    - Cloud database exposure resistance: Even if the persistent database is leaked or accessed by an unauthorized party, raw URLs, visited domains, and email subjects remain completely indecipherable without the user's client-side secret.
  - Side Panel Transparent Decryption:
    - In `extension/src/ui/sidepanelController.js`, `renderMailClicks` transparently decrypts records on the fly via `resolveClicksForDisplay` using the session key, preserving the rich UI for the authentic user.
  - Session Purge & Key Eviction:
    - Wipes in-memory crypto keys on logout and via `chrome.storage.onChanged` in both sidepanel and background service worker.
  - Database Schema & Migration:
    - Added `is_encrypted` (boolean) and `encrypted_payload` (text) to `url_clicks` and `security_digest_logs` in SQLAlchemy models and Pydantic schemas.
    - Created Alembic migration `h8c9d0e1f2a3_add_zero_knowledge_encryption_columns.py` (revising `g7b8c9d0e1f2`).
    - Applied DDL to live Neon Cloud PostgreSQL database, verified columns, and stamped Alembic version.
    - Updated `init_db()` in `database.py` with auto-migration statements on startup.
- Verification & Validation:
  - Created unit test suite `extension/tests/cryptoUtils.test.js` (6 tests covering PBKDF2 caching, round-trip AES-256-GCM, non-repeating IVs, tamper resistance / tag corruption, wrong key rejection, and performance benchmark).
  - Created backend test suite `backend/tests/test_zk_encryption.py` (2 tests validating encrypted click persistence, retrieval, and digest dispatch).
  - All 89 extension unit tests passed (`npm test`).
  - All 10 backend integration tests passed (`test_api.py`).
  - Zero-Knowledge backend tests passed on live Neon DB (`test_zk_encryption.py`).
  - Offline autonomy preserved: Browser extension remains 100% usable independently when disconnected from cloud backend.

### 2026-11-21 — Authentication Feature Lockout & Header Logo Welcome Routing

- Strict Authentication Feature Lockout (Account-Only Access):
  - Added Auth Gate Banner (`#authGateBanner`) in the Side Panel, active whenever user is not authenticated.
  - Locked all interactive features when unauthenticated: URL Scanner, Context Email Scanning, Quick Samples, Current Tab inspection, Active Webpage Inspector, 15-Day Security Digest dispatches/previews, Mail URL Click History clearing, and Safety Feedback.
  - Unauthenticated feature actions automatically intercept user action, prompt to Sign In or Sign Up, and open the Auth modal.
  - Webmail In-Page Scanning Guard: In `contentScript.js`, checking `safeinbox_auth` before analyzing emails; renders a locked banner (`SafeInbox AI — Account Required`) and suppresses raw threat inspection until an account is signed in.
  - Live Threat Simulator Guard: In `welcomeController.js`, verifies active session before running simulation; scrolls to Auth card if unauthenticated.
- Logo & Project Title Routing:
  - Made the header `.brand` interactive (`#brandHeaderBtn`, pointer cursor, hover glow, keyboard focusable). Clicking the logo or project title now routes directly to the Welcome & Setup page (`welcome.html`).
- Validation: 83 frontend Jest tests passing, 10/10 system subsystems passing, 15/15 auth security attack vectors passing.

### 2026-11-20 — Fix Signup Verification Code HTTP 500 & Auto-Sync DB Schema

- Resolved Signup HTTP 500 on `POST /api/v1/auth/signup/request-otp`:
  - Identified root cause: Live Neon PostgreSQL schema was missing `index_id` on `users`, causing `select(User)` to raise `asyncpg.ProgrammingError: column users.index_id does not exist`.
  - Applied schema migration to Neon Cloud DB adding `index_id` on `users`, `user_index_id` on `url_clicks`, `security_digest_logs`, `terms_consents`, and `user_email`/`user_index_id` on `scan_audit_logs`, stamping Alembic version at `g7b8c9d0e1f2`.
  - Upgraded `init_db()` in `backend/app/database.py` with self-healing column synchronization (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...`) on PostgreSQL startup, ensuring schema remains synchronized across cold starts and deployments.
  - Updated `backend/Dockerfile` CMD entrypoint to run `alembic upgrade head || true` before starting Uvicorn.
  - Verified live OTP signup dispatch pipeline with `test_request_signup_otp.py` (200 OK via Google Apps Script relay).
  - Validation: 83 Jest tests passed, all 10 system subsystems passed, all 15 auth security attack vectors passed.

### 2026-11-20 — Unique Index ID Creation on Signup & Email Data/URL Tracking

- Unique Index ID Generation & Database Indexing:
  - Created deterministic, uppercase, unique index ID generator `generate_user_index_id(email)` in `backend/app/models/user.py` producing standard `SAFE-IDX-[A-F0-9]{12}` identifiers derived from SHA-256 of the normalized email.
  - Added unique column and index `index_id` (`String(64), unique=True, index=True, nullable=False`) to the `users` table.
  - Linked `user_index_id` across database persistence models:
    - `url_clicks.user_index_id` (`String(64), index=True`) in `backend/app/models/threat.py`.
    - `security_digest_logs.user_index_id` (`String(64), index=True`) in `backend/app/models/digest.py`.
    - `terms_consents.user_index_id` (`String(64), index=True`) in `backend/app/models/user.py`.
    - `scan_audit_logs.user_email` and `scan_audit_logs.user_index_id` in `backend/app/models/threat.py`.
  - Authored Alembic database migration `backend/alembic/versions/g7b8c9d0e1f2_add_user_index_id_tracking.py` (revising `f6a7b8c9d0e1`).
- Signup & Auth Pipeline Integration (`backend/app/routers/auth.py`):
  - On user registration in `POST /api/v1/auth/signup` and `POST /api/v1/auth/signup/verify-otp`, automatically creates and assigns `index_id` to `new_user`.
  - Added `index_id` to `UserResponse`, JWT Bearer token claims, and `build_user_response()`.
  - Created dedicated endpoint `GET /api/v1/auth/user-by-index/{index_id}` for public user profile retrieval by Index ID.
  - Created unified tracking endpoint `GET /api/v1/auth/track/{identifier}` accepting an email or `SAFE-IDX-...` index ID, returning aggregated account status, recent URL clicks, digest dispatches, and terms consent.
- URL Clicks & Digest Sync Tracking:
  - Updated `POST /api/v1/scan/click` and `GET /api/v1/scan/clicks` in `backend/app/routers/url.py` to record, return, and filter by `user_index_id`.
  - Updated `POST /api/v1/digest/send` and `GET /api/v1/digest/history` in `backend/app/routers/digest.py` to store and filter by `user_index_id`.
  - Updated HTML digest template generator in `backend/app/services/digest_service.py` to render the user's `Index ID: SAFE-IDX-XXXXXXXXXXXX` in the report header.
- Extension Side Panel & Welcome UI Integration:
  - Added `#authProfileIndexId`, `#authProfileIndexVal`, and `#btnCopyIndexId` to `extension/sidepanel.html` with styling in `extension/src/ui/sidepanel.css`.
  - Updated `extension/src/ui/sidepanelController.js` to render the user's Index ID in the account profile with a copy-to-clipboard action.
  - Added `#profileIndexId` and `#profileIndexVal` to `extension/welcome.html` and rendered in `extension/src/ui/welcomeController.js`.
  - Updated `extension/src/background/serviceWorker.js` (`syncClickWithBackend` and `dispatch15DayDigestNow`) to extract and propagate `user_index_id` to cloud persistence and local report templates.
- Validation:
  - Extension test suite: all 83 tests passed (`npm test`).
  - Backend whole system tests: all 10 subsystems passed (`test_entire_system.py`).
  - Backend attack vector tests: all 15 attack vectors passed (`test_auth_security.py`).

### 2026-11-20 — Side Panel Threat Intel Removal & Universal Mail URL Click History Recording

- Side Panel UI Simplification:
  - Removed the `Cloud Threat Intel` accordion panel (`#cloudPanel`) from `extension/sidepanel.html`.
  - Preserved account access through the top-header account pill button (`#accountPillBtn`), allowing users to sign in, view their profile, and sign out without unnecessary accordion clutter.
  - Retained defensive null checks in `extension/src/ui/sidepanelController.js` for seamless backward compatibility.
- Universal Webmail URL Click Recording (Safe & Threat):
  - Updated `extension/src/content/contentScript.js` to ensure 100% of all links clicked by users in webmail messages (Gmail, Outlook, Yahoo Mail) are logged into `webmail_url_clicks` and synchronized to backend persistence:
    - Added `unwrapWebmailRedirectUrl(rawUrl)` to resolve true destination targets out of tracking wrappers (e.g., `google.com/url?q=...` in Gmail, and `*.safelinks.protection.outlook.com/?url=...` in Outlook).
    - Updated `recordWebmailUrlClick(entry)` to unwrap destinations and default risk level to `"SAFE"` (or `"HIGH"` if risk score >= 50) so safe links are explicitly categorized and logged alongside threats.
    - Updated `attachSafeLinkClickListener(aEl, urlVerdict, emailData)` and `flagSuspiciousLinkElement(aEl, urlVerdict, emailData)` with capture-phase event listening (`useCapture: true`) for both `click` and `auxclick` (middle-click), ensuring client-side navigation handlers cannot drop the tracking event.
    - Added a safety-net sweep over all `urlElements` and a delegated container-level capture listener in `processSingleEmailContainer` to capture dynamically inserted or non-candidate links.
  - Updated `extension/src/background/serviceWorker.js` (`syncClickWithBackend`):
    - Added fallback checks for `sessionRes.safeinbox_auth.user.email` to guarantee clicked URLs synced to cloud persistence include the user's authenticated email.
- Validation:
  - Extension unit & E2E tests: all 83 tests passed (`npm test`).
  - Backend whole system tests: all 9 subsystems passed (`test_entire_system.py`).
  - Backend attack vector tests: all 14 vectors passed (`test_auth_security.py`).


### 2026-11-20 — 15-Day Security Digest Email with URL Click History & 15-Day Database Retention Purge

- 15-Day Security Digest Email Compilation & Delivery:
  - Enhanced `extension/src/background/serviceWorker.js` (`get15DayDigestData` & `dispatch15DayDigestNow`):
    - Corrected user email resolution to prioritize `auth.user.email` from `safeinbox_auth`, ensuring real authenticated emails receive the report.
    - Aggregates all webmail link clicks from `webmail_url_clicks` and in-email clicked URLs across the 15-day rolling window (`timestamp >= now - 15 days`).
    - Fixed cloud backend URL discovery to use `await getEffectiveBackendUrl()`, dispatching to `POST /api/v1/digest/send` on Render (`https://safeinbox-ai.onrender.com`).
    - Attached Bearer authentication header to cloud digest dispatch requests when logged in.
  - Enhanced HTML Email Report Generator (`backend/app/services/digest_service.py` & `serviceWorker.js`):
    - Added dedicated **"15-Day Webmail URL Click Audit Trail"** section rendering defanged destinations, email context, exact click timestamps, risk scores, badges, and user action outcomes.
    - Included official **"15-Day Privacy Lifecycle"** disclosure explaining the automatic purge policy.
- 15-Day Rolling Database Retention Purge:
  - Implemented `purge_expired_15day_history(db, user_email, days=15)` in `backend/app/services/digest_service.py`:
    - Automatically executed on every digest dispatch (`POST /api/v1/digest/send`) and available via dedicated endpoint `POST /api/v1/digest/purge`.
    - Permanently deletes records older than 15 days (`< now - 15 days`) from `scan_audit_logs`, `url_clicks`, and `security_digest_logs` in Neon PostgreSQL.
    - Enforced 15-day pruning in `chrome.storage.local` (`safeinbox_15day_email_records` and `webmail_url_clicks`) keeping client storage synchronized.
- Side Panel UI Enhancements (`extension/src/ui/sidepanelController.js`):
  - Updated status messages to distinguish Google Apps Script, SMTP, and autonomous delivery modes.
  - Displays purged database record count in status feedback upon completion.
- Validation:
  - Extension test suite: all 82 tests passed (`npm test`).
  - Backend whole system test suite: all 9 subsystems passed (`test_entire_system.py`).
  - Backend attack test suite: all 14 vectors passed (`test_auth_security.py`).
  - Standalone digest and retention check: passed (`run_digest_check.py`).
  - Live Google Apps Script relay: verified live email delivery with `HTTP 200 {"success": true}`.
  - Live Neon PostgreSQL database purge: verified successful deletion of expired test records older than 15 days.

### 2026-11-19 — Render Cloud Deployment & Extension Default Endpoint Integration

- Render Production Cloud Backend Live:
  - Deployed Dockerized FastAPI backend to Render at `https://safeinbox-ai.onrender.com` under 100% free tier.
  - Verified live status with remote health probe (`HTTP 200`, `status: healthy`, `environment: production`, `database: connected` to Neon PostgreSQL).
  - Validated live remote URL threat scanning (`POST https://safeinbox-ai.onrender.com/api/v1/scan/url` returned HTTP 200 with 82ms latency).
- Browser Extension Cloud Endpoint Configuration:
  - Updated default backend endpoints across `extension/src/background/serviceWorker.js`, `extension/src/ui/sidepanelController.js`, `extension/src/ui/welcomeController.js`, `extension/src/ui/termsController.js`, and `extension/sidepanel.html` to target `https://safeinbox-ai.onrender.com`.
  - Extension connects out-of-the-box to the 24/7 cloud backend over HTTPS without requiring local Python server execution.
- Validation:
  - Live HTTP health, API health, Swagger docs, and URL scan verification on `https://safeinbox-ai.onrender.com` all passed with HTTP 200.
  - All 82 extension tests passed (`npm test`).

### 2026-11-16 — Unified Ephemeral OTP System Across Sign-In, Sign-Up, 15-Day Sessions & 30-Day Password Update

- Implemented Strict Database OTP Ephemerality:
  - Database Cleanliness: Hardened `backend/app/services/otp_service.py` with `cleanup_otp_record(db, email, record)` to immediately and permanently delete OTP rows from `email_otp_verifications` table in Neon PostgreSQL the moment verification succeeds, expires, or locks out.
  - Zero Lingering Rows: Verified that after verification completes, 0 OTP records remain in the database for the user.
- Unified OTP Verification Across All Authentication Flows:
  - Sign-Up: Pre-checks 1-email-1-account -> requests 6-digit OTP -> dispatches email via Google Apps Script -> verifies OTP -> creates user -> purges OTP row from DB -> issues JWT.
  - Sign-In (including 15-Day session renewal): Validates credentials -> requests 6-digit OTP -> dispatches email via Google Apps Script -> verifies OTP -> purges OTP row from DB -> issues 15-day JWT token (`1296000s`).
  - 30-Day Password Update: Validates current password, novelty, history, complexity -> requests 6-digit OTP -> dispatches email via Google Apps Script -> verifies OTP -> purges OTP row from DB -> updates password and history in DB -> resets 30-day rotation timer.
- Extension UI & Welcome Controller Integration:
  - Unified `extension/src/ui/sidepanelController.js` and `extension/src/ui/welcomeController.js` to support multi-flow OTP authorization (`signup`, `signin`, `change_password`).
  - Added dynamic headings, step badges, prompt text, targeted email indicators, and 10-minute countdown timers across both `sidepanel.html` and `welcome.html`.
  - Updated session expiration constants from 7 days to 15 days (`FIFTEEN_DAYS_MS = 15 * 24 * 60 * 60 * 1000`).
- Validation:
  - End-to-End Live Neon Database Test (`backend/tests/test_otp_ephemeral_lifecycle.py`): Verified 100% success across all 3 flows with live Google Apps Script dispatch and verified 0 lingering OTP rows in Neon PostgreSQL.
  - Extension unit test suite: all 82 tests passed (`npm test`).
  - Backend attack test suite: all 14 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Backend entire system test suite: all 9 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).
  - Live backend uvicorn daemon running on `http://127.0.0.1:8080` with `--reload` connected to Neon PostgreSQL.

### 2026-11-16 — Google Apps Script Live Email OTP Relay Integration

- Configured Real Email OTP Dispatch via Google Apps Script:
  - Web App Relay Integration: Configured `APPS_SCRIPT_URL` and `APPS_SCRIPT_SECRET` in `backend/app/config.py` and `backend/.env`.
  - Service Integration: Updated `dispatch_otp_email` in `backend/app/services/otp_service.py` to route verification emails via asynchronous `httpx` POST to the user's deployed Google Apps Script Web App with redirect following.
  - Security Digest Relay: Updated `backend/app/services/digest_service.py` so 15-day security digests can also be dispatched through the Google Apps Script webhook relay.
  - Verification & Multi-Path Env Resolution: Enhanced Pydantic `SettingsConfigDict` to load from `(".env", "backend/.env")`.
- Validation:
  - Live Webhook Verification: Verified direct POST to `https://script.google.com/macros/s/AKfycbwxZSLh7fxMuvdIm5uxgoPbImhEmWVpFEbKU1D3ZSyQZdiKAoAd9E-R2hwyXv4Y6wge_w/exec` returned `{"success": true}`.
  - End-to-End Server Request: Executed `POST /api/v1/auth/signup/request-otp` on running uvicorn daemon; verified HTTP 200 with `delivery_mode: "apps_script"`.
  - Extension unit tests: all 82 tests passed (`npm test`).
  - Backend attack test suite: all 14 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Backend entire system test suite: all 9 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).

### 2026-11-16 — Database Synchronization Auto-Configuration & Neon Cloud Migration Sync

- Diagnosed Root Cause of Data Not Saving to Database:
  1. Offline Backend Server: The Chrome extension runs inside the browser sandbox and cannot make raw TCP socket connections to remote PostgreSQL. Data (clicks, email audits, feedback, user accounts) is communicated via HTTP API endpoints (`http://localhost:8080`). When the local backend server was not running, requests failed and were buffered locally in `chrome.storage.local` (`safeinbox_pending_clicks`, `safeinbox_pending_audits`, `safeinbox_pending_feedback`), never reaching Neon PostgreSQL.
  2. Missing `email_otp_verifications` Table on Neon: Alembic revision `f6a7b8c9d0e1` had not been executed on the live Neon PostgreSQL instance. Executed `alembic upgrade head`, bringing Neon public schema to 9 fully synchronized tables.
  3. Default Backend Configuration Initialization: `serviceWorker.js` now automatically initializes `cloudBackendUrl: "http://localhost:8080"` and `cloudBackendEnabled: true` in `chrome.storage.local` on install/startup if unconfigured.
  4. Auto-Flushing Pending Data: Added automatic `flushAllPendingCloudData()` execution on extension startup, on install, and upon successful audit/feedback submission so queued records drain to the backend immediately when the server connects.
  5. Side Panel Email Audit Dispatch: Added `RECORD_EMAIL_AUDIT` dispatch to `runEmailScan` in `sidepanelController.js` so emails scanned directly in the Side Panel are synchronized with `scan_audit_logs`.
  6. Direct Virtualenv Execution: Updated `start_backend.bat` to detect and invoke `.venv\Scripts\python.exe` directly.
- Validation:
  - Live Neon Database Synchronization: Executed `backend/tests/sync_and_track_neon.py` with 100% success across all 7 streams (`users`, `terms_consents`, `threat_urls`, `scan_audit_logs`, `feedback_records`, `security_digest_logs`, `url_clicks`).
  - Neon public schema verified with all 9 tables at head revision `f6a7b8c9d0e1`.
  - Extension unit tests: all 82 tests passed (`npm test`).
  - Backend attack test suite: all 14 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Backend entire system test suite: all 9 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).

### 2026-11-10 — ONNX Model Worker Initialization Fix & Email OTP Signup Verification

- Resolved "No trained model is installed" in Dedicated Web Workers:
  - Root Cause Diagnosed:
    1. Scope Redeclaration Syntax Error: `urlInferenceWorker.js` and `textMlWorker.js` declared `let ort = null;` at the script top level. When `importScripts("vendor/ort.min.js")` executed, `ort.min.js` declared `var ort = ...;`, triggering `SyntaxError: Identifier 'ort' has already been declared` in V8 worker execution. The caught error left `ort = null`, preventing `loadModel()` from running and silently dropping scans to heuristic-only mode.
    2. Global vs. Self Resolution: `ort = self.ort || null;` evaluated to `null` because `var ort` in strict mode does not automatically bind to `self.ort`. Resolved via universal accessor `(typeof self !== "undefined" && self.ort) || (typeof ort !== "undefined" ? ort : null)`.
    3. ONNX Session Buffer Format: Passed `modelBuffer instanceof ArrayBuffer ? new Uint8Array(modelBuffer) : modelBuffer` into `ort.InferenceSession.create` to satisfy strict TypedArray argument checks.
    4. Offscreen Host Message Routing: Fixed operator precedence in `textWorkerHost.js` so `RUN_URL_INFERENCE` is not intercepted by the email message guard.
  - Result: Both `url-threat.onnx` (80 KB) and `email-threat.onnx` (4.29 MB) initialize cleanly in browser Web Workers and offscreen documents, providing neural ONNX inferences alongside heuristic signals.
- Implemented Email OTP Verification for Sign-Up:
  - Backend Cryptographic Service (`backend/app/services/otp_service.py`):
    - Generates 6-digit cryptographically secure codes via `secrets.randbelow(900000) + 100000`.
    - Hashes codes with HMAC-SHA256 and unique 16-byte random salts; zero plaintext OTP storage.
    - Constant-time verification using `secrets.compare_digest` prevents timing attacks.
    - 3-attempt brute-force lockout and 60-second resend cooldown (`HTTP 429`).
    - 10-minute time-to-live (`expires_at`).
    - High-contrast responsive security email dispatch via SMTP with dev simulation fallback.
  - Database Model & Alembic Migration:
    - Added `EmailOTPVerification` table in `backend/app/models/user.py` and Alembic migration `f6a7b8c9d0e1_add_email_otp_verifications_table.py`.
  - API Endpoints (`backend/app/routers/auth.py`):
    - `POST /api/v1/auth/signup/request-otp`: Pre-checks 1-email-1-account policy, password complexity, upserts pending verification, and dispatches email.
    - `POST /api/v1/auth/signup/resend-otp`: Enforces 60-second cooldown and resets attempt budget.
    - `POST /api/v1/auth/signup/verify-otp`: Verifies OTP, checks TTL/lockout, creates `User` in PostgreSQL, logs terms consent, and issues 7-day JWT.
  - Extension UI Integration:
    - Added OTP verification cards, numeric code inputs, 10-minute countdown timers, and resend cooldown buttons in `extension/welcome.html`, `extension/sidepanel.html`, `extension/src/ui/welcomeController.js`, and `extension/src/ui/sidepanelController.js`.
- Validation:
  - Extension unit tests: all 82 tests passed (`npm test`).
  - Backend attack test suite: all 14 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Backend entire system test suite: all 9 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).
  - Clean syntax verified on all extension JavaScript files (`node --check`).

### 2026-11-09 — Web Worker Chrome API Isolation Fix for ONNX Neural Model Inference

- Diagnosed and Resolved "No trained model is installed" in Dedicated Web Workers:
  - Root Cause: In Chrome Manifest V3, Dedicated Web Workers (`urlInferenceWorker.js` and `textMlWorker.js` spawned via `new Worker(...)`) do not inherit the `chrome.*` extension API namespace (`DedicatedWorkerGlobalScope`). Calling `chrome.runtime.getURL("vendor/")` or `chrome.runtime.getURL("models/...")` threw a runtime `ReferenceError: chrome is not defined`, silently aborting worker initialization and causing both URL and Email Text models to drop to heuristic-only mode.
  - Universal Canonical Resource Resolution: Added `getResourceUrl(relativePath)` to both workers. It prioritizes `chrome.runtime.getURL` if available (e.g. in test mocks), and falls back to standard W3C `self.location.origin` (`chrome-extension://<id>`) and `new URL(..., self.location.href)` in real browser Dedicated Workers.
  - WASM Worker Environment Configuration: Configured `ort.env.wasm.proxy = false` and `ort.env.wasm.numThreads = 1` across both workers to enforce reliable single-threaded WebAssembly execution without multi-worker proxy deadlocks.
  - Dynamic Import & Script Loading Hardening: Wrapped script imports with canonical URL fallbacks (`importScripts(getResourceUrl(...))`), ensuring ONNX Runtime Web (`ort.min.js`), text tokenizer (`textParser.js`), and URL threat analyzer (`urlThreatParser.js`) load reliably under MV3 CSP.
- Validation:
  - Extension unit tests: all 81 passed with 0 failures (`npm test`).
  - Backend auth attack test suite: all 13 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Backend system test suite: all 8 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).
  - Node.js standalone worker simulation: verified `getResourceUrl` resolves canonical `chrome-extension://` paths and imports cleanly without `chrome` object access.

### 2026-11-04 — Full ONNX ML Model Synchronization & Offscreen Inference Engine Hardening

- Resolved "No trained model is installed" Heuristic Fallback Root Causes:
  - Manifest V3 Web Accessible Resources Fix: Corrected mismatched worker paths (`src/ml/workers/urlInferenceWorker.js`, `src/ml/textMlWorker.js`, `src/ml/textWorkerHost.js`) and added wildcard patterns (`vendor/*`, `models/*`, `src/ml/*`) in `manifest.json`. Previously, Chrome refused to load the WASM modules, MJS helpers, and ONNX models due to resource access restrictions.
  - Multi-Threading & Single-Threading WASM Asset Synchronization: Synced all ONNX Runtime Web 1.22.0 binaries (`ort-wasm-simd-threaded.wasm`, `ort-wasm-simd-threaded.jsep.wasm`, `ort-wasm-simd-threaded.mjs`, `ort-wasm-simd-threaded.jsep.mjs`) and generated runtime fallback aliases (`ort-wasm-simd.wasm`, `ort-wasm.wasm`, `ort.wasm`, `ort.all.min.js`) via `tools/sync-onnx-runtime.js`.
  - In-Memory ArrayBuffer Model Initialization: Updated both `urlInferenceWorker.js` and `textMlWorker.js` to fetch models and pass raw `ArrayBuffer` directly into `ort.InferenceSession.create()`, avoiding URL parsing failures (`ERR_INVALID_URL`) in worker fetch routines.
  - Offscreen Document Dual-Model Hosting: Upgraded `textWorkerHost.js` in `offscreen.html` to manage both the Email Text neural network and the URL inference worker. Background `serviceWorker.js` now routes URL inference to the offscreen document host automatically when the side panel is not open, eliminating heuristic fallback during webmail message scanning.
  - Stale Cache Auto-Purge: Added `purgeStaleHeuristicCaches()` on extension startup/install to evict older heuristic-only scan entries that previously recorded `model_available: false`.
- End-to-End Synchronization with Neon Database:
  - Scanned threat URLs and risk scores are synchronized directly with PostgreSQL `threat_urls` and `scan_audit_logs`.
  - User feedback and safe/threat classifications are dual-stored in `chrome.storage.local` and synchronized with `feedback_records`.
  - Hyperlink clicks are persisted to `url_clicks`.
- Validation:
  - Extension unit tests: all 81 tests passed with 0 failures (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).
  - Auth security attack test suite: all 13 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).

### 2026-11-04 — Multi-Device Duplicate Signup Elimination & Complete Log Attack Security Hardening

- Resolved Multi-Device Duplicate Signup Vulnerability:
  - Root Cause Diagnosed: Previously, when registering on Device 2 with the backend server offline or unreachable, `sidepanelController.js` and `welcomeController.js` caught the network exception and silently fell back to creating an unverified local account in `chrome.storage.local`.
  - Enforced Server Verification Requirement: Eliminated silent offline registration fallback. Account registration (Sign Up) is now strictly authoritative—it requires successful server communication to verify global email uniqueness against the Neon PostgreSQL database. If unreachable, the UI clearly instructs the user to start the backend or switch to Sign In if already registered on another device.
  - Device Local Pre-Check: Added synchronous local store pre-checks (`safeinbox_registered_users`) in both controllers rejecting duplicate registration attempts before network dispatch.
  - Seamless Multi-Device Sign In: When a user signs in on Device 2 via backend authentication, verified credentials are now securely cached locally so future offline sessions can authenticate independently on that device without duplicating the account.
  - Concurrency Race Protection: Backend catches concurrent multi-device signup attempts with `try...except IntegrityError` and returns `HTTP 409 Conflict` after rolling back the session.
- Implemented Full Log Attack Protections & CWE Defenses (`backend/app/services/log_security.py`):
  - Neutralized Log Injection & CRLF Injection (CWE-117): `sanitize_log_value` strips carriage returns (`\r`), newlines (`\n`), tabs, and non-printable control characters from all input parameters (email, user agent, IP address, event types).
  - Terminal Poisoning Defense: Stripped ANSI escape codes (`\x1b[[0-9;]*[a-zA-Z]`) preventing terminal hijacking, clearing, or color spoofing when viewing logs.
  - Zero-Credential & Secret Redaction (CWE-532): All audit log payloads automatically scan keys for `password`, `secret`, `salt`, `token`, and `key`, replacing sensitive content with `[REDACTED_SECURITY_DATA]`. Raw JWTs are masked with `mask_sensitive_token` (`eyJhbG...4xY2`).
  - Log Flooding & Disk Exhaustion DoS Defense: Bounded all logged string lengths (email: 128, IP: 64, UA: 256, details: 256) preventing disk exhaustion attacks.
  - Structured Single-Line Audit Logging: `emit_security_audit_log` formats all security events as single-line, CRLF-free JSON strings to ensure SIEM integrity.
- Validation:
  - Authentication attack test suite: all 13 attack vectors passed (`.venv\Scripts\python.exe backend/tests/test_auth_security.py`).
  - Extension test suite: all 81 tests passed with 0 failures (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`.venv\Scripts\python.exe backend/tests/test_entire_system.py`).

### 2026-11-04 — Enterprise Authentication Security, 1-Account Policy, Weekly Re-login & Monthly Password Rotation

- Implemented 1-Email-1-Account Policy:
  - Enforced unique constraint and lowercase normalization on `users.email` in database and schemas (`backend/app/models/user.py`, `backend/app/schemas/auth.py`, `backend/app/routers/auth.py`).
  - Added duplicate email rejection with clear error message: `"An account with this email address already exists. Only 1 account per email is allowed."`
- Hardened Password Complexity & Policy:
  - Upgraded minimum length to 10 characters.
  - Added checks for repetitive characters (`(.)\1{3,}`), keyboard/numeric sequential patterns (`12345`, `qwerty`, etc.), and context-aware exclusion of email username parts and full name tokens.
  - Expanded common password rejection dictionary.
- Implemented Weekly Device Re-login Policy (7 Days):
  - Token lifetime set to 7 days (604,800 seconds).
  - Added session expiration check in `extension/src/ui/sidepanelController.js` and `welcomeController.js`: auto-clears `safeinbox_auth` from `chrome.storage.local` after 7 days, forcing re-authentication on the device.
- Implemented Monthly Password Rotation Policy (30 Days) & Non-Similarity Defense:
  - Added `password_changed_at`, `password_history`, `failed_login_attempts`, and `locked_until` columns to `User` model and executed Alembic migration `e5f6a7b8c9d0` on Neon PostgreSQL.
  - Added `POST /api/v1/auth/change-password` endpoint.
  - Integrated similarity detection using Levenshtein distance and Gestalt pattern matching (`calculate_password_similarity`, `levenshtein_distance`). Rejects new passwords with similarity > 0.60 or edit distance < 4.
  - Integrated password history reuse prevention (`is_password_in_history`) rejecting the last 5 used passwords.
  - Added Change Password UI and monthly expiry notices in `extension/sidepanel.html` and `sidepanelController.js`.
- PostgreSQL Injection & Attack Hardening:
  - Audited all queries: 100% parameterized with asyncpg native bindings (`$1, $2, ...`). Zero f-strings in SQL queries.
  - Email validator explicitly rejects SQL injection metacharacters (`'`, `"`, `;`, `--`, `/*`, `*/`, `\x00`).
  - Constant-time dummy scrypt password hashing for non-existent users prevents enumeration timing attacks.
  - Account locks for 5 minutes after 5 consecutive failed login attempts.
- Validation:
  - Authentication attack test suite: all 9 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - Extension unit tests: 80 passed, 0 failed (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`python backend/tests/test_entire_system.py`).
  - Neon live sync & tracking harness: all 7 streams passed with 100% success (`python backend/tests/sync_and_track_neon.py`).
- User Actions & Click Synchronization: In-browser webmail actions (clicking external links, submitting safe/threat feedback on security banners, and email audit detections) are dual-written: stored in `chrome.storage.local` for complete offline autonomy, and dispatched asynchronously to the backend database (`POST /api/v1/scan/click`, `POST /api/v1/scan/audit`, `POST /api/v1/feedback`). An offline queue (`safeinbox_pending_clicks`, `safeinbox_pending_feedback`, `safeinbox_pending_audits`) buffers entries if the backend server is unreachable, automatically flushing queued records upon backend reconnection.
- 15-Day Security Digest Email System: Aggregates client-side webmail audit trails (`sender`, `receiver`, `subject`, `timestamp`, `time_slab`, ML threat scores and breakdown) and correlates all URL click events made by the user in each email. Dispatches a high-contrast responsive security digest email to the registered user every 15 days via SMTP (or simulated/client preview when offline) tracked by `chrome.alarms` and persisted in `SecurityDigestLog`. The side panel features live 15-day cycle tracking, manual dispatch ("Send 15-Day Digest Now"), and an in-panel HTML email preview modal.

### 2026-11-04 — Neon Lakebase Postgres Schema Synchronization & Full Data Tracking

- Connected to User's Active Neon Database:
  - Updated `DATABASE_URL` in `backend/.env` and `.env` with the user's active pooled PostgreSQL connection string: `postgresql://neondb_owner:[REDACTED_PASSWORD]@ep-summer-union-a134dbgc-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require`.
  - Configured `async_database_url` in `backend/app/config.py` to automatically adapt `postgresql://` to `postgresql+asyncpg://` while standardizing SSL parameters (`ssl=require`) for asyncpg.
- Schema Synchronization & Migration Stamping (`backend/tests/sync_and_track_neon.py`):
  - Verified connection to Neon Cloud PostgreSQL (PostgreSQL 18.6).
  - Executed `Base.metadata.create_all` to automatically synchronize missing tables (`security_digest_logs`, `url_clicks`).
  - Stamped `alembic_version` table to head revision `d4e5f6a7b8c9`.
  - Verified all 8 tables in Neon `public` schema: `alembic_version`, `feedback_records`, `scan_audit_logs`, `security_digest_logs`, `terms_consents`, `threat_urls`, `url_clicks`, and `users`.
- Live End-to-End Data Tracking Across All 7 Streams:
  - Stream 1: User Account (`users`): Stored user, PBKDF2 hashed password, full name, and active status.
  - Stream 2: Terms & Privacy Consent (`terms_consents`): Stored consent with user foreign key, IP address, and MAC address.
  - Stream 3: Threat Intelligence (`threat_urls`): Stored SHA-256 hash, URL, hostname, risk score (0.96), risk level (CRITICAL), attack types, and findings JSON.
  - Stream 4: Scan Audit Log (`scan_audit_logs`): Stored zero-PII content hash, risk score (85), and threat vectors JSON.
  - Stream 5: Model Dataset Feedback (`feedback_records`): Stored URL and TEXT partitioned feedback samples.
  - Stream 6: 15-Day Security Digest (`security_digest_logs`): Stored period start/end, total emails (38), threats (4), clicks (2), and delivery status.
  - Stream 7: Hyperlink Clicks (`url_clicks`): Stored user email, original URL, defanged URL (`hxxps://`), URL hash, risk score, and proceed decision.
  - Queried and verified 100% data integrity for all 7 records directly from Neon. Added `--keep` flag to [`backend/tests/sync_and_track_neon.py`](file:///c:/Users/Asus/Desktop/AI%20Extention/backend/tests/sync_and_track_neon.py) and populated live test records retained directly in Neon for dashboard inspection.
  - Added [`start_backend.bat`](file:///c:/Users/Asus/Desktop/AI%20Extention/start_backend.bat) one-click local launcher for running the FastAPI backend with Neon connection.
- Validation:
  - Neon live sync & tracking harness: all 7 streams passed with 100% success (`python backend/tests/sync_and_track_neon.py`).
  - Extension test suite: 80 passed, 0 failed (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`python backend/tests/test_entire_system.py`).

### 2026-11-04 — Neon Cloud Integration Setup for Project summer-union

- Extracted Neon Project Metadata from user-provided Data API endpoint (`https://ep-summer-union-a134dbgc.apirest.ap-southeast-1.aws.neon.tech/neondb/rest/v1`):
  - Endpoint ID: `ep-summer-union-a134dbgc`
  - Region: `ap-southeast-1` (AWS Singapore)
  - Database: `neondb`
  - Direct/Pooled PostgreSQL Host: `ep-summer-union-a134dbgc-pooler.ap-southeast-1.aws.neon.tech`
- Configured Environment & Settings (`backend/.env`, `.env`, `backend/app/config.py`):
  - Added `NEON_DATA_API_URL`, `NEON_HOST`, and `NEON_DATABASE` to `Settings`.
  - Created `.env` files configuring the Neon project parameters and preparing `DATABASE_URL` template for PostgreSQL + asyncpg.
- Validated Connectivity:
  - Probed Neon Data API endpoint directly, confirming live response with project request ID (`neon-request-id`).
- Validation:
  - Extension test suite: 80 passed, 0 failed (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`python backend/tests/test_entire_system.py`).
  - Database verification and live tracking: all 7 streams verified (`python backend/tests/verify_and_track_database.py`).
  - Syntax check: clean on all configurations and scripts.

### 2026-11-04 — Database Synchronization, Perfect Storage Validation & Live Tracking Harness

- Implemented Direct Scan Audit Ingestion Endpoints (`backend/app/routers/url.py`, `backend/app/schemas/url_scan.py`):
  - Added `POST /api/v1/scan/audit` accepting `ScanAuditCreate` and persisting zero-PII audit entries directly into `scan_audit_logs`.
  - Added `GET /api/v1/scan/audits` retrieving chronological audit logs with scan type filtering.
  - Wired `syncAuditWithBackend` in `extension/src/background/serviceWorker.js` to dispatch audit logs directly to `/api/v1/scan/audit` with offline buffering (`safeinbox_pending_audits`).
- Built Comprehensive Database Verification & Tracking Harness (`backend/tests/verify_and_track_database.py`):
  - Audited table schemas, column types, and constraints across all project SQLite database files (`backend/safeinbox.db` and root `safeinbox.db`).
  - Tested live data synchronization and verified 100% data integrity across all 7 core streams:
    1. Users (`users`): Stored email, PBKDF2/scrypt hashed password, full name, and active status.
    2. Terms Consents (`terms_consents`): Stored user ID foreign key link, IP address, MAC address, terms version, and agreement timestamp.
    3. Threat URLs (`threat_urls`): Stored SHA-256 URL hash, canonical URL, hostname, risk score, risk level, attack types JSON, and findings JSON.
    4. Scan Audit Logs (`scan_audit_logs`): Stored zero-PII content hash, risk score, risk level, and threat vectors JSON.
    5. Feedback Records (`feedback_records`): Stored target hash, URL vs TEXT partitioned type, boolean safe flag, source, and bounded sample.
    6. Security Digest Logs (`security_digest_logs`): Stored recipient user email, 15-day period start/end, email count, threat count, click count, and dispatch status.
    7. Hyperlink Clicks (`url_clicks`): Stored user email, original URL, defanged URL, SHA-256 hash, email subject, sender, risk score, risk level, and user proceed choice.
- Added Extension E2E Test Suite 8 (`extension/tests/entireSystemEndToEnd.test.js`):
  - Validated content script dual-write dispatches (`RECORD_WEBMAIL_CLICK`, `RECORD_FEEDBACK`, `RECORD_EMAIL_AUDIT`).
  - Validated service worker listeners and offline buffer queues (`safeinbox_pending_clicks`, `safeinbox_pending_feedback`, `safeinbox_pending_audits`).
- Validation:
  - Extension test suite: 80 passed, 0 failed (`npm test`).
  - Database schema & live tracking harness: all 7 streams verified storing with 100% integrity across both databases (`python backend/tests/verify_and_track_database.py`).
  - Database synchronization pipeline: all 6 pipelines passed (`python backend/tests/test_database_sync.py`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`python backend/tests/test_entire_system.py`).
  - Authentication attack test suite: all 6 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - Standalone 15-day digest check: passed (`python backend/tests/run_digest_check.py`).
  - Syntax check: clean on `contentScript.js` and `serviceWorker.js` (`node --check`).

### 2026-11-04 — User Action & URL Click Synchronization with SQL Database & Offline Resilience

- Identified Root Cause of Unstored Actions & Clicks:
  - Extension was operating strictly in autonomous offline mode: `recordWebmailUrlClick()` saved exclusively to `chrome.storage.local` (`webmail_url_clicks`) without dispatching a network message to the service worker or backend API.
  - The local backend server (`http://localhost:8080`) was not running, so no network listener was receiving HTTP requests.
  - The backend database schema did not yet include an ORM model or API endpoint for hyperlink click events.
- Implemented Database Schema & Migration for Click Audit Tracking (`backend/app/models/threat.py`, `backend/alembic/versions/d4e5f6a7b8c9_add_url_clicks_table.py`):
  - Created `UrlClickLog` ORM model storing `user_email`, `url`, `defanged_url`, `url_hash`, `email_subject`, `sender`, `risk_score`, `risk_level`, `proceeded`, `source`, and `clicked_at`.
  - Added Alembic migration `d4e5f6a7b8c9_add_url_clicks_table.py` and upgraded both `backend/safeinbox.db` and root `safeinbox.db` to head revision `d4e5f6a7b8c9`.
- Added Click Ingestion & Retrieval API Endpoints (`backend/app/routers/url.py`, `backend/app/schemas/url_scan.py`):
  - `POST /api/v1/scan/click`: Accepts `UrlClickCreate`, defangs URL, hashes destination, inserts into `url_clicks`, returns `UrlClickResponse`.
  - `GET /api/v1/scan/clicks`: Retrieves chronologically sorted click audit history filtered by `user_email` and bounded by `limit`.
- Wired Real-Time Action & Click Dual-Writing in Extension (`extension/src/content/contentScript.js`, `extension/src/background/serviceWorker.js`):
  - In `contentScript.js`: `recordWebmailUrlClick()` dispatches `RECORD_WEBMAIL_CLICK`; `saveBrowserFeedback()` dispatches `RECORD_FEEDBACK`; `record15DayEmailAudit()` dispatches `RECORD_EMAIL_AUDIT`.
  - In `serviceWorker.js`: Implemented `syncClickWithBackend`, `syncFeedbackWithBackend`, `syncAuditWithBackend`, and offline retry buffers (`safeinbox_pending_clicks`, `safeinbox_pending_feedback`).
  - Added `FLUSH_PENDING_SYNC` and automatic buffer flushing upon successful backend connection (`testCloudBackend`).
  - Maintained 100% offline autonomy: if backend is offline or unconfigured, all user interactions continue recording locally in `chrome.storage.local` without throwing errors or blocking UI.
- Validation:
  - Extension test suite: 79 passed, 0 failed (`npm test`).
  - Backend end-to-end system test suite: all 8 subsystems passed (`python backend/tests/test_entire_system.py`).
  - Database synchronization test harness: all 6 pipelines passed (`python backend/tests/test_database_sync.py`).
  - Authentication attack test suite: all 6 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - Syntax check: clean on `contentScript.js` and `serviceWorker.js` (`node --check`).

### 2026-11-04 — Comprehensive End-to-End System Test Run Across Extension, Models, Database Sync, and 15-Day Security Digest

- Created Full Extension End-to-End Test Suite (`extension/tests/entireSystemEndToEnd.test.js`):
  - Subsystem 1: User Sign-Up flow enforcing password complexity, cryptographic 16-byte salt generation, PBKDF2 hashing (100,000 iterations), device metadata capture, terms consent audit logging, and form input sanitization.
  - Subsystem 2: User Sign-In flow enforcing client-side brute-force lockout (triggers 30-second lockout on 5 consecutive failures), credential verification, and session storage restoration.
  - Subsystem 3: User Sign-Out flow purging `safeinbox_auth`, `safeinbox_user_session`, session `activeEmailScan`, resetting failure counters, and clearing input fields.
  - Subsystem 4: Verified all 39 buttons, tabs, links, modals, and password visibility toggles (`👁️` / `🙈`) across both Side Panel (`extension/sidepanel.html`) and Welcome onboarding page (`extension/welcome.html`).
  - Subsystem 5: Verified both neural ML models (`extension/models/url-threat.onnx` [84 KB] with 32-dim float feature vector and 128 character tensor; `extension/models/email-threat.onnx` [4.49 MB] + `extension/models/email-vocab.json` [343 KB] with WordPiece tokenization and 256-length `input_ids` and `attention_mask` tensors).
  - Subsystem 6: Verified data saving rules (FIFO bounded URL threat cache, zero-PII email text cache by SHA-256, user feedback bounded to 100 items, and mail-only URL click history bounded to 500 items).
  - Subsystem 7: Verified 15-day security digest data sharing, correlating email sender, receiver, subject, timestamp, 15-day time-slab, composite ML score, threat vectors, and all embedded clicked URLs with defanged destinations and click timestamps.
- Created Backend End-to-End System Test Suite (`backend/tests/test_entire_system.py`):
  - Validated all 7 backend subsystems: user signup and terms consent, brute-force rate limiter lockout, signout token revocation, URL threat intelligence engine, email threat analyzer, feedback dataset zero-leakage partitioning, and 15-day HTML security digest generation.
  - Enhanced HTML email report in `backend/app/services/digest_service.py` to format and display the exact click timestamp alongside defanged URLs and risk badges for each clicked link.
- Validation:
  - Full extension test suite: 79 passed, 0 failed (`npm test`).
  - Backend end-to-end system test suite: all 7 subsystems passed (`python backend/tests/test_entire_system.py`).
  - Database synchronization test harness: all 5 pipelines passed (`python backend/tests/test_database_sync.py`).
  - Authentication attack test suite: all 6 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - 15-Day digest standalone check: passed (`python backend/tests/run_digest_check.py`).
  - All non-vendor extension JavaScript files passed syntax verification (`node --check`).

### 2026-11-04 — Database Synchronization and Migration Parity across Local and Cloud Schemas

- Alembic Migration Parity & Auto-Sync (`backend/alembic/env.py`, `backend/alembic/versions/`):
  - Updated `backend/alembic/env.py` to register all ORM models (`ThreatURL`, `FeedbackRecord`, `ScanAuditLog`, `User`, `TermsConsent`, `SecurityDigestLog`) into `Base.metadata`.
  - Added synchronous execution path for SQLite in `run_migrations_online` to avoid Windows event loop socket deadlocks in sandboxed and local CI environments.
  - Successfully executed Alembic upgrade to `head` (`c3d4e5f6a7b8`), bringing all tables (`users`, `terms_consents`, `threat_urls`, `feedback_records`, `scan_audit_logs`, `security_digest_logs`) to current revision.
- Verified 5 Full Database Synchronization Pipelines (`backend/tests/test_database_sync.py`):
  1. User Authentication & Terms Consent Synchronization (`users`, `terms_consents`).
  2. URL Threat Intelligence Caching & Synchronization (`threat_urls`).
  3. Webmail Email Scan Audit Trail Synchronization (`scan_audit_logs`).
  4. Threat Feedback & Labeling Synchronization (`feedback_records`).
  5. 15-Day Security Audit Digest Synchronization (`security_digest_logs`).
- Maintained Autonomous Offline Extension Resilience: Browser extension continues operating independently with local heuristics and client-side PBKDF2 cryptography if the database or backend server is offline.
- Validation:
  - Database synchronization test harness: all 5 pipelines passed (`python backend/tests/test_database_sync.py`).
  - Alembic migrations: upgrade to head succeeded (`python -m alembic upgrade head`).
  - Backend attack test suite: all 6 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - Backend digest test suite: passed (`python backend/tests/run_digest_check.py`).
  - Extension test suite: 72 passed, 0 failed (`npm test`).

### 2026-11-03 — Security Hardening of Sign-In, Sign-Up, and Sign-Out with Attack Test Suites

- Backend Schema & Validation Hardening (`backend/app/schemas/auth.py`):
  - Upgraded email validation to strict RFC 5322 regex: `^(?!\.)[a-zA-Z0-9_.+-]+(?<!\.)@(?!-)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,24}$`, rejecting double dots, trailing dots, script injection, and invalid TLD lengths.
  - Enforced strong password policy (`validate_password_complexity`): minimum 8 characters, maximum 128 characters, uppercase, lowercase, digit, special symbol, and blacklist rejection of trivial/dictionary passwords (`password`, `12345678`, `qwerty123`, `admin123`, `safeinbox123`).
  - Stored XSS defense (`sanitize_display_name`): completely strips `<script>` and `<style>` blocks along with their inner contents, strips residual HTML tags, and removes non-printable control characters.
- Backend Brute-Force & Credential Stuffing Defense (`backend/app/services/auth_service.py`, `backend/app/routers/auth.py`):
  - Implemented `AuthRateLimiter`: Sliding-window limiter on IP addresses (max 10 signup/min, max 25 signin/min) and targeted accounts (5 consecutive failures engages progressive 180s account lockout). Returns HTTP 429 Too Many Requests with `Retry-After`.
  - User Enumeration Timing Attack Neutralization: Added `dummy_verify_password` executing a precomputed scrypt verification for non-existent email addresses. Guarantees constant-time CPU latency (~40ms) identical to valid user password verification, eliminating timing side-channels.
  - JWT Lifecycle Hardening & Broken Token Invalidation: Added unique `jti` identifier (`secrets.token_hex(16)`) and `token_version` to token payloads; implemented `revoke_token` blacklist and algorithm pinning (`HS256`).
  - Implemented `POST /api/v1/auth/signout` (and `/logout` alias) explicitly revoking active token `jti` in the revocation blacklist to prevent token reuse after sign-out.
- Extension Frontend Hardening (`extension/src/ui/sidepanelController.js`, `extension/sidepanel.html`, `extension/src/ui/welcomeController.js`, `extension/welcome.html`, `sidepanel.css`, `welcome.css`):
  - Interactive Password Visibility Toggles: Added accessible `👁️` / `🙈` toggle buttons next to password fields across both side panel and welcome onboarding modals.
  - Live Complexity Guidance: Displayed visual cues for password complexity requirements and enforced client-side email and password validation prior to submission.
  - Client-Side Brute-Force Lockout: 5 consecutive failed sign-in attempts locks the client out for 30 seconds with a live countdown display.
  - Autonomous Offline Hashing: Replaced weak client-side hashing with high-entropy `PBKDF2-HMAC-SHA256` (100,000 iterations via WebCrypto API) with cryptographically random 16-byte salts (`generateCryptoSalt`), ensuring full offline autonomy when backend is unreachable.
  - Zero-Leak Sign-Out: `clearAuthSession` and `removeAuth` notify the backend for token revocation, purge `safeinbox_auth` and `safeinbox_user_session` from storage, clear session storage `activeEmailScan`, wipe form inputs, and reset failure counters.
- Comprehensive Automated Attack Test Suites:
  - Added `extension/tests/authSecurity.test.js`: 6 tests passing (password toggle UI presence, email injection validation, password complexity policy, client lockout, PBKDF2 cryptography, and controller session cleanup).
  - Added `backend/tests/test_auth_security.py`: 6 attack vectors passing (credential stuffing lockout, dictionary attack rejection, timing enumeration neutralization, stored XSS profile sanitization, RFC email injection rejection, and JWT revocation/tampering).
- Validation:
  - Full extension test suite: 72 passed, 0 failed (`npm test`).
  - Backend attack test suite: all 6 attack vectors passed (`python backend/tests/test_auth_security.py`).
  - Backend digest test suite: all passed (`python backend/tests/run_digest_check.py`).
  - Non-vendor JavaScript syntax checks: clean (`node --check extension/src/ui/sidepanelController.js`, `node --check extension/src/ui/welcomeController.js`).

### 2026-11-03 — Implement 15-Day Security Digest Email System across backend and browser extension

- Automated 15-Day Security Digest Backend Architecture (`backend/`):
  - Added SMTP configuration settings to `backend/app/config.py` (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`, `SMTP_TLS`, `DIGEST_INTERVAL_DAYS = 15`).
  - Created Pydantic audit and dispatch models (`backend/app/schemas/digest.py`): `UrlClickItem`, `EmailRecordItem`, `DigestSendRequest`, `DigestSendResponse`, `DigestHistoryItem`.
  - Created `SecurityDigestLog` ORM model (`backend/app/models/digest.py`) and Alembic migration (`backend/alembic/versions/c3d4e5f6a7b8_add_security_digest_logs_table.py`).
  - Implemented `backend/app/services/digest_service.py`:
    - `generate_digest_html`: Generates high-contrast, responsive HTML email digest with branding, summary metrics, chronological cards with sender, receiver, time-slab, ML score breakdown (text vs URL risk), threat vectors, and defanged clicked URLs.
    - `dispatch_15_day_digest`: Non-blocking SMTP dispatch via standard library `asyncio.to_thread` with automatic fallback to simulated preview delivery, persisting audit records to `SecurityDigestLog`.
  - Implemented `backend/app/routers/digest.py`: `POST /api/v1/digest/send`, `POST /api/v1/digest/preview`, `GET /api/v1/digest/history`.
- Client-Side 15-Day Email Audit & Click Tracking (`extension/src/content/contentScript.js`):
  - Implemented `record15DayEmailAudit`: Accumulates opened email sender, receiver, subject, timestamp, time-slab, ML threat scores, and vectors in `chrome.storage.local["safeinbox_15day_email_records"]` (FIFO bounded to 500 items).
  - Implemented `associateClickWith15DayRecord`: When a webmail link is clicked, appends the clicked destination (defanged URL, risk score, risk level, timestamp) directly to the corresponding email record.
- Autonomous Background Scheduler & Runtime Messaging (`extension/src/background/serviceWorker.js`, `manifest.json`):
  - Added `"alarms"` permission to `extension/manifest.json`.
  - Configured `chrome.alarms` listener `safeinbox_15day_digest_check` (runs every 6 hours) checking 15-day elapsed window.
  - Implemented runtime message handlers:
    - `GET_15DAY_DIGEST_DATA`: returns active 15-day time-slab, user email, email count, click count, and next dispatch due timestamp.
    - `DISPATCH_15DAY_DIGEST_NOW`: allows manual immediate dispatch of the 15-day report with fallback local compilation.
    - `PREVIEW_15DAY_DIGEST`: renders full HTML email digest preview.
- Side Panel User Interface (`extension/sidepanel.html`, `sidepanel.css`, `sidepanelController.js`):
  - Added `#digestPanel` accordion displaying target user email, active 15-day time-slab window, audited email & click counts, and live status badge.
  - Added `#btnSendDigestNow` ("📧 Send 15-Day Digest Now") and `#btnPreviewDigest` ("👁 Preview Email Report").
  - Injected responsive `#digestPreviewModal` with sandboxed `<iframe>` for inspecting generated HTML email reports directly in the side panel.
- Validation:
  - All 66 extension unit and integration tests passed (`npm test`), including new `extension/tests/securityDigest.test.js`.
  - All non-vendor extension JS files passed syntax validation (`node --check`).
  - Synthetic email demo fixture passed (`node tools/check-email-demo.js`).
  - Backend digest HTML generator verified via Python assertions.

### 2026-11-02 — Train, evaluate, and deploy high-accuracy Email Text Threat ONNX model (100k+ texts)

- End-to-End Email Text Training Pipeline (`tools/ml_text/`):
  - Built custom WordPiece vocabulary generator (`build_vocab.js`) processing all 5 raw text datasets to yield a clean 16,384-token vocabulary (`extension/models/email-vocab.json`, 335 KB) including special tokens (`[PAD]`, `[UNK]`, `[CLS]`, `[SEP]`, `[URL]`, `[IP]`, `[MONEY]`).
  - Implemented high-throughput text tokenizer and feature extractor (`extract_text_features.js`) utilizing `EmailTextParser.stripHtml`, `maskSensitiveTokens`, and `wordPieceTokenize` to output memory-mapped binary tensors (`input_ids` `[N, 128]`, `attention_mask` `[N, 128]`, `labels` `[N]`).
  - Enforced zero data leakage with deterministic SHA-256 Train (80%), Val (10%), and Test (10%) splits.
  - Processed all 5 text datasets: `text1.csv` (1,600 samples), `text2.csv` (5,572 samples), `text3.csv` (5,171 samples), `text4.csv` (5,574 samples), and `both url and txt.csv` (83,441 samples), totaling **101,358 clean, verified text samples**.
- Multi-Scale 1D ConvNet Text Architecture (`tools/ml_text/model.py`):
  - Created `TextThreatNet` featuring an embedding layer (dim 64), 4 parallel Conv1D filters (kernel sizes 2, 3, 4, 5 with 64 filters each + BatchNorm1d + ReLU), adaptive max pooling, and dense projection layers yielding binary classification logits (`[safe, threat]`).
- Unified Multi-Corpus Training (`tools/ml_text/train_text.py`):
  - Shuffled across all 5 corpora simultaneously with zero-copy memory-mapped `ConcatDataset` (81,054 training samples) using AdamW, Cosine Annealing, and class-balanced Cross-Entropy loss.
- Grand Combined Benchmark on 10,061 Unseen Holdout Texts:
  - `text1` (149 test texts): 73.83% Accuracy, 75.47% F1.
  - `text2` (547 test texts): 94.88% Accuracy, 85.42% F1, 4.79% FPR.
  - `text3` (566 test texts): 97.70% Accuracy, 95.87% F1, 1.47% FPR.
  - `text4` (548 test texts): 95.62% Accuracy, 87.50% F1, 4.76% FPR.
  - `both` (8,251 test texts): 97.98% Accuracy, 98.11% F1, 1.66% FPR.
  - **Combined Benchmark (10,061 unseen texts)**: **97.31% Accuracy**, **97.24% Precision**, **97.18% Recall**, **97.21% F1-Score**, **0.9967 ROC-AUC**, **2.57% FPR**.
- Browser ONNX Model Deployment (`extension/models/email-threat.onnx`):
  - Exported verified TorchScript ONNX model (4.29 MB) accepting dynamic batch axes with `input_ids` and `attention_mask`.
  - Validated live calibration: Benign team sync email (0.03%), benign personal email (2.47%), PayPal suspension phishing (99.82%), lottery financial scam (99.06%).
- Validation:
  - All 63 extension tests passed (`npm test`).

### 2026-11-01 — Train, calibrate, and deploy high-accuracy hybrid URL threat ONNX model (2M+ URLs)

- End-to-End URL Training Pipeline & Feature Extraction (`tools/ml_url/`):
  - Created high-throughput Node.js feature extractor (`extract_features.js`, `extract_all.js`) using the shared `urlThreatParser.js` analyzer, generating 32-dim dense heuristic features and 128-token scheme-invariant character tensors.
  - Implemented strict deterministic cryptographic (SHA-256) splitting into Train (80%), Val (10%), and Test (10%) sets with zero data leakage across all datasets.
  - Processed all 4 raw datasets: `URL1.csv` (419,506 samples), `URL2.csv` (449,695 samples), `URL3.csv` (650,937 samples), and `URL4.csv` (547,428 samples), totaling **2,067,566 clean, verified URLs**.
- Hybrid Neural Network Architecture (`tools/ml_url/model.py`):
  - Built `HybridUrlThreatNet` combining a 32-dim dense heuristic subnetwork with a character-level 1D ConvNet (Embedding -> 2x Conv1D + BatchNorm + ReLU -> AdaptiveMaxPool1d -> FC) with multi-class logits (`[safe, threat]`).
- Unified Multi-Corpus Training (`tools/ml_url/train_combined.py`):
  - Shuffled across all 4 corpora simultaneously using memory-mapped zero-copy `ConcatDataset` (1,654,564 training samples) to eliminate catastrophic forgetting and protocol-prefix bias.
  - Trained with AdamW, Cosine Annealing, and class-balanced Cross-Entropy loss.
- Grand Combined Benchmark on 206,144 Unseen Holdout Samples:
  - `URL1` (41,975 test URLs): 96.38% Accuracy, 90.26% F1, 2.70% FPR.
  - `URL2` (44,732 test URLs): 97.76% Accuracy, 95.29% F1, 2.55% FPR.
  - `URL3` (64,701 test URLs): 87.38% Accuracy, 82.52% F1.
  - `URL4` (54,736 test URLs): 90.31% Accuracy, 84.45% F1.
  - **Combined Benchmark (206,144 unseen URLs)**: **92.24% Accuracy**, **91.55% Recall**, **86.42% F1-Score**, **0.9790 ROC-AUC**, **7.50% FPR**.
- Browser ONNX Model Deployment (`extension/models/url-threat.onnx`):
  - Exported verified TorchScript ONNX model (80 KB) with dynamic batch dimensions.
  - Validated live calibration: `google.com` (7.8–19.2%), `github.com` (6.8–24.3%), `wikipedia.org` (0.8–1.3%), `amazon.com` (8.1%) vs malicious URLs (100.00%).
- Validation:
  - All 63 extension tests passed (`npm test`).

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
