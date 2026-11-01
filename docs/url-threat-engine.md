# Client-Side URL Threat Engine

## Architecture

- `extension/src/url/urlThreatParser.js` canonicalizes HTTP(S) URLs without navigating to them and emits findings, a 32-value heuristic feature vector, and a 128-token character tensor.
- `extension/src/background/serviceWorker.js` accepts extension messages, hashes canonical URLs and email text with SHA-256, caches bounded results in `chrome.storage.local`, and routes email inference through the offscreen worker host.
- `extension/src/ml/workers/urlInferenceWorker.js` loads locally packaged ONNX Runtime Web with the WASM execution provider and combines model output with parser risk. With no model/runtime available, the deterministic heuristic result is used.
- `extension/src/content/urlLinkScanner.js` audits HTTP(S) links on pages, shows isolated shadow-DOM badges/details, and asks before opening high-risk links.
- `extension/sidepanel.html` is the native Side Panel UI, organized into Summary, URL Scanner, and Context Scanning. The webmail content script stores the latest open email in temporary `chrome.storage.session`; the panel reads it on startup, email changes, and active-tab switches. Summary uses the mean of email-text risk and average URL risk while showing the highest individual URL risk in its explanation.
- `extension/src/email/urlCandidateExtractor.js` extracts hyperlink targets, raw URLs, `www` links, and bare domains, normalizes and deduplicates them for sequential scans.
- `extension/src/utils/textParser.js` owns email normalization, sender/recipient/subject/body heuristics, and WordPiece tensor construction. `extension/src/email/emailTextAnalyzer.js` is its shared facade for UI and content integrations.
- `extension/offscreen.html` and `extension/src/ml/textWorkerHost.js` host `extension/src/ml/textMlWorker.js` outside the UI so email inference remains available with the Side Panel closed. The text model and matching vocabulary are optional local artifacts; neither is bundled.
- `extension/src/content/contentScript.js` owns webmail DOM extraction and in-page banners, while `extension/src/ui/sidepanelController.js` owns Side Panel rendering and scan orchestration.

The intended dependency direction is UI/content integration → email or URL analysis contracts → optional inference workers. The email text analyzer is implemented behind the shared `EmailTextParser` contract; see [`email-text-engine.md`](./email-text-engine.md) for its NLP pipeline and model contract.

The scanner never opens, resolves, or fetches a URL while analyzing it. Redirect parameters, internal destinations, and payload markers are treated as indicators only. A heuristic score is not a verdict or a guarantee of safety.

## Implementation plan

1. Define the URL parser, attack indicators, model features, and test fixtures.
2. Add the SHA-256 cache and service-worker inference message bridge.
3. Package ONNX Runtime Web/WASM locally and add an optional model worker with a documented tensor contract.
4. Add safe link annotations and a confirmation dialog in the content script.
5. Connect email extraction and the native Side Panel to the URL analyzer and email-text checks.
6. Run parser tests, syntax checks, manifest checks, and Side Panel/content-flow smoke tests.

## Install and test

1. Run `npm install` in the project root.
2. Run `npm run setup:email-demo` to validate the synthetic email samples and extension resource paths. Run `npm run sync:onnx-runtime` to copy the ONNX JS/WASM assets into `extension/vendor/`.
3. Open `chrome://extensions`, enable Developer mode, and choose **Load unpacked** for the `extension/` folder.
4. Click the extension icon to open the native Side Panel. Chrome requires a user gesture and does not permit automatic panel opening on email navigation. On supported email pages, opening a message triggers in-page text and URL analysis; the panel follows the active email while open.
5. After reloading the unpacked extension, refresh the webmail tab once so Chrome installs the updated content scripts.
6. Run `npm test` for parser and integration tests.
7. Optionally add a trained model following [`../extension/models/README.md`](../extension/models/README.md), then reload the extension.

Chrome does not permit the extension to open its native Side Panel automatically from an email-open event; a user must open it from the extension icon. Email inspection banners still run on the page independently. The parser and browser-side heuristics remain active if a model file is absent. The package does not include fabricated or randomly initialized weights.
