# SafeInbox AI Browser Extension Guide

## Overview

The browser extension inspects URLs, active-page links, and email content in Chrome, Edge, and Brave. It runs locally with parser heuristics and an optional ONNX Runtime Web/WASM model. No Python service or remote API is required.

No trained ONNX weights or email tokenizer vocabulary are currently included, so email results use transparent heuristic checks until compatible local model assets are supplied. Safe/Threat feedback labels are stored in browser extension storage only, bounded to the most recent 100 URL and 100 text samples. They are not uploaded and do not train or change the current model.

The extension is organized by responsibility: `src/url/` contains URL parsing, `src/utils/textParser.js` contains email normalization, transparent rules, and WordPiece tensor construction, `src/email/` contains URL extraction and the analyzer facade, `src/content/` contains page integrations, `src/ui/` contains the Side Panel, and `src/ml/` contains off-thread URL and email inference. The email text pipeline is ready for a compatible trained model and exact matching vocabulary; until then it reports heuristic-only results. See [`email-text-engine.md`](./email-text-engine.md) for the model contract and demo steps.

## Capabilities

- Inspect URLs and links for IDN homographs, brand-like domains, DGA-like characteristics, redirect parameters, internal destinations, encoded payload markers, and inline URL credentials.
- Inspect email text and sender details for brand/domain mismatches, urgency, and credential requests.
- Scan links and supported open email messages on webmail pages.
- Review evidence and suggested actions, and save a local Safe/Threat assessment.

Inspection analyzes the URL text only: it never requests the URL or attempts to connect to internal hosts. Risk scores are indicators, not a guarantee of safety.

## Install

1. Open the extension manager:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select this project's `extension` directory.
4. Pin the extension icon if desired.

The ONNX runtime JavaScript/WASM assets are included in `extension/vendor/`; no build step is needed to load the extension. To run tests or refresh those assets, install Node.js 20+ and run `npm install`, `npm test`, `npm run setup:email-demo`, and `npm run sync:onnx-runtime` in the project root.

## Use

- Click the extension icon to open the native Side Panel, then inspect a URL or paste email content.
- Use **Scan Active Page Links** on a regular web page to review its links.
- The Side Panel has **Summary**, **URL Scanner**, and **Context Scanning** views. Summary reports the arithmetic mean of email-text risk and the average score of its URL candidates; URL Scanner shows each URL's separate score and feedback controls.
- On a supported webmail page, opening or changing a message triggers in-page email-text and URL analysis. With the Side Panel open, the panel follows email changes and active-tab switches. Email URLs are analyzed sequentially, and the highest individual URL risk is also stated so an average does not hide a high-risk link.
- Chrome requires a user gesture to open its native Side Panel. Opening an email cannot automatically open the panel; click the extension icon to open it. After reloading the extension in `chrome://extensions`, refresh the webmail tab once so the updated content script is installed.
- Feedback is stored locally as labeled samples for possible future training. The current model is not retrained automatically; no trained ONNX weights or email vocabulary are bundled.
- The optional model input contract is documented in [`../extension/models/README.md`](../extension/models/README.md).

The latest open email is temporarily kept in `chrome.storage.session` for Side Panel handoff and removed after scanning; Chrome clears that session storage at browser-session end. The persistent SHA-256 result cache omits the body, subject, and sender/recipient addresses.
