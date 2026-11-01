# Client-Side Email Text Threat Engine

## Implementation plan

1. **Disassemble and normalize email data.** `extension/src/utils/textParser.js` accepts sender, recipient, Bcc, subject, body, or raw pasted text; strips HTML/CSS/script noise; normalizes entities; and masks links, IP addresses, and money amounts before tokenization.
2. **Run transparent threat checks.** The parser emits structured findings and threat vectors for sender/display-name mismatch, consumer-mail impersonation, broad To/Cc/Bcc distribution, urgent subjects, financial hooks, credential requests, and coercive language.
3. **Prepare transformer inputs.** A model-specific WordPiece vocabulary maps the normalized message into fixed-size `input_ids` and `attention_mask` tensors. Messages are split into model-sized subword chunks (512 by default) and the worker classifies up to eight chunks, aggregating the highest threat probability.
4. **Infer off the UI thread.** `extension/src/ml/textMlWorker.js` loads locally packaged ONNX Runtime Web/WASM, a compatible quantized model, and its matching vocabulary. `extension/offscreen.html` and `src/ml/textWorkerHost.js` host this worker in a Chrome offscreen document so webmail analysis can use it even when the Side Panel is closed. It combines classifier probability with deterministic heuristics without allowing a low model score to erase a high-confidence parser finding.
5. **Route and cache locally.** `extension/src/background/serviceWorker.js` accepts Side Panel and webmail analysis requests, hashes the supplied email fields with SHA-256, routes inference through the offscreen worker, and caches bounded results in `chrome.storage.local`. Cached results omit message body, subject, address, and normalized text.
6. **Show explainable alerts.** `extension/src/content/contentScript.js` detects supported open webmail messages, renders separate URL/text banners and evidence, and highlights suspicious body sentences without rewriting message HTML. The Side Panel reuses the same analyzer and service-worker route.
7. **Verify with synthetic fixtures.** Run `npm test` and `npm run setup:email-demo`; the setup checker validates extension resources and fixture outcomes, then prints the unpacked extension path and built-in sample triggers. Load that folder in Chrome and use the Side Panel's synthetic email samples or supported webmail pages for manual DOM validation.

## Component map

```text
extension/
  manifest.json
  sidepanel.html
  offscreen.html
  src/
    background/serviceWorker.js
    content/contentScript.js
    email/emailTextAnalyzer.js
    ml/textWorkerHost.js
    ml/textMlWorker.js
    utils/textParser.js
    ui/sidepanelController.js
  models/
    email-threat.onnx       # optional trained model, not included
    email-vocab.json        # matching tokenizer vocabulary, not included
  tests/
    fixtures/email-samples.json
    textParser.test.js
```

`emailTextAnalyzer.js` is the stable compatibility facade used by the UI and webmail script. It delegates to `EmailTextParser`; threat rules and tokenization stay out of DOM and presentation code.

## ONNX model and tokenizer contract

To enable learned inference, supply **both** local files:

- `extension/models/email-threat.onnx`
- `extension/models/email-vocab.json`

The vocabulary JSON can be either a token-to-integer mapping or an object of the form `{"max_length": 512, "output_type": "logits", "vocab": {"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3}}`. Set `output_type` to `"logits"` (default) or `"probabilities"` to describe the ONNX output. The IDs and tokenization rules must match the model's training tokenizer exactly. The worker requires `[PAD]`, `[UNK]`, `[CLS]`, and `[SEP]`.

The ONNX model must accept `input_ids` and `attention_mask` with shape `[1, max_length]`; `token_type_ids` is also supplied if the model declares it. The model may declare int32 or int64 token inputs. The first output must be a binary threat logit/probability (`[1]`) or two-class logits/probabilities (`[1, 2]`, safe at index 0 and threat at index 1). The vocabulary's optional `max_length` must match the model context window.

**No trained email model or tokenizer vocabulary is included.** The extension therefore reports heuristic-only results until a compatible, trained pair is installed. Random/dummy ONNX weights would produce arbitrary confidence values and are deliberately not generated or presented as a trained model. The JSON fixtures and demo checker exercise deterministic behavior without pretending to validate learned accuracy.

## Privacy and limitations

Email analysis runs in the extension. The latest open email is temporarily handed to the Side Panel through `chrome.storage.session` and removed after that scan completes; if the Side Panel is not opened, Chrome clears the session data when its browser session ends. The SHA-256 cache stores sanitized results, not the original body, subject, or address. Model/vocabulary files are loaded only from the extension package; no email is uploaded. Explicit Safe/Threat feedback saves a bounded set of labels locally for possible future training, but it does not update the current model.

Threat-vector categories are based on transparent rules. A binary classifier can raise or corroborate overall risk but cannot provide reliable category-specific explanations unless a separately trained multi-label model and matching output contract are supplied. Heuristic signals and a model score are not proof that a message is malicious or safe.
