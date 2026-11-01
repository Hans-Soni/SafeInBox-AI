# Optional ONNX model

The extension runs its URL parser and transparent heuristics without an ONNX file. To enable learned inference, place a compatible, trained binary at:

```text
extension/models/url-threat.onnx
```

The model must accept two batched inputs:

- A `float32` feature tensor shaped `[1, 32]`.
- An `int32` character-ID tensor shaped `[1, 128]`.

The preferred input names contain `feature` and `char`/`token`; otherwise the first two model inputs are used. The first model output must be a binary threat probability/logit (`[1]`) or two-class safe/threat probabilities/logits (`[1, 2]`, with threat at index 1).

Only locally packaged models are loaded. The extension does not download model files or send inspected URLs to a server. Scores from an ONNX model are combined with parser heuristics; the model does not replace them.

## Optional email text model

Email text inference is a separate modality and uses `src/ml/textMlWorker.js`. To enable it, place both of these trained, mutually compatible artifacts in this directory:

```text
email-threat.onnx
email-vocab.json
```

The vocabulary maps tokens to the exact integer IDs used by the model and must include `[PAD]`, `[UNK]`, `[CLS]`, and `[SEP]`. It may include a `max_length` field (512 is the default) and `output_type` (`logits`, the default, or `probabilities`). The model takes `input_ids` and `attention_mask` with shape `[1, max_length]`; optional `token_type_ids` are also provided if required. Inputs may be int32 or int64. Its first output must be a binary threat logit/probability or two-class logits/probabilities with threat at index 1. See [`../../docs/email-text-engine.md`](../../docs/email-text-engine.md) for details.

No email model weights or vocabulary are bundled. Do not place random or dummy weights at these paths: they would produce arbitrary confidence values and are not an accuracy test. Use `npm run check:email-demo` for the synthetic heuristic fixtures; model evaluation requires a separately trained and validated model/tokenizer pair.
