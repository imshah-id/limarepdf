# Bundled OCR model

`text-recognition.onnx` is PaddleOCR's text recognition model `PP-OCRv6_small_rec`, by
PaddlePaddle. `text-recognition-chars.txt` is its list of characters, one a line in the order of
the model's classes. Both are built into `limarepdf-core` and used for OCR.

- Source: <https://huggingface.co/PaddlePaddle/PP-OCRv6_small_rec_onnx>, revision
  `b8f84f0b80c529de40b4fbb3544b84fa7233a513` (last modified 2026-06-18)
- Model: the file `inference.onnx`, 21,159,378 bytes, SHA-256
  `5435fd747c9e0efe15a96d0b378d5bd157e9492ed8fd80edf08f30d02fa24634`
- Characters: `PostProcess.character_dict` of the same revision's `inference.yml`, one a line, in
  its order (18,708 lines)
- Licence: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), the licence's text in
  `LICENSE-APACHE` at the top of this repository and in release archives
- Changes: none. The model is distributed exactly as published (only renamed); the characters are
  the list as `inference.yml` gives it, written out one a line.

The model reads Chinese and many other scripts. LimarePDF reads only the letters, digits and signs
of the languages written in Latin letters that its text layer can write (see `readable` in
`src/ocr.rs`); the other characters' classes are left out, so a Latin letter isn't read as a Greek
or Cyrillic one that looks the same.

LimarePDF itself is MIT OR Apache-2.0.

PaddleOCR's text *detection* model is not included: LimarePDF finds words with its own image
processing, and groups them into lines with [ocrs](https://github.com/robertknight/ocrs)' layout
analysis (see `src/ocr.rs`).
