//! Print the text found in an image file, one line per text line.
//!
//! Usage: cargo run --release -p limarepdf-core --example ocr -- MODEL.onnx CHARACTERS.txt IMAGE
//!
//! MODEL.onnx is a PaddleOCR text recognition model, CHARACTERS.txt its characters, one a line.

fn main() -> limarepdf_core::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [model, characters, image] = &args[..] else {
        anyhow::bail!("usage: ocr MODEL.onnx CHARACTERS.txt IMAGE");
    };
    let characters = std::fs::read_to_string(characters)?;
    let ocr = limarepdf_core::Ocr::new(std::fs::read(model)?, &characters)?;
    let img = image::open(image)?.to_luma8();
    for line in ocr.read(img.as_raw(), img.width(), img.height())? {
        println!("{}", line.text());
    }
    Ok(())
}
