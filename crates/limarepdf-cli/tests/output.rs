//! When `limarepdf-cli` can't write its output (audit R15): a reader that went away (`… | head`)
//! is sent nothing more, and the command runs to its end with its usual status, saving what it
//! would have saved (decision D5, PB-203); any other failure, such as a full disk, is an error
//! with a plain message and status 1, saying whether a file was saved.

use limarepdf_core::render::{encode, Bitmap, ImageFormat};
use limarepdf_core::{ImageImport, Pdf};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A one-page PDF with a line of text and a filled text field.
fn make_pdf(dir: &Path) -> PathBuf {
    let content = "BT /F1 12 Tf 10 100 Td (Some words) Tj ET";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R] >>"
            .into(),
        stream(content),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (Walrus) \
         /Rect [50 50 150 70] /P 3 0 R >>"
            .into(),
    ];
    write_pdf(&dir.join("input.pdf"), &objects)
}

/// `blanks.pdf`: three pages of text, the middle one blank.
fn with_a_blank_page(dir: &Path) -> PathBuf {
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>".into(),
    ];
    for i in 0..3 {
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents {} 0 R \
             /Resources << /Font << /F1 9 0 R >> >> >>",
            6 + i
        ));
    }
    for words in ["Some words", "", "Other words"] {
        objects.push(match words {
            "" => stream(""),
            _ => stream(&format!("BT /F1 12 Tf 10 100 Td ({words}) Tj ET")),
        });
    }
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into());
    write_pdf(&dir.join("blanks.pdf"), &objects)
}

/// `scan.pdf`: one page that is a greyscale picture at 150 dpi, dark bars on light grey, as a
/// scan of text.
fn scan(dir: &Path) {
    let (width, height) = (300, 200);
    let rgba = (0..width * height)
        .flat_map(|i| {
            let (x, y) = (i % width, i / width);
            let v = match y % 20 < 6 && (20..280).contains(&x) {
                true => 30,
                false => 230,
            };
            [v, v, v, 255]
        })
        .collect();
    let bitmap = Bitmap {
        width,
        height,
        rgba,
    };
    let png = encode(&bitmap, ImageFormat::Png, 150.0).unwrap();
    let opts = ImageImport {
        dpi: Some(150.0),
        ..Default::default()
    };
    let mut p = Pdf::from_images(&[png], &opts).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("scan.pdf"), p.to_bytes().unwrap()).unwrap();
}

/// `in.pdf`: one page with a lossless picture and then a JPEG.
fn pictures(dir: &Path) {
    let bitmap = Bitmap {
        width: 40,
        height: 20,
        rgba: [200, 20, 20, 255].repeat(40 * 20),
    };
    let png = encode(&bitmap, ImageFormat::Png, 72.0).unwrap();
    let jpeg = encode(&bitmap, ImageFormat::Jpeg(90), 72.0).unwrap();
    let mut p = Pdf::new();
    p.insert_blank(0, 612.0, 792.0).unwrap();
    p.add_image(0, [72.0, 600.0, 152.0, 640.0], &png).unwrap();
    p.add_image(0, [72.0, 400.0, 152.0, 440.0], &jpeg).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("in.pdf"), p.to_bytes().unwrap()).unwrap();
}

/// A content stream object holding `content`.
fn stream(content: &str) -> String {
    format!(
        "<< /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    )
}

/// Writes `objects`, numbered from 1 with the first the catalogue, as a PDF at `path`.
fn write_pdf(path: &Path, objects: &[String]) -> PathBuf {
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = pdf.len();
    pdf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for o in offsets {
        pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, pdf).unwrap();
    path.to_path_buf()
}

fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("output")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn run(args: &[&str], dir: &Path, stdout: Stdio) -> Output {
    limarepdf_core::child_seam::output_to(
        Command::new(env!("CARGO_BIN_EXE_limarepdf-cli"))
            .current_dir(dir)
            .args(args),
        stdout,
    )
    .unwrap()
}

/// Output to a pipe whose reader has already gone, so every write fails as `… | head` would.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

/// Output to a full disk.
#[cfg(target_os = "linux")]
fn full() -> Stdio {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap()
        .into()
}

/// Commands that only report, writing to a full disk, fail with a plain message.
#[cfg(target_os = "linux")]
#[test]
fn a_report_that_cant_be_written_fails() {
    let dir = folder("report");
    make_pdf(&dir);
    for args in [
        &["info", "input.pdf"][..],
        &["text", "input.pdf"],
        &["form", "list", "input.pdf", "--json"],
    ] {
        let out = run(args, &dir, full());
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {err}");
        assert!(
            err.contains("couldn't write the output: "),
            "{args:?}: {err}"
        );
        assert!(err.contains("No space left on device"), "{args:?}: {err}");
        assert!(!err.contains("saved"), "{args:?}: {err}");
        assert!(!err.contains("internal error"), "{args:?}: {err}");
    }
}

/// A command that saved its file before its report couldn't be written says the file was
/// saved; one whose report failed before saving saves nothing.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_report_says_whether_the_file_was_saved() {
    let dir = folder("saved");
    make_pdf(&dir);
    let out = run(
        &[
            "set-info",
            "input.pdf",
            "-o",
            "titled.pdf",
            "--title",
            "Walrus",
        ],
        &dir,
        full(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("the file was saved, but its report couldn't be written: "),
        "{err}"
    );
    // The title is packed in an object stream, compressed, so the file is read.
    let saved = limarepdf_core::Pdf::open(dir.join("titled.pdf"), None).unwrap();
    assert_eq!(saved.info().title.as_deref(), Some("Walrus"));

    // Remove blank pages reports what it found before it saves.
    let out = run(
        &["remove-blank", "input.pdf", "-o", "unblank.pdf"],
        &dir,
        full(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("couldn't write the output: "), "{err}");
    assert!(!err.contains("saved"), "{err}");
    assert!(!dir.join("unblank.pdf").exists());
}

/// A reader that went away stops the output quietly, with the status the command would have
/// had: 0 normally, and 1 for `verify` when a check fails (here: no signatures, with
/// `--require-trusted`).
#[test]
fn a_reader_that_went_away_stops_quietly() {
    let dir = folder("closed");
    make_pdf(&dir);
    for args in [
        &["info", "input.pdf"][..],
        &["text", "input.pdf"],
        &["form", "list", "input.pdf", "--json"],
    ] {
        let out = run(args, &dir, closed_pipe());
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {err}");
        assert_eq!(err, "", "{args:?}");
    }
    let out = run(
        &["verify", "input.pdf", "--require-trusted"],
        &dir,
        closed_pipe(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!err.contains("couldn't write"), "{err}");
}

/// Remove blank pages reports what it found before it saves: with its reader gone, it still
/// saves, and the kept pages keep their text. It once stopped there, with status 0 and nothing
/// saved (PB-203).
#[test]
fn a_reader_that_went_away_doesnt_stop_remove_blank() {
    let dir = folder("closed-blank");
    with_a_blank_page(&dir);
    let out = run(
        &["remove-blank", "blanks.pdf", "-o", "unblank.pdf"],
        &dir,
        closed_pipe(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(err, "");
    let saved = Pdf::open(dir.join("unblank.pdf"), None).unwrap();
    assert_eq!(saved.page_count(), 2);
    assert!(saved.page_text(0).contains("Some words"));
    assert!(saved.page_text(1).contains("Other words"));
}

/// Optimise scans reports each page before it saves: with its reader gone, it still saves.
#[test]
fn a_reader_that_went_away_doesnt_stop_optimize_scans() {
    let dir = folder("closed-scans");
    scan(&dir);
    let out = run(
        &["optimize-scans", "scan.pdf", "-o", "smaller.pdf"],
        &dir,
        closed_pipe(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let saved = Pdf::open(dir.join("smaller.pdf"), None).unwrap();
    assert_eq!(saved.page_count(), 1);
}

/// Save images reports what it saved before it fails for a picture it couldn't save, here
/// for a folder in its place: with its reader gone, it still fails, with status 1, after
/// saving the other picture. It once stopped at the report, with status 0.
#[test]
fn a_reader_that_went_away_doesnt_hide_a_failure() {
    let dir = folder("closed-pictures");
    pictures(&dir);
    let pics = dir.join("pics");
    std::fs::create_dir_all(pics.join("in-page-001-image-1.png").join("mine")).unwrap();
    let out = run(
        &["save-images", "in.pdf", "--out-dir", "pics", "--overwrite"],
        &dir,
        closed_pipe(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("1 picture(s) couldn't be saved"), "{err}");
    assert!(pics.join("in-page-001-image-2.jpg").is_file());
}

/// Output that can be written is as before.
#[test]
fn output_that_can_be_written_is_unchanged() {
    let dir = folder("normal");
    make_pdf(&dir);
    let out = run(&["text", "input.pdf"], &dir, Stdio::piped());
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "--- page 1 ---\nSome words\n"
    );
    let out = run(
        &["form", "list", "input.pdf", "--json"],
        &dir,
        Stdio::piped(),
    );
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "{\n  \"Name\": \"Walrus\"\n}\n"
    );
}
