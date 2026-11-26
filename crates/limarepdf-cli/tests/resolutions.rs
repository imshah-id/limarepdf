//! Resolutions and JPEG qualities out of range are refused before anything is written
//! (PB-206): `images` and `insert-images`' `--dpi` and `--fallback-dpi`, `optimize-scans
//! --max-dpi`, `render --dpi` and the two `--quality` options. Files made at resolutions in
//! range open again at the sizes those give, the document added to keeping its own page.

use limarepdf_core::render::{encode, Bitmap, ImageFormat};
use limarepdf_core::{image_dimensions, FontChoice, Pdf};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Values no resolution option takes: nothing, below nothing, not a number, endless, and next
/// to nothing.
const NEVER: [&str; 6] = ["0", "-5", "nan", "inf", "-inf", "1e-30"];

fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("resolutions")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    limarepdf_core::child_seam::output(
        Command::new(env!("CARGO_BIN_EXE_limarepdf-cli"))
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .args(args),
    )
    .unwrap()
}

fn ok(dir: &Path, args: &[&str]) {
    let res = run(dir, args);
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(res.status.success(), "{args:?}: {err}");
}

/// `args` fail, saying `why` about `option`, and leave `dir` holding what it held.
fn refused(dir: &Path, args: &[&str], option: &str, why: &str) {
    let before = contents(dir);
    let res = run(dir, args);
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(!res.status.success(), "{args:?} ran");
    assert!(err.contains(option) && err.contains(why), "{args:?}: {err}");
    assert_eq!(contents(dir), before, "{args:?} changed the folder");
}

/// Every file in `dir`, below it too, with its bytes, by name.
fn contents(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut all = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        if path.is_dir() {
            all.extend(contents(&path));
        } else {
            let bytes = std::fs::read(&path).unwrap();
            all.push((path, bytes));
        }
    }
    all.sort();
    all
}

/// `name`: a `w` × `h` grey ramp stating `dpi`, 0 for a resolution LimarePDF doesn't use.
fn picture(dir: &Path, name: &str, (w, h): (usize, usize), dpi: f32) {
    let rgba = (0..w * h)
        .flat_map(|i| {
            let v = (i % w * 255 / w) as u8;
            [v, v, v, 255]
        })
        .collect();
    let b = Bitmap {
        width: w,
        height: h,
        rgba,
    };
    std::fs::write(dir.join(name), encode(&b, ImageFormat::Png, dpi).unwrap()).unwrap();
}

/// `text.pdf`: a Letter page with a line of text, nothing to do with the pictures.
fn text_pdf(dir: &Path) {
    let mut p = Pdf::new();
    p.insert_blank(0, 612.0, 792.0).unwrap();
    let font = FontChoice::default();
    p.add_text(0, (72.0, 100.0), "Harbour survey", font, 12.0, [0.0; 3])
        .unwrap();
    std::fs::write(dir.join("text.pdf"), p.to_bytes().unwrap()).unwrap();
}

/// The pages of `name`, reopened, as (width, height) in points.
fn sizes(dir: &Path, name: &str) -> Vec<(f32, f32)> {
    Pdf::open(dir.join(name), None).unwrap().page_sizes()
}

fn assert_sizes(dir: &Path, name: &str, want: &[(f32, f32)]) {
    let got = sizes(dir, name);
    let near = |a: (f32, f32), b: &(f32, f32)| (a.0 - b.0).abs() < 0.05 && (a.1 - b.1).abs() < 0.05;
    assert!(
        got.len() == want.len() && got.iter().zip(want).all(|(a, b)| near(*a, b)),
        "{name}: got {got:?}, want {want:?}"
    );
}

#[test]
fn picture_resolutions_out_of_range_are_refused() {
    let dir = folder("pictures");
    picture(&dir, "none.png", (600, 400), 0.0);
    text_pdf(&dir);
    let why = "expected a resolution from 10 to 10000 dpi";
    for v in NEVER.iter().chain(&["9.9", "10000.5"]) {
        for option in ["--dpi", "--fallback-dpi"] {
            let value = format!("{option}={v}");
            let images = ["images", "none.png", "-o", "out.pdf", &value];
            refused(&dir, &images, option, why);
            let insert = [
                "insert-images",
                "text.pdf",
                "-o",
                "out.pdf",
                "--after",
                "1",
                "--images",
                "none.png",
                &value,
            ];
            refused(&dir, &insert, option, why);
        }
    }
}

#[test]
fn pictures_at_resolutions_in_range_open_at_their_size() {
    let dir = folder("picture-sizes");
    picture(&dir, "none.png", (600, 400), 0.0);
    picture(&dir, "stated.png", (600, 400), 300.0);
    text_pdf(&dir);
    // The file's own resolution, the one assumed for a file stating none, and the ends of
    // the range.
    ok(&dir, &["images", "stated.png", "-o", "stated.pdf"]);
    assert_sizes(&dir, "stated.pdf", &[(144.0, 96.0)]);
    ok(&dir, &["images", "none.png", "-o", "none.pdf"]);
    assert_sizes(&dir, "none.pdf", &[(288.0, 192.0)]);
    let args = [
        "images",
        "none.png",
        "-o",
        "low.pdf",
        "--fallback-dpi",
        "10",
    ];
    ok(&dir, &args);
    assert_sizes(&dir, "low.pdf", &[(4320.0, 2880.0)]);
    let args = ["images", "stated.png", "-o", "high.pdf", "--dpi", "10000"];
    ok(&dir, &args);
    assert_sizes(&dir, "high.pdf", &[(4.32, 2.88)]);
    // Added to a document, the picture's page follows its own.
    let args = [
        "insert-images",
        "text.pdf",
        "-o",
        "added.pdf",
        "--after",
        "1",
        "--images",
        "none.png",
        "--dpi",
        "150",
    ];
    ok(&dir, &args);
    assert_sizes(&dir, "added.pdf", &[(612.0, 792.0), (288.0, 192.0)]);
    let p = Pdf::open(dir.join("added.pdf"), None).unwrap();
    assert!(p.page_text(0).contains("Harbour survey"));
}

#[test]
fn a_largest_scan_resolution_out_of_range_is_refused() {
    let dir = folder("scans");
    picture(&dir, "scan.png", (600, 400), 300.0);
    ok(&dir, &["images", "scan.png", "-o", "scan.pdf"]);
    let why = "expected a resolution from 10 to 10000 dpi";
    for v in NEVER.iter().chain(&["9.9", "10000.5"]) {
        let value = format!("--max-dpi={v}");
        let args = [
            "optimize-scans",
            "scan.pdf",
            "-o",
            "out.pdf",
            "--mode",
            "gray",
            &value,
        ];
        refused(&dir, &args, "--max-dpi", why);
    }
    // In range, the scan is brought down to it, and the page keeps its size.
    for d in ["50", "10"] {
        let out = format!("at-{d}.pdf");
        let args = [
            "optimize-scans",
            "scan.pdf",
            "-o",
            &out,
            "--mode",
            "gray",
            "--max-dpi",
            d,
        ];
        ok(&dir, &args);
        assert_sizes(&dir, &out, &[(144.0, 96.0)]);
    }
}

#[test]
fn render_resolutions_out_of_range_are_refused() {
    let dir = folder("render");
    picture(&dir, "small.png", (60, 40), 72.0);
    // 60 × 40 pt exactly: a PNG states 72 dpi only to the nearest pixel a metre.
    let args = ["images", "small.png", "-o", "small.pdf", "--dpi", "72"];
    ok(&dir, &args);
    let why = "expected a resolution from 36 to 1152 dpi";
    for v in NEVER.iter().chain(&["35", "1153", "2000"]) {
        let value = format!("--dpi={v}");
        let args = ["render", "small.pdf", "--out-dir", "pngs", &value];
        refused(&dir, &args, "--dpi", why);
    }
    // The ends of the range are drawn at their size.
    for (dpi, want) in [("36", (30, 20)), ("1152", (960, 640))] {
        let out = format!("at-{dpi}");
        let args = ["render", "small.pdf", "--out-dir", &out, "--dpi", dpi];
        ok(&dir, &args);
        let png = std::fs::read(dir.join(out).join("small-001.png")).unwrap();
        assert_eq!(image_dimensions(&png).unwrap(), want, "{dpi} dpi");
    }
}

#[test]
fn jpeg_qualities_out_of_range_are_refused() {
    let dir = folder("quality");
    picture(&dir, "scan.png", (600, 400), 300.0);
    ok(&dir, &["images", "scan.png", "-o", "scan.pdf"]);
    for q in ["0", "101", "255"] {
        let args = [
            "render",
            "scan.pdf",
            "--out-dir",
            "jpegs",
            "--format",
            "jpeg",
            "--quality",
            q,
        ];
        refused(&dir, &args, "--quality", "1..=100");
        let args = [
            "optimize-scans",
            "scan.pdf",
            "-o",
            "out.pdf",
            "--quality",
            q,
        ];
        refused(&dir, &args, "--quality", "1..=100");
    }
}
