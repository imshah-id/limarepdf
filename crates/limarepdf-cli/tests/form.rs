//! `limarepdf-cli form fill`: a field past the 10,000 LimarePDF lists is filled by name, as
//! any other (PB-174). It was refused as not there. The values `form list --json` prints are
//! taken back with a read-only field among them (PB-207).

use limarepdf_core::{FieldValue, Pdf};
use std::path::{Path, PathBuf};
use std::process::Output;

/// How many fields LimarePDF lists.
const LISTED: usize = 10_000;

/// A stream object of `dict`'s entries holding `data`, not compressed.
fn stream(dict: &str, data: &str) -> String {
    format!(
        "<< {dict} /Length {} >>\nstream\n{data}\nendstream",
        data.len()
    )
}

/// A one-page PDF at `dir/in.pdf`, 300 by 200 points, with a form of [`LISTED`] empty text
/// fields sharing one drawing, then `last`, with none; each field is its own widget on the
/// page.
fn make_pdf(dir: &Path) -> PathBuf {
    const FIRST: usize = 7;
    let ids: Vec<String> = (0..=LISTED).map(|i| format!("{} 0 R", FIRST + i)).collect();
    let ids = ids.join(" ");
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [{ids}] >>"),
        format!("<< /Fields [{ids}] /DA (/Helv 10 Tf 0 g) /DR << /Font << /Helv 5 0 R >> >> >>"),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
        stream("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", ""),
    ];
    for i in 0..LISTED {
        objects.push(format!(
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (f{i}) /F 4 /Rect [0 0 10 10] \
             /P 3 0 R /AP << /N 6 0 R >> >>"
        ));
    }
    objects.push(
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (last) /F 4 /Rect [10 150 160 170] \
         /P 3 0 R >>"
            .into(),
    );
    write_pdf(dir, &objects)
}

/// A one-page PDF at `dir/in.pdf` with a form of one field titled with 64 KiB of `a`, and
/// under it `kids` text fields `k0`, `k1`..., each holding `v`, none with a widget.
fn make_titled(dir: &Path, kids: usize) -> PathBuf {
    const FIRST: usize = 5;
    let ids: Vec<String> = (0..kids).map(|i| format!("{} 0 R", FIRST + i)).collect();
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>".into(),
        format!(
            "<< /T ({}) /Kids [{}] >>",
            "a".repeat(65_536),
            ids.join(" ")
        ),
    ];
    objects.extend((0..kids).map(|i| format!("<< /FT /Tx /T (k{i}) /V (v) /Parent 4 0 R >>")));
    write_pdf(dir, &objects)
}

/// A one-page PDF at `dir/in.pdf` with the line "Unrelated" and a form of two text fields:
/// `Reference`, read-only, holding "A-100", and `Name`, holding "Ann".
fn make_read_only(dir: &Path) -> PathBuf {
    let objects = vec![
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R] \
         /DA (/Helv 10 Tf 0 g) /DR << /Font << /Helv 7 0 R >> >> >> >>"
            .to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 6 0 R \
         /Resources << /Font << /F1 7 0 R >> >> /Annots [4 0 R 5 0 R] >>"
            .into(),
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Reference) /Ff 1 /V (A-100) /F 4 \
         /Rect [25 100 170 120] /P 3 0 R >>"
            .into(),
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (Ann) /F 4 \
         /Rect [25 70 170 90] /P 3 0 R >>"
            .into(),
        stream("", "BT /F1 12 Tf 25 30 Td (Unrelated) Tj ET"),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
    ];
    write_pdf(dir, &objects)
}

/// `objects`, numbered from 1, the first the catalog, written as `dir/in.pdf`.
fn write_pdf(dir: &Path, objects: &[String]) -> PathBuf {
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = pdf.len();
    let size = objects.len() + 1;
    pdf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for o in offsets {
        pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    let path = dir.join("in.pdf");
    std::fs::write(&path, pdf).unwrap();
    path
}

fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("form")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    limarepdf_core::child_seam::output(
        std::process::Command::new(env!("CARGO_BIN_EXE_limarepdf-cli"))
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .args(args),
    )
    .unwrap()
}

#[test]
fn fill_sets_a_field_past_those_listed() {
    let dir = folder("past-listed");
    make_pdf(&dir);
    let res = run(
        &dir,
        &[
            "form",
            "fill",
            "in.pdf",
            "--set",
            "last=Jane Doe",
            "-o",
            "out.pdf",
        ],
    );
    let out = String::from_utf8_lossy(&res.stdout);
    let err = String::from_utf8_lossy(&res.stderr);
    assert_eq!(res.status.code(), Some(0), "{err}");
    assert!(out.starts_with("filled 1 field(s); wrote "), "{out}");

    let pdf = Pdf::open(dir.join("out.pdf"), None).unwrap();
    let last = pdf.every_form_field().pop().unwrap();
    assert_eq!(last.name, "last");
    assert_eq!(last.value, FieldValue::Text("Jane Doe".into()));
}

/// A form whose 1,100 fields share a 64 KiB title holds more than LimarePDF reads of one
/// (2²⁶ steps, the bytes of their names among them): `form fill` naming a field past those
/// read says so, writing nothing. It said there was no such field. Among 1,000, read whole,
/// a field that isn't there is not there. The name is given in a values file, looked up as
/// `--set`'s are: Windows takes a command line of 32,767 characters at most.
#[test]
fn fill_says_a_field_past_what_is_read_may_be_there() {
    let title = "a".repeat(65_536);
    let values = format!("{{\"{title}.k1099\": \"x\"}}");
    for (kids, says) in [
        (
            1_100,
            "reading the form's fields would take more than 67108864 steps",
        ),
        (1_000, "no form field named"),
    ] {
        let dir = folder(&format!("past-read-{kids}"));
        make_titled(&dir, kids);
        std::fs::write(dir.join("values.json"), &values).unwrap();
        let res = run(
            &dir,
            &[
                "form",
                "fill",
                "in.pdf",
                "--values",
                "values.json",
                "-o",
                "out.pdf",
            ],
        );
        let err = String::from_utf8_lossy(&res.stderr).replace(&title, "<title>");
        assert!(!res.status.success(), "{kids}");
        assert!(err.contains(says), "{kids}: {err}");
        assert!(!dir.join("out.pdf").exists(), "{kids}");
    }
}

/// The values `form list --json` prints, one changed, fill the form in again though a
/// read-only field is among them: its value is left as it is, and the report says so
/// (PB-207). Filling stopped at it, writing nothing. Given as it is with `--set`, it is left
/// too; any other value for it is still refused, writing nothing.
#[test]
fn fill_takes_back_the_values_listed() {
    let dir = folder("round-trip");
    make_read_only(&dir);
    let listed = run(&dir, &["form", "list", "in.pdf", "--json"]);
    assert_eq!(listed.status.code(), Some(0));
    let mut values: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(values["Reference"], "A-100");
    values["Name"] = "Bert".into();
    std::fs::write(dir.join("values.json"), values.to_string()).unwrap();
    let fill = |args: &[&str], output: &str| {
        let res = run(
            &dir,
            &[&["form", "fill", "in.pdf"], args, &["-o", output]].concat(),
        );
        let out = String::from_utf8_lossy(&res.stdout).into_owned();
        let err = String::from_utf8_lossy(&res.stderr).into_owned();
        (res.status.code(), out, err)
    };

    let (code, out, err) = fill(&["--values", "values.json"], "out.pdf");
    assert_eq!(code, Some(0), "{err}");
    assert!(
        out.starts_with("filled 1 field(s); left 1 read-only field(s) as they were; wrote "),
        "{out}"
    );
    let pdf = Pdf::open(dir.join("out.pdf"), None).unwrap();
    let value = |name: &str| {
        let fields = pdf.form_fields();
        fields.into_iter().find(|f| f.name == name).unwrap().value
    };
    assert_eq!(value("Name"), FieldValue::Text("Bert".into()));
    assert_eq!(value("Reference"), FieldValue::Text("A-100".into()));
    assert!(pdf.page_text(0).contains("Unrelated"));

    let (code, out, err) = fill(&["--set", "Reference=A-100"], "same.pdf");
    assert_eq!(code, Some(0), "{err}");
    assert!(
        out.starts_with("filled 0 field(s); left 1 read-only field(s) as they were; wrote "),
        "{out}"
    );

    values["Reference"] = "A-200".into();
    std::fs::write(dir.join("changed.json"), values.to_string()).unwrap();
    for args in [&["--values", "changed.json"], &["--set", "Reference=A-200"]] {
        let (code, out, err) = fill(args, "changed.pdf");
        assert_eq!(code, Some(1), "{args:?}");
        assert_eq!(out, "", "{args:?}");
        assert!(
            err.contains("the field \"Reference\" is read-only"),
            "{args:?}: {err}"
        );
        assert!(!dir.join("changed.pdf").exists(), "{args:?}");
    }
}
