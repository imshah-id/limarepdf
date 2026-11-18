//! `limarepdf-cli annot` past the budget for reading the annotations (WP-04): `annot list`
//! lists the rest marked too large to show, and `annot remove` refuses, writing nothing. An
//! annotation several pages list is listed once, and chosen by `--pages` naming any of them.

use limarepdf_core::{budget_seam, Pdf};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// An empty folder for `name`'s files.
fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `dir/in.pdf`, one page with two notes by Tester, and a budget for reading the
/// annotations one step short of reading both.
fn two_notes(dir: &Path) -> u64 {
    let mut pdf = Pdf::new();
    pdf.insert_blank(0, 400.0, 400.0).unwrap();
    for (y, text) in [(100.0, "Walrus one"), (300.0, "Walrus two")] {
        pdf.add_note(0, (100.0, y), [1.0, 1.0, 0.0], text, "Tester")
            .unwrap();
    }
    let path = dir.join("in.pdf");
    std::fs::write(&path, pdf.to_bytes().unwrap()).unwrap();
    let pdf = Pdf::open(&path, None).unwrap();
    let (_, taken) = budget_seam::with_limit(u64::MAX, || pdf.annotations());
    let short = taken[1] - 1;
    let (listed, _) = budget_seam::with_limit(short, || pdf.annotations());
    let unread: Vec<bool> = listed.iter().map(|a| a.unread).collect();
    assert_eq!(unread, [false, true]);
    short
}

/// The CLI run in `dir` with `args`, every operation limited to `budget` steps.
fn run(dir: &Path, budget: u64, args: &[&str]) -> Output {
    limarepdf_core::child_seam::output(
        Command::new(env!("CARGO_BIN_EXE_limarepdf-cli"))
            .current_dir(dir)
            .env(budget_seam::VAR, budget.to_string())
            .args(args),
    )
    .unwrap()
}

#[test]
fn an_annotation_past_the_reading_budget_is_listed_too_large_to_show() {
    let dir = folder("annotations-listed");
    let short = two_notes(&dir);
    let out = run(&dir, short, &["annot", "list", "in.pdf"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].contains("\"Walrus one\""), "{text}");
    assert!(!lines[0].contains("too large to show"), "{text}");
    assert!(lines[1].ends_with("(too large to show)"), "{text}");
    assert!(!text.contains("Walrus two"), "{text}");

    let out = run(&dir, short, &["annot", "list", "in.pdf", "--json"]);
    assert!(out.status.success(), "{out:?}");
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rows = rows.as_array().unwrap();
    let unread: Vec<_> = rows.iter().map(|r| r["unread"].as_bool()).collect();
    assert_eq!(unread, [Some(false), Some(true)], "{rows:?}");
    assert_eq!(
        (rows[1]["contents"].as_str(), rows[1]["author"].as_str()),
        (Some(""), Some(""))
    );
}

#[test]
fn removing_annotations_past_the_reading_budget_is_refused() {
    let dir = folder("annotations-removed");
    let short = two_notes(&dir);
    for pick in [&[][..], &["--author", "Tester"], &["--type", "note"]] {
        let args = [&["annot", "remove", "in.pdf", "-o", "out.pdf"][..], pick].concat();
        let out = run(&dir, short, &args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{pick:?}: {err}");
        assert!(
            err.contains("reading the annotations would take more than"),
            "{err}"
        );
        assert!(!dir.join("out.pdf").exists(), "{pick:?} wrote");
    }
}

/// A note pages 2 and 3 list, the third sharing the second's `/Annots`: listed once, on page
/// 2, whichever of them `--pages` names, and removed by `--pages 3`.
#[test]
fn a_note_two_pages_list_is_listed_once_and_chosen_by_either() {
    let dir = folder("annotations-shared");
    let mut pdf = Pdf::new();
    for i in 0..3 {
        pdf.insert_blank(i, 400.0, 400.0).unwrap();
    }
    pdf.add_note(1, (100.0, 100.0), [1.0, 1.0, 0.0], "Walrus one", "Tester")
        .unwrap();
    let ids = pdf.page_ids();
    let page = pdf.doc.get_dictionary(ids[1]).unwrap();
    let list = page.get(b"Annots").unwrap();
    let list = pdf.doc.dereference(list).unwrap().1.clone();
    let list = pdf.doc.add_object(list);
    for &page in &ids[1..] {
        let page = pdf.doc.get_dictionary_mut(page).unwrap();
        page.set("Annots", list);
    }
    std::fs::write(dir.join("in.pdf"), pdf.to_bytes().unwrap()).unwrap();
    for (pages, on) in [("1-3", &[2][..]), ("2", &[2]), ("3", &[2]), ("1", &[])] {
        let args = ["annot", "list", "in.pdf", "--json", "--pages", pages];
        let out = run(&dir, u64::MAX, &args);
        assert!(out.status.success(), "{out:?}");
        let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let rows = rows.as_array().unwrap();
        let listed: Vec<_> = rows.iter().filter_map(|r| r["page"].as_u64()).collect();
        assert_eq!(listed, on, "--pages {pages}");
    }
    let args = ["annot", "remove", "in.pdf", "-o", "out.pdf", "--pages", "3"];
    let out = run(&dir, u64::MAX, &args);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("removed 1 annotation(s)"), "{out:?}");
    let left = Pdf::open(dir.join("out.pdf"), None).unwrap();
    assert!(left.annotations().is_empty());
}
