//! What changed after signing, and whether the signer allowed it: the allowed-changes
//! analysis (Acrobat's rules), the shadow and incremental-saving attack shapes, malformed
//! appended revisions, and the signed version of each signature.

// lopdf's page list, of files made here (clippy.toml).
#![allow(clippy::disallowed_methods)]

mod sigkit;

use limarepdf_core::{
    verify_signatures, Change, ChangeKind, DigitalSignature, Pdf, Permissions, Refusal, SigStatus,
    SignatureReport, TrustList,
};
use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};
use sigkit::*;

fn report(b: &[u8]) -> SignatureReport {
    verify_signatures(b, None, &TrustList::default()).unwrap()
}

/// The signature in field `name`.
fn sig(b: &[u8], name: &str) -> DigitalSignature {
    report(b)
        .signatures
        .into_iter()
        .find(|s| s.fields.iter().any(|f| f == name))
        .unwrap_or_else(|| panic!("no signature in {name}"))
}

/// The changes after the signature in `Signature1`, as (kind, refusal).
fn changes(b: &[u8]) -> Vec<(ChangeKind, Option<Refusal>)> {
    summary(&sig(b, "Signature1").changes)
}

fn summary(c: &[Change]) -> Vec<(ChangeKind, Option<Refusal>)> {
    c.iter().map(|c| (c.kind.clone(), c.refused)).collect()
}

#[track_caller]
fn assert_refused(b: &[u8], want: &ChangeKind) {
    let got = changes(b);
    assert!(
        got.iter().any(|(k, r)| k == want && r.is_some()),
        "expected {want:?} refused, got {got:#?}"
    );
    assert!(!report(b).all_ok());
}

// ---------------------------------------------------------------- building documents

/// Edits the latest version in an appended revision.
fn edit(b: &[u8], f: impl FnOnce(&Document, &mut Document)) -> Vec<u8> {
    append_update(b, |inc| {
        let prev = inc.get_prev_documents().clone();
        f(&prev, &mut inc.new_document);
    })
}

fn root(d: &Document) -> ObjectId {
    d.trailer.get(b"Root").unwrap().as_reference().unwrap()
}

fn page(d: &Document) -> ObjectId {
    *d.get_pages().get(&1).unwrap()
}

fn dict(d: &Document, id: ObjectId) -> Dictionary {
    d.get_object(id).unwrap().as_dict().unwrap().clone()
}

/// The object of the field (or annotation) titled `name`, in it or in an object of its own.
fn titled(d: &Document, name: &str) -> ObjectId {
    *d.objects
        .iter()
        .find(|(_, o)| {
            o.as_dict()
                .ok()
                .and_then(|o| o.get(b"T").ok())
                .and_then(|t| d.dereference(t).ok())
                .and_then(|(_, t)| t.as_str().ok())
                .is_some_and(|t| t == name.as_bytes())
        })
        .unwrap()
        .0
}

fn appearance(new: &mut Document, content: &str) -> ObjectId {
    new.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 20.into()],
        },
        content.as_bytes().to_vec(),
    ))
}

/// The page's annotations with `add` appended.
fn add_annot(prev: &Document, new: &mut Document, add: ObjectId) {
    let p = page(prev);
    let mut d = dict(prev, p);
    let mut annots = d
        .get(b"Annots")
        .ok()
        .and_then(|a| a.as_array().ok())
        .cloned()
        .unwrap_or_default();
    annots.push(add.into());
    d.set("Annots", annots);
    new.set_object(p, Object::Dictionary(d));
}

/// The base document with text fields named `names`.
fn form(names: &[&str]) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let p = page(prev);
        let mut fields: Vec<Object> = Vec::new();
        for (i, n) in names.iter().enumerate() {
            let ap = appearance(new, "");
            let y = 100 + 30 * i as i64;
            let id = new.add_object(dictionary! {
                "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx",
                "T" => Object::string_literal(*n), "F" => 4, "P" => p,
                "Rect" => vec![150.into(), y.into(), 250.into(), (y + 20).into()],
                "AP" => dictionary! { "N" => ap },
            });
            fields.push(id.into());
        }
        let mut d = dict(prev, p);
        d.set("Annots", fields.clone());
        new.set_object(p, Object::Dictionary(d));
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set(
            "AcroForm",
            dictionary! { "Fields" => fields, "DA" => Object::string_literal("/Helv 0 Tf 0 g") },
        );
        new.set_object(r, Object::Dictionary(c));
    })
}

/// Fills in the text field `name` with `value` and a new appearance.
fn fill(b: &[u8], name: &str, value: &str) -> Vec<u8> {
    edit(b, |prev, new| {
        let id = titled(prev, name);
        let mut d = dict(prev, id);
        let ap = appearance(new, &format!("BT ({value}) Tj ET"));
        d.set("V", Object::string_literal(value));
        d.set("AP", dictionary! { "N" => ap });
        new.set_object(id, Object::Dictionary(d));
    })
}

/// Adds a note on page 1, with `extra` entries.
fn comment(b: &[u8], extra: Dictionary) -> Vec<u8> {
    edit(b, |prev, new| {
        let mut d = dictionary! {
            "Type" => "Annot", "Subtype" => "Text", "Contents" => Object::string_literal("Hi"),
            "Rect" => vec![10.into(), 10.into(), 30.into(), 30.into()], "P" => page(prev),
        };
        d.extend(&extra);
        let id = new.add_object(d);
        add_annot(prev, new, id);
    })
}

fn approve(input: &[u8]) -> Vec<u8> {
    sign(input, &id("rsa3072"), &Field::default(), &Cms::default())
}

fn doc_mdp(p: i64) -> Object {
    vec![Object::from(dictionary! {
        "Type" => "SigRef", "TransformMethod" => "DocMDP",
        "TransformParams" => dictionary! { "Type" => "TransformParams", "V" => "1.2", "P" => p },
    })]
    .into()
}

fn certify(input: &[u8], p: i64) -> Vec<u8> {
    let f = Field {
        reference: Some(doc_mdp(p)),
        perms: true,
        ..Field::default()
    };
    sign(input, &id("rsa3072"), &f, &Cms::default())
}

/// Signs `input` in a new field `name` with another key.
fn countersign(input: &[u8], name: &'static str, invisible: bool) -> Vec<u8> {
    let f = Field {
        name,
        invisible,
        ..Field::default()
    };
    sign(input, &id("p256"), &f, &Cms::default())
}

fn timestamp(input: &[u8], invisible: bool) -> Vec<u8> {
    let f = Field {
        name: "Timestamp1",
        sub_filter: "ETSI.RFC3161",
        doc_timestamp: true,
        invisible,
        m: None,
        reason: None,
        ..Field::default()
    };
    sign_with(input, &f, |r| {
        timestamp_token(&tsa(), r, "20260601130000Z", Hash::Sha256)
    })
}

fn lock(action: &str, fields: &[&str], p: Option<i64>) -> Object {
    let mut params = dictionary! {
        "Type" => "TransformParams", "V" => "1.2", "Action" => Object::Name(action.into()),
        "Fields" => fields.iter().map(|f| Object::string_literal(*f)).collect::<Vec<_>>(),
    };
    if let Some(p) = p {
        params.set("P", p);
    }
    vec![Object::from(dictionary! {
        "Type" => "SigRef", "TransformMethod" => "FieldMDP", "TransformParams" => params,
    })]
    .into()
}

fn locked_by(input: &[u8], reference: Object) -> Vec<u8> {
    let f = Field {
        reference: Some(reference),
        ..Field::default()
    };
    sign(input, &id("rsa3072"), &f, &Cms::default())
}

/// The page's content stream.
fn contents(b: &[u8]) -> ObjectId {
    let d = Document::load_mem(b).unwrap();
    dict(&d, page(&d))
        .get(b"Contents")
        .unwrap()
        .as_reference()
        .unwrap()
}

/// A viewer navigation action, harmless, never run.
fn next_page() -> Dictionary {
    dictionary! { "S" => "Named", "N" => "NextPage" }
}

/// Widget entries running `next_page()` when the widget's page opens.
fn on_open() -> Dictionary {
    dictionary! { "AA" => dictionary! { "PO" => next_page() } }
}

/// Entries for a new widget, made with any objects they need.
type Entries = fn(&mut Document) -> Dictionary;

/// `b` with an empty, invisible signature field `Extra` added as the full audit's probe adds
/// it: one widget, or (`kid`) a field with the widget as its kid. `extra` makes entries for
/// the widget (an action, say), adding any objects they need.
fn extra_field(b: &[u8], kid: bool, extra: impl FnOnce(&mut Document) -> Dictionary) -> Vec<u8> {
    edit(b, |prev, new| {
        let mut widget = dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "P" => page(prev),
            "Rect" => vec![0.into(), 0.into(), 0.into(), 0.into()],
        };
        widget.extend(&extra(new));
        let mut field = dictionary! { "FT" => "Sig", "T" => Object::string_literal("Extra") };
        let top = if kid {
            let top = new.new_object_id();
            widget.set("Parent", top);
            let w = new.add_object(widget);
            add_annot(prev, new, w);
            field.set("Kids", vec![Object::from(w)]);
            new.set_object(top, Object::Dictionary(field));
            top
        } else {
            widget.extend(&field);
            let w = new.add_object(widget);
            add_annot(prev, new, w);
            w
        };
        list_field(prev, new, top);
    })
}

/// Field `top` listed last in the form's `/Fields`.
fn list_field(prev: &Document, new: &mut Document, top: ObjectId) {
    let r = root(prev);
    let mut c = dict(prev, r);
    // A file not yet signed may have no form.
    let mut form = (c.get(b"AcroForm").and_then(Object::as_dict).cloned()).unwrap_or_default();
    let mut fields = (form.get(b"Fields").and_then(Object::as_array).cloned()).unwrap_or_default();
    fields.push(top.into());
    form.set("Fields", fields);
    c.set("AcroForm", form);
    new.set_object(r, Object::Dictionary(c));
}

/// Field `top` moved first in the form's `/Fields`, the rest kept in order.
fn list_first(prev: &Document, new: &mut Document, top: ObjectId) {
    relist(prev, new, |fields| {
        fields.retain(|f| f.as_reference().ok() != Some(top));
        fields.insert(0, top.into());
    });
}

/// Field `top` no longer listed in the form's `/Fields`.
fn unlist(prev: &Document, new: &mut Document, top: ObjectId) {
    relist(prev, new, |fields| {
        fields.retain(|f| f.as_reference().ok() != Some(top))
    });
}

/// The form's `/Fields` changed by `change`.
fn relist(prev: &Document, new: &mut Document, change: impl FnOnce(&mut Vec<Object>)) {
    let r = root(prev);
    let mut c = dict(prev, r);
    let mut form = c.get(b"AcroForm").unwrap().as_dict().unwrap().clone();
    let mut fields = form.get(b"Fields").unwrap().as_array().unwrap().clone();
    change(&mut fields);
    form.set("Fields", fields);
    c.set("AcroForm", form);
    new.set_object(r, Object::Dictionary(c));
}

// ---------------------------------------------------------------- allowed changes

#[test]
fn nothing_changed_after_signing() {
    let b = approve(&base_pdf());
    let s = sig(&b, "Signature1");
    assert!(s.changes.is_empty());
    assert_eq!(s.signed_len, Some(b.len()));
    assert!(report(&b).all_ok());
    // White space after the end changes nothing.
    let mut w = b.clone();
    w.extend_from_slice(b"\r\n\n");
    assert!(sig(&w, "Signature1").changes.is_empty());
}

/// A revision with a cross-reference table listing only the head of the free list, after
/// one with a stream, changes nothing. lopdf lists object 0 as free after reading such a
/// table, but not before, and that was refused as "can't read object 0 reliably".
#[test]
fn a_table_after_a_cross_reference_stream_changes_nothing_by_itself() {
    let mut d = Document::load_mem(&base_pdf()).unwrap();
    d.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceStream;
    let mut base = Vec::new();
    d.save_to(&mut base).unwrap();
    let b = approve(&base);
    assert!(sig(&b, "Signature1").changes.is_empty());
    let b = append_raw(&b, &[], &[0], &[], "");
    assert!(String::from_utf8_lossy(&b).contains("\nxref\n0 1\n"));
    assert_eq!(changes(&b), []);
    assert!(report(&b).all_ok());
}

/// A revision written by hand: object 1 as `body` in a new object stream, and a
/// cross-reference stream giving object 0 the entry `zero` (type and fields, `/W [1 4 2]`).
/// When `named`, that entry is in a second cross-reference stream the first names with
/// `/XRefStm` instead, and the first lists nothing for object 0.
fn object_one_in_a_stream(b: &[u8], body: &str, zero: (u8, u32, u16), named: bool) -> Vec<u8> {
    let d = Document::load_mem(b).unwrap();
    let r = root(&d);
    let prev = last_startxref(b);
    let (stm, x, s) = (d.max_id + 1, d.max_id + 2, d.max_id + 3);
    let mut out = [b, b"\n"].concat();
    let at_stm = out.len();
    let data = format!("1 0 {body}");
    out.extend_from_slice(
        format!(
            "{stm} 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{data}\n\
             endstream\nendobj\n",
            data.len()
        )
        .as_bytes(),
    );
    let rows = |entries: &[(u8, u32, u16)]| {
        let mut rows = Vec::new();
        for &(kind, f1, f2) in entries {
            rows.push(kind);
            rows.extend_from_slice(&f1.to_be_bytes());
            rows.extend_from_slice(&f2.to_be_bytes());
        }
        rows
    };
    let at_s = out.len();
    if named {
        let zero = rows(&[zero]);
        out.extend_from_slice(
            format!(
                "{s} 0 obj\n<< /Type /XRef /W [1 4 2] /Index [0 1] /Size {} /Length {} >>\n\
                 stream\n",
                s + 1,
                zero.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&zero);
        out.extend_from_slice(b"\nendstream\nendobj\n");
    }
    let at_x = out.len();
    let mut entries = vec![(2, stm, 0), (1, at_stm as u32, 0), (1, at_x as u32, 0)];
    let (index, size, more) = if named {
        entries.push((1, at_s as u32, 0));
        (format!("1 1 {stm} 3"), s + 1, format!(" /XRefStm {at_s}"))
    } else {
        entries.insert(0, zero);
        (format!("0 2 {stm} 2"), x + 1, String::new())
    };
    let rows = rows(&entries);
    out.extend_from_slice(
        format!(
            "{x} 0 obj\n<< /Type /XRef /W [1 4 2] /Index [{index}] /Size {size} /Root {} {} R \
             /Prev {prev}{more} /Length {} >>\nstream\n",
            r.0,
            r.1,
            rows.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&rows);
    out.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{at_x}\n%%EOF\n").as_bytes());
    out
}

/// A hybrid revision written by hand: object 1 as `body` in a new object stream, listed in
/// a cross-reference stream that a table names with `/XRefStm`. The table lists a new
/// number N with `table_n`, rows of type and offset (`f` or `n`), and the stream with
/// `stream_n`, rows of type and fields (`/W [1 4 2]`). Returns the file and N.
fn hybrid_revision(
    b: &[u8],
    body: &str,
    table_n: &[(char, u32)],
    stream_n: &[(u8, u32, u16)],
) -> (Vec<u8>, u32) {
    let d = Document::load_mem(b).unwrap();
    let r = root(&d);
    let prev = last_startxref(b);
    let (stm, x, n) = (d.max_id + 1, d.max_id + 2, d.max_id + 3);
    let mut out = [b, b"\n"].concat();
    let at_stm = out.len();
    let data = format!("1 0 {body}");
    out.extend_from_slice(
        format!(
            "{stm} 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{data}\n\
             endstream\nendobj\n",
            data.len()
        )
        .as_bytes(),
    );
    let mut entries = vec![(2u8, stm, 0u16)];
    let mut index = "1 1".to_string();
    for &e in stream_n {
        entries.push(e);
        index.push_str(&format!(" {n} 1"));
    }
    let mut rows = Vec::new();
    for (kind, f1, f2) in entries {
        rows.push(kind);
        rows.extend_from_slice(&f1.to_be_bytes());
        rows.extend_from_slice(&f2.to_be_bytes());
    }
    let at_x = out.len();
    out.extend_from_slice(
        format!(
            "{x} 0 obj\n<< /Type /XRef /W [1 4 2] /Index [{index}] /Size {} /Length {} >>\n\
             stream\n",
            n + 1,
            rows.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&rows);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let at_t = out.len();
    let mut table = format!("xref\n{stm} 2\n{at_stm:010} 00000 n\r\n{at_x:010} 00000 n\r\n");
    for &(kind, offset) in table_n {
        table.push_str(&format!("{n} 1\n{offset:010} 00000 {kind}\r\n"));
    }
    out.extend_from_slice(
        format!(
            "{table}trailer\n<< /Size {} /Root {} {} R /Prev {prev} /XRefStm {at_x} >>\n\
             startxref\n{at_t}\n%%EOF\n",
            n + 1,
            r.0,
            r.1
        )
        .as_bytes(),
    );
    (out, n)
}

/// The `startxref` value of the revision `b` ends with.
fn last_startxref(b: &[u8]) -> String {
    let tail = String::from_utf8_lossy(&b[b.len() - 40..]).into_owned();
    let prev = tail.split("startxref").last().unwrap();
    prev.split_whitespace().next().unwrap().to_string()
}

/// A signed file whose cross-reference is a stream, with object 1 (the catalog) written
/// plainly: the file, where object 1 starts, and its dictionary as written.
fn object_one_signed() -> (Vec<u8>, u32, String) {
    let mut d = Document::load_mem(&base_pdf()).unwrap();
    d.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceStream;
    let mut base = Vec::new();
    d.save_to(&mut base).unwrap();
    let b = approve(&base);
    let d = Document::load_mem(&b).unwrap();
    let Some(&lopdf::xref::XrefEntry::Normal { offset, .. }) = d.reference_table.get(1) else {
        panic!("object 1 isn't written plainly");
    };
    let at = offset as usize;
    let text = String::from_utf8_lossy(&b[at..at + 200]).into_owned();
    assert!(text.starts_with("1 0 obj"));
    let old = text["1 0 obj".len()..]
        .split("endobj")
        .next()
        .unwrap()
        .trim()
        .to_string();
    (b, offset, old)
}

/// An entry in use for object 0, added between two signatures and freed after the second,
/// is refused. One pointing at the signed bytes of object 1 has lopdf read that old copy
/// over a new one in an object stream (it keeps the object an entry's bytes name, and
/// never puts an object-stream member over one it has). The second signature can't be
/// checked then, so the first was compared with the end alone, where object 0 is only
/// free, and the page tree turned for the second signer, then turned back, passed as
/// allowed.
#[test]
fn an_entry_in_use_for_object_0_is_refused() {
    let (b, offset, old) = object_one_signed();
    let max_id = Document::load_mem(&b).unwrap().max_id;
    let turned = format!("{}/Rotate 180>>", old.strip_suffix(">>").unwrap());
    // Object 0 at object 1's signed bytes, or in the new object stream.
    for zero in [(1, offset, 0), (2, max_id + 1, 0)] {
        let r2 = object_one_in_a_stream(&b, &turned, zero, false);
        let s2 = countersign(&r2, "Signature2", true);
        let b = append_raw(&s2, &[(1, old.as_bytes())], &[0], &[], "");
        let want = ChangeKind::Malformed("LimarePDF can't read object 0 reliably".into());
        let got = changes(&b);
        assert!(
            got.contains(&(want, Some(Refusal::Never))),
            "{zero:?}: {got:#?}"
        );
    }
}

/// A cross-reference stream naming another with `/XRefStm`, after signing, is refused. The
/// specification gives that key to a table's trailer only, and other apps don't follow it
/// from a stream, but lopdf does: there an entry in use for object 0, at object 1's signed
/// bytes, brought back that old copy past the check of
/// [`an_entry_in_use_for_object_0_is_refused`], and the page tree turned for the second
/// signer, then turned back, passed as allowed.
#[test]
fn a_cross_reference_stream_naming_another_is_refused() {
    let want = ChangeKind::Malformed(
        "a later revision's cross-reference stream names another one (/XRefStm), which PDF \
         apps read differently"
            .into(),
    );
    let (end, _) = turned_for_the_second_signer(|b, turned, offset| {
        let r2 = object_one_in_a_stream(b, turned, (1, offset, 0), true);
        // LimarePDF says other apps read the file differently.
        assert!(Pdf::from_bytes(&r2, None).unwrap().differs().is_some());
        (r2, 0)
    });
    let got = changes(&end);
    assert!(
        got.contains(&(want.clone(), Some(Refusal::Never))),
        "{got:#?}"
    );
    // The key alone is refused, whatever the stream it names lists.
    let (b, _, old) = object_one_signed();
    let plain = object_one_in_a_stream(&b, &old, (0, 0, 65535), true);
    assert_eq!(changes(&plain), [(want, Some(Refusal::Never))]);
}

/// The page tree turned for a second signer by a revision that lopdf reads with object 1's
/// signed copy, and turned back after: `revision` makes the first from the signed file,
/// object 1 turned and where its signed copy starts, returning it and the number lopdf
/// reads at that copy, which the last revision frees. Returns the file and that number.
fn turned_for_the_second_signer(
    revision: impl Fn(&[u8], &str, u32) -> (Vec<u8>, u32),
) -> (Vec<u8>, u32) {
    let (b, offset, old) = object_one_signed();
    let turned = format!("{}/Rotate 180>>", old.strip_suffix(">>").unwrap());
    let (r2, n) = revision(&b, &turned, offset);
    let lopdf = Document::load_mem(&r2).unwrap();
    assert!(matches!(
        lopdf.reference_table.get(n),
        Some(&lopdf::xref::XrefEntry::Normal { offset: o, .. }) if o == offset
    ));
    let s2 = countersign(&r2, "Signature2", true);
    (append_raw(&s2, &[(1, old.as_bytes())], &[n], &[], ""), n)
}

/// A hybrid revision whose table frees a number its cross-reference stream places, after
/// signing, is refused. Apps that read the table first take the number as free, but lopdf
/// lets the stream's entry replace a free one: placed at object 1's signed bytes, it
/// brought back that old copy over a new one in an object stream, and the page tree
/// turned for the second signer, then turned back, passed as allowed.
#[test]
fn a_hybrid_table_freeing_what_its_stream_places_is_refused() {
    let want = |n| {
        ChangeKind::Malformed(format!(
            "a later revision lists object {n} as free in its cross-reference table but in \
             use in its cross-reference stream, which PDF apps read differently"
        ))
    };
    let (end, n) = turned_for_the_second_signer(|b, turned, offset| {
        hybrid_revision(b, turned, &[('f', 0)], &[(1, offset, 0)])
    });
    let got = changes(&end);
    assert!(got.contains(&(want(n), Some(Refusal::Never))), "{got:#?}");
    // The two entries alone are refused, with nothing changed.
    let (b, offset, old) = object_one_signed();
    let (plain, n) = hybrid_revision(&b, &old, &[('f', 0)], &[(1, offset, 0)]);
    assert_eq!(changes(&plain), [(want(n), Some(Refusal::Never))]);
}

/// A revision giving a number two different entries in one cross-reference section, after
/// signing, is refused. LimarePDF takes the first and lopdf the last: free, then at object
/// 1's signed bytes, lopdf brought back that old copy over a new one in an object stream,
/// and the page tree turned for the second signer, then turned back, passed as allowed.
#[test]
fn a_number_listed_twice_differently_is_refused() {
    let want = |n| {
        ChangeKind::Malformed(format!(
            "a later revision gives object {n} two different cross-reference entries, which \
             PDF apps read differently"
        ))
    };
    // Twice in the table, or twice in the cross-reference stream.
    for in_stream in [false, true] {
        let revision = |b: &[u8], body: &str, offset| match in_stream {
            false => hybrid_revision(b, body, &[('f', 0), ('n', offset)], &[]),
            true => hybrid_revision(b, body, &[], &[(0, 0, 0), (1, offset, 0)]),
        };
        let (end, n) = turned_for_the_second_signer(revision);
        let got = changes(&end);
        assert!(got.contains(&(want(n), Some(Refusal::Never))), "{got:#?}");
        // The two entries alone are refused, with nothing changed.
        let (b, offset, old) = object_one_signed();
        let (plain, n) = revision(&b, &old, offset);
        assert_eq!(changes(&plain), [(want(n), Some(Refusal::Never))]);
    }
    // The same entry twice reads alike everywhere.
    let (b, _, old) = object_one_signed();
    let (twice, _) = hybrid_revision(&b, &old, &[('f', 0), ('f', 0)], &[]);
    assert_eq!(changes(&twice), []);
}

/// A later signature whose version other apps may read differently from LimarePDF can't be
/// checked, so the versions before and after it are compared as one, and the earlier
/// signatures are refused too. A new number at object 1's signed bytes had lopdf read that
/// old copy over a new one in an object stream, and the page tree turned for the second
/// signer, then turned back, passed as allowed.
#[test]
fn a_later_signed_version_read_differently_is_refused() {
    let (end, _) = turned_for_the_second_signer(|b, turned, offset| {
        let r2 = hybrid_revision(b, turned, &[('n', offset)], &[]);
        assert!(Pdf::from_bytes(&r2.0, None).unwrap().differs().is_some());
        r2
    });
    let got = changes(&end);
    let want = "other PDF apps may read a later signed version differently from LimarePDF (";
    assert!(
        got.iter().any(|c| matches!(c,
            (ChangeKind::Malformed(why), Some(Refusal::Never)) if why.starts_with(want))),
        "{got:#?}"
    );
    // A signature after it, over a version read alike everywhere, is unaffected.
    let s3 = countersign(&end, "Signature3", true);
    assert_eq!(sig(&s3, "Signature3").status, SigStatus::Valid);
    assert!(sig(&s3, "Signature3").changes.is_empty());
}

/// A later signature that can't be checked for another reason refuses nothing earlier: the
/// version it signed reads alike everywhere, and is compared with the rest.
#[test]
fn a_later_signature_broken_otherwise_refuses_nothing() {
    let mut b = countersign(&approve(&base_pdf()), "Signature2", false);
    // Signature2's range ending inside its revision's end-of-file marker.
    let key = b"/ByteRange";
    let at = b.windows(key.len()).rposition(|w| w == key).unwrap();
    let at = at + b[at..].iter().position(|&c| c == b'[').unwrap() + 1;
    let close = at + b[at..].iter().position(|&c| c == b']').unwrap();
    let text = String::from_utf8(b[at..close].to_vec()).unwrap();
    let d: usize = text.split_whitespace().last().unwrap().parse().unwrap();
    let i = text.rfind(&d.to_string()).unwrap();
    let shorter = format!("{}{:<w$}", &text[..i], d - 3, w = text.len() - i);
    b[at..close].copy_from_slice(shorter.as_bytes());
    assert_eq!(
        sig(&b, "Signature2").status,
        SigStatus::Broken(
            "the signed part doesn't end where a version of the document ends".into()
        )
    );
    assert_eq!(
        changes(&b),
        [(ChangeKind::Signed("Signature2".into()), None)]
    );
}

/// A number LimarePDF reads as freed after signing but lopdf as in use is refused, as one
/// lopdf reads in use is never compared: a hybrid revision's cross-reference stream frees
/// it in rows too narrow for lopdf, which keeps the entry before, written plainly or in an
/// object stream.
#[test]
fn a_number_lopdf_reads_in_use_but_freed_is_refused() {
    use lopdf::xref::XrefEntry::{Compressed, Normal};
    let (b, offset, old) = object_one_signed();
    let stm = Document::load_mem(&b).unwrap().max_id + 1;
    let (in_stream, _) = hybrid_revision(&b, &old, &[], &[]);
    let read = [
        Normal {
            offset,
            generation: 0,
        },
        Compressed {
            container: stm,
            index: 0,
        },
    ];
    for (r2, read) in [b, in_stream].into_iter().zip(read) {
        let r3 = narrow_free(&r2, 1);
        let lopdf = Document::load_mem(&r3).unwrap();
        assert_eq!(
            format!("{:?}", lopdf.reference_table.get(1)),
            format!("{:?}", Some(read))
        );
        let want = ChangeKind::Malformed("LimarePDF can't read object 1 reliably".into());
        assert_eq!(changes(&r3), [(want, Some(Refusal::Never))]);
    }
}

/// A hybrid revision written by hand whose cross-reference stream frees object `k` in rows
/// two bytes wide (`/W [1 1 0]`), and whose table lists only that stream.
fn narrow_free(b: &[u8], k: u32) -> Vec<u8> {
    let d = Document::load_mem(b).unwrap();
    let r = root(&d);
    let prev = last_startxref(b);
    let x = d.max_id + 1;
    let mut out = [b, b"\n"].concat();
    let at_x = out.len();
    out.extend_from_slice(
        format!(
            "{x} 0 obj\n<< /Type /XRef /W [1 1 0] /Index [{k} 1] /Size {} /Length 2 >>\n\
             stream\n",
            x + 1
        )
        .as_bytes(),
    );
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let at_t = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{x} 1\n{at_x:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} {} R /Prev {prev} \
             /XRefStm {at_x} >>\nstartxref\n{at_t}\n%%EOF\n",
            x + 1,
            r.0,
            r.1
        )
        .as_bytes(),
    );
    out
}

#[test]
fn filling_in_a_form_is_allowed() {
    let b = fill(&approve(&form(&["Name", "Date"])), "Name", "Jane");
    let s = sig(&b, "Signature1");
    assert_eq!(
        summary(&s.changes),
        [(ChangeKind::FieldFilled("Name".into()), None)]
    );
    assert_eq!(s.changes[0].page, Some(0));
    assert_eq!(s.status, SigStatus::Valid);
    assert!(report(&b).all_ok());
}

#[test]
fn another_signature_is_allowed() {
    let b = countersign(&approve(&base_pdf()), "Signature2", false);
    assert_eq!(
        changes(&b),
        [(ChangeKind::Signed("Signature2".into()), None)]
    );
    assert!(sig(&b, "Signature2").changes.is_empty());
    assert!(report(&b).all_ok());

    // Signing an empty signature field added by the first signer.
    let with_field = edit(&approve(&base_pdf()), |prev, new| {
        let id = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig",
            "T" => Object::string_literal("Approver"), "P" => page(prev),
            "Rect" => vec![0.into(), 100.into(), 50.into(), 120.into()],
        });
        add_annot(prev, new, id);
        let r = root(prev);
        let mut c = dict(prev, r);
        let mut form = c.get(b"AcroForm").unwrap().as_dict().unwrap().clone();
        let mut fields = form.get(b"Fields").unwrap().as_array().unwrap().clone();
        fields.push(id.into());
        form.set("Fields", fields);
        c.set("AcroForm", form);
        new.set_object(r, Object::Dictionary(c));
    });
    assert_eq!(
        changes(&with_field),
        [(ChangeKind::SignatureFieldAdded("Approver".into()), None)]
    );
    let f = Field {
        name: "Approver",
        existing: true,
        ..Field::default()
    };
    let b = sign(&with_field, &id("p256"), &f, &Cms::default());
    assert_eq!(changes(&b), [(ChangeKind::Signed("Approver".into()), None)]);
    assert!(report(&b).all_ok());
}

#[test]
fn comments_are_allowed_unless_certified_without_them() {
    let added = comment(&approve(&base_pdf()), Dictionary::new());
    assert_eq!(changes(&added), [(ChangeKind::CommentAdded, None)]);
    // Removing a comment made before signing, and editing one, are comment changes too.
    let removed = edit(
        &approve(&comment(&base_pdf(), Dictionary::new())),
        |prev, new| {
            let p = page(prev);
            let mut d = dict(prev, p);
            let mut annots = d.get(b"Annots").unwrap().as_array().unwrap().clone();
            // The comment, then the signature's widget.
            let widget = annots.pop().unwrap();
            annots[0] = widget;
            d.set("Annots", annots);
            new.set_object(p, Object::Dictionary(d));
        },
    );
    assert_eq!(changes(&removed), [(ChangeKind::CommentRemoved, None)]);
    // Taking the signature's own widget off the page hides the signature.
    let hidden = edit(&approve(&base_pdf()), |prev, new| {
        let p = page(prev);
        let mut d = dict(prev, p);
        d.set("Annots", Vec::<Object>::new());
        new.set_object(p, Object::Dictionary(d));
    });
    assert_refused(&hidden, &ChangeKind::SignatureChanged("Signature1".into()));
    let edited = edit(
        &approve(&comment(&base_pdf(), Dictionary::new())),
        |prev, new| {
            let id = *prev
                .objects
                .iter()
                .find(|(_, o)| {
                    o.as_dict()
                        .is_ok_and(|d| d.has(b"Contents") && d.has(b"Rect"))
                })
                .unwrap()
                .0;
            let mut d = dict(prev, id);
            d.set("Contents", Object::string_literal("Changed"));
            new.set_object(id, Object::Dictionary(d));
        },
    );
    assert_eq!(changes(&edited), [(ChangeKind::CommentChanged, None)]);

    let p2 = comment(&certify(&base_pdf(), 2), Dictionary::new());
    assert_eq!(
        changes(&p2),
        [(
            ChangeKind::CommentAdded,
            Some(Refusal::Certification(Permissions::FormFilling))
        )]
    );
    let p3 = comment(&certify(&base_pdf(), 3), Dictionary::new());
    assert_eq!(changes(&p3), [(ChangeKind::CommentAdded, None)]);
}

#[test]
fn certification_limits() {
    // No changes: validation data and an invisible document timestamp only.
    let p1 = certify(&form(&["Name"]), 1);
    let dss = edit(&p1, |prev, new| {
        let cert = new.add_object(Stream::new(Dictionary::new(), cert_der("ca")));
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set("DSS", dictionary! { "Certs" => vec![Object::from(cert)] });
        new.set_object(r, Object::Dictionary(c));
    });
    let stamped = timestamp(&dss, true);
    assert_eq!(
        changes(&stamped),
        [
            (ChangeKind::DocumentTimestamp("Timestamp1".into()), None),
            (ChangeKind::ValidationData, None),
        ]
    );
    assert!(report(&stamped).all_ok());
    let visible = timestamp(&p1, false);
    assert!(changes(&visible)[0].1.is_some());
    let filled = fill(&p1, "Name", "Jane");
    assert_eq!(
        changes(&filled),
        [(
            ChangeKind::FieldFilled("Name".into()),
            Some(Refusal::Certification(Permissions::NoChanges))
        )]
    );

    // Form filling and signing: a new signature field must be invisible.
    let p2 = certify(&form(&["Name"]), 2);
    assert!(report(&fill(&p2, "Name", "Jane")).all_ok());
    assert!(report(&countersign(&p2, "Signature2", true)).all_ok());
    assert_eq!(
        changes(&countersign(&p2, "Signature2", false)),
        [(
            ChangeKind::Signed("Signature2".into()),
            Some(Refusal::Certification(Permissions::FormFilling))
        )]
    );
}

#[test]
fn field_locks() {
    let b = locked_by(&form(&["Name", "Date"]), lock("Include", &["Name"], None));
    assert_eq!(
        changes(&fill(&b, "Name", "Jane")),
        [(
            ChangeKind::FieldFilled("Name".into()),
            Some(Refusal::Locked)
        )]
    );
    assert_eq!(
        changes(&fill(&b, "Date", "Today")),
        [(ChangeKind::FieldFilled("Date".into()), None)]
    );
    let all_but = locked_by(&form(&["Name", "Date"]), lock("Exclude", &["Date"], None));
    assert!(!report(&fill(&all_but, "Name", "Jane")).all_ok());
    assert!(report(&fill(&all_but, "Date", "Today")).all_ok());
    // "Lock document": nothing may change.
    let doc = locked_by(&base_pdf(), lock("All", &[], Some(1)));
    assert_eq!(
        changes(&comment(&doc, Dictionary::new())),
        [(ChangeKind::CommentAdded, Some(Refusal::Locked))]
    );
}

#[test]
fn document_information_may_change() {
    let b = approve(&base_pdf());
    let num = Document::load_mem(&b).unwrap().max_id + 1;
    let b = append_raw(
        &b,
        &[(num, b"<< /Title (New title) >>")],
        &[],
        &[],
        &format!("/Info {num} 0 R"),
    );
    assert_eq!(changes(&b), [(ChangeKind::Metadata, None)]);
}

#[test]
fn rewriting_strings_differently_is_no_change() {
    let b = approve(&base_pdf());
    let d = Document::load_mem(&b).unwrap();
    let field = titled(&d, "Signature1");
    let value = sig_id(&b, "Signature1");
    let p = page(&d);
    // The same field with its name as a hex string.
    let body = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T <5369676E617475726531> /V {} 0 R \
         /F 132 /Rect [20 20 120 60] /P {} 0 R >>",
        value.0, p.0
    );
    let b = append_raw(&b, &[(field.0, body.as_bytes())], &[], &[], "");
    let s = sig(&b, "Signature1");
    assert!(!s.covers_whole_file);
    assert!(s.changes.is_empty(), "{:#?}", s.changes);
}

// ---------------------------------------------------------------- disallowed changes

#[test]
fn page_content_changes_are_refused() {
    let b = approve(&base_pdf());
    let c = contents(&b);
    let in_place = edit(&b, |_, new| {
        new.set_object(
            c,
            Stream::new(Dictionary::new(), b"0 0 m 100 100 l S".to_vec()),
        );
    });
    assert_refused(&in_place, &ChangeKind::PageContent);
    let replaced = edit(&b, |prev, new| {
        let s = new.add_object(Stream::new(Dictionary::new(), b"0 0 m 1 1 l S".to_vec()));
        let p = page(prev);
        let mut d = dict(prev, p);
        d.set("Contents", s);
        new.set_object(p, Object::Dictionary(d));
    });
    assert_refused(&replaced, &ChangeKind::PageContent);
    let rotated = edit(&b, |prev, new| {
        let p = page(prev);
        let mut d = dict(prev, p);
        d.set("Rotate", 90);
        new.set_object(p, Object::Dictionary(d));
    });
    assert_refused(&rotated, &ChangeKind::PageContent);
}

#[test]
fn adding_a_page_is_refused() {
    let b = edit(&approve(&base_pdf()), |prev, new| {
        let pages = dict(prev, root(prev))
            .get(b"Pages")
            .unwrap()
            .as_reference()
            .unwrap();
        let mut d = dict(prev, pages);
        let extra = new.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages,
            "MediaBox" => vec![0.into(), 0.into(), 300.into(), 200.into()],
        });
        let mut kids = d.get(b"Kids").unwrap().as_array().unwrap().clone();
        kids.push(extra.into());
        d.set("Kids", kids);
        d.set("Count", 2);
        new.set_object(pages, Object::Dictionary(d));
    });
    assert_refused(&b, &ChangeKind::PagesChanged);
}

#[test]
fn changing_a_signature_is_refused() {
    let b = approve(&base_pdf());
    let id = sig_id(&b, "Signature1");
    let reason = edit(&b, |prev, new| {
        let mut d = dict(prev, id);
        d.set("Reason", Object::string_literal("Forged"));
        new.set_object(id, Object::Dictionary(d));
    });
    assert_refused(&reason, &ChangeKind::SignatureChanged("Signature1".into()));
    let look = edit(&b, |prev, new| {
        let f = titled(prev, "Signature1");
        let ap = appearance(new, "BT (Someone else) Tj ET");
        let mut d = dict(prev, f);
        d.set("AP", dictionary! { "N" => ap });
        new.set_object(f, Object::Dictionary(d));
    });
    assert_refused(&look, &ChangeKind::SignatureChanged("Signature1".into()));
}

#[test]
fn new_fields_and_field_changes_are_refused() {
    let b = approve(&form(&["Name"]));
    let added = edit(&b, |prev, new| {
        let id = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx",
            "T" => Object::string_literal("Extra"), "P" => page(prev),
            "Rect" => vec![0.into(), 0.into(), 50.into(), 20.into()],
        });
        add_annot(prev, new, id);
        let r = root(prev);
        let mut c = dict(prev, r);
        let mut form = c.get(b"AcroForm").unwrap().as_dict().unwrap().clone();
        let mut fields = form.get(b"Fields").unwrap().as_array().unwrap().clone();
        fields.push(id.into());
        form.set("Fields", fields);
        c.set("AcroForm", form);
        new.set_object(r, Object::Dictionary(c));
    });
    assert_refused(&added, &ChangeKind::FieldAdded("Extra".into()));
    // Moving a field, or hiding it, isn't filling it in.
    let moved = edit(&b, |prev, new| {
        let f = titled(prev, "Name");
        let mut d = dict(prev, f);
        d.set("F", 6);
        new.set_object(f, Object::Dictionary(d));
    });
    assert_refused(&moved, &ChangeKind::FieldChanged("Name".into()));
}

/// The base document with fields `A`, with no kids, and `B`, with text field `G` and an
/// untitled field with no kids as its kids; `indirect`, the titles of `B` and `G` each in an
/// object of its own.
fn parent_form(indirect: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let title = |new: &mut Document, t: &str| match indirect {
            true => new.add_object(Object::string_literal(t)).into(),
            false => Object::string_literal(t),
        };
        let a = new.add_object(dictionary! {
            "T" => Object::string_literal("A"), "Kids" => Vec::<Object>::new(),
        });
        let b = new.new_object_id();
        let ap = appearance(new, "");
        let t = title(new, "G");
        let g = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx",
            "T" => t, "F" => 4, "P" => page(prev), "Parent" => b,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 120.into()],
            "AP" => dictionary! { "N" => ap },
        });
        add_annot(prev, new, g);
        let u = new.add_object(dictionary! { "Kids" => Vec::<Object>::new(), "Parent" => b });
        let kids = vec![Object::from(g), Object::from(u)];
        let field = dictionary! { "T" => title(new, "B"), "Kids" => kids };
        new.set_object(b, Object::Dictionary(field));
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set(
            "AcroForm",
            dictionary! {
                "Fields" => vec![Object::from(a), Object::from(b)],
                "DA" => Object::string_literal("/Helv 0 Tf 0 g"),
            },
        );
        new.set_object(r, Object::Dictionary(c));
    })
}

/// Field `id` as `new` has it so far, or else as `prev` has it, changed by `change`.
fn change(prev: &Document, new: &mut Document, id: ObjectId, change: impl FnOnce(&mut Dictionary)) {
    let mut d = (new.get_dictionary(id).cloned()).unwrap_or_else(|_| dict(prev, id));
    change(&mut d);
    new.set_object(id, Object::Dictionary(d));
}

/// Field `id` renamed `to`, in its title's object if the title has one of its own.
fn rename(prev: &Document, new: &mut Document, id: ObjectId, to: &str) {
    let to = Object::string_literal(to);
    match dict(prev, id).get(b"T").unwrap().as_reference() {
        Ok(t) => new.set_object(t, to),
        Err(_) => change(prev, new, id, |d| d.set("T", to)),
    }
}

/// `B.G` of [`parent_form`], locked by the signature, moved or renamed by edits to other fields
/// or to titles in objects of their own alone: listed among `A`'s kids too (its own parent still
/// `B`), named after the first list it's on it would be `A.G`; moved under `B`'s untitled kid,
/// still named `B.G`; `B` renamed `C`; or `G` renamed `H`. Each is refused as a change to
/// `B.G`, and filling it in is judged by the name it was signed with. Listed under `A`, filling
/// it in was allowed, as filling in a field the lock doesn't name; moved under the untitled kid,
/// so was moving it; with titles in objects of their own, so was renaming.
#[test]
fn a_field_renamed_by_changes_to_other_fields_is_refused() {
    let moved = (ChangeKind::FieldChanged("B.G".into()), Some(Refusal::Never));
    // `B`'s title in an object of its own changed is part of `B` changed: filling it in, which
    // the lock allows, beside `B` renamed, which nothing does.
    let title = (ChangeKind::FieldFilled("B".into()), None);
    let cases = [
        "listed under A",
        "moved under the untitled kid",
        "B renamed C",
        "G renamed H",
    ];
    let mut wrong = Vec::new();
    for (indirect, titles) in [(false, "titles in fields"), (true, "titles apart")] {
        let signed = locked_by(&parent_form(indirect), lock("Include", &["B.G"], None));
        for (case, filled) in cases.iter().flat_map(|c| [(c, false), (c, true)]) {
            let e = edit(&signed, |prev, new| {
                let (a, b, g) = (titled(prev, "A"), titled(prev, "B"), titled(prev, "G"));
                match *case {
                    "listed under A" => change(prev, new, a, |d| d.set("Kids", vec![g.into()])),
                    "moved under the untitled kid" => {
                        let kids = dict(prev, b).get(b"Kids").unwrap().clone();
                        let u = kids.as_array().unwrap()[1].as_reference().unwrap();
                        change(prev, new, u, |d| d.set("Kids", vec![g.into()]));
                        change(prev, new, b, |d| d.set("Kids", vec![u.into()]));
                    }
                    "B renamed C" => rename(prev, new, b, "C"),
                    _ => rename(prev, new, g, "H"),
                }
                if filled {
                    let ap = appearance(new, "BT (Jane) Tj ET");
                    change(prev, new, g, |d| {
                        d.set("V", Object::string_literal("Jane"));
                        d.set("AP", dictionary! { "N" => ap });
                    });
                }
            });
            let got = changes(&e);
            let allowed = got.iter().any(|c| c.1.is_none() && *c != title);
            if !got.contains(&moved) || allowed || report(&e).all_ok() {
                wrong.push(format!("{titles}, {case}, filled {filled}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A field listed again by another field than the one it's named by, or no longer: `B.G` of
/// [`parent_form`] under `A` listed after `B`, or under `B`'s untitled kid; text field `Name`
/// under signature field `Approver` listed after it, its kids in an array of their own; or
/// `Name` under a signature field added after signing. Each is refused as a change to that
/// field, after a lock naming it, an approval or a certification allowing no changes. So is a
/// new signature field's widget listed under `Name` too, as a change to `Name`, or in
/// `/Fields` too, as a field added. Listed twice by the same field or by `/Fields`, a field is
/// the same either way, so `A` and a new signature field listed twice are allowed. Only the
/// listing a field is named by was compared, so those refused were allowed before.
#[test]
fn a_field_listed_again_is_refused() {
    let id = |b: &[u8], name| titled(&Document::load_mem(b).unwrap(), name);
    // Field `name`'s kids in `b`.
    let kids = |b: &[u8], name| {
        let d = Document::load_mem(b).unwrap();
        dict(&d, titled(&d, name)).get(b"Kids").unwrap().clone()
    };
    // Field `owner`'s kids, or the kids array `owner`, made `kid`, or none.
    let list = |b: &[u8], owner: ObjectId, kid: Option<ObjectId>| {
        let kids: Vec<Object> = kid.into_iter().map(Object::from).collect();
        edit(b, |prev, new| match prev.get_object(owner).unwrap() {
            Object::Array(_) => new.set_object(owner, kids),
            _ => change(prev, new, owner, |d| d.set("Kids", kids)),
        })
    };
    let moved = |field: &str| ChangeKind::FieldChanged(field.into());
    let mut wrong = Vec::new();
    // `e` refused for `kind`, or allowed if none.
    let mut check = |what: &str, e: &[u8], kind: Option<ChangeKind>| {
        let (got, ok) = (changes(e), report(e).all_ok());
        let found = kind.map_or(ok, |k| !ok && got.contains(&(k, Some(Refusal::Never))));
        if !found {
            wrong.push(format!("{what}: {got:?}"));
        }
    };
    let fields = edit(&parent_form(false), |p, n| relist(p, n, |f| f.reverse()));
    let (a, g) = (id(&fields, "A"), id(&fields, "G"));
    let under_b = kids(&fields, "B");
    let u = under_b.as_array().unwrap()[1].as_reference().unwrap();
    let twice = list(&fields, a, Some(g));
    let approver = edit(&form(&["Name"]), |prev, new| {
        let kids = new.add_object(Vec::<Object>::new());
        let f = new.add_object(dictionary! {
            "FT" => "Sig", "T" => Object::string_literal("Approver"), "Kids" => kids,
        });
        list_field(prev, new, f);
    });
    let array = kids(&approver, "Approver").as_reference().unwrap();
    let name = id(&approver, "Name");
    let naming = lock("Include", &["B.G", "Name"], None);
    let sign = |b: &[u8], signer| match signer {
        "P1" => certify(b, 1),
        "an approval" => approve(b),
        _ => locked_by(b, naming.clone()),
    };
    // Each named after its field first.
    let cases = [
        ("B.G under A too", &fields, a, Some(g)),
        ("B.G under the untitled kid too", &fields, u, Some(g)),
        ("B.G no longer under A too", &twice, a, None),
        ("Name under Approver too", &approver, array, Some(name)),
    ];
    for signer in ["a lock naming it", "an approval", "P1"] {
        for (case, unsigned, owner, kid) in cases {
            let e = list(&sign(unsigned, signer), owner, kid);
            let field = case.split(' ').next();
            check(&format!("{case} after {signer}"), &e, field.map(moved));
        }
        let signed = sign(&fields, signer);
        let e = edit(&signed, |p, n| relist(p, n, |l| l.push(a.into())));
        check(&format!("A listed twice after {signer}"), &e, None);
    }
    // Signature field `Extra` added with a widget: the field and the widget.
    let add_extra = |prev: &Document, new: &mut Document| {
        let (f, w) = (new.new_object_id(), new.new_object_id());
        let widget = dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "P" => page(prev), "Parent" => f,
            "Rect" => vec![0.into(), 0.into(), 0.into(), 0.into()],
        };
        new.set_object(w, widget);
        add_annot(prev, new, w);
        let kids = vec![Object::from(w)];
        let field = dictionary! {
            "FT" => "Sig", "T" => Object::string_literal("Extra"), "Kids" => kids,
        };
        new.set_object(f, field);
        (f, w)
    };
    // After an approval, which allows adding it.
    let approved = approve(&form(&["Name"]));
    let e = edit(&approved, |prev, new| {
        let kids = vec![Object::from(titled(prev, "Name"))];
        let f = new.add_object(dictionary! {
            "FT" => "Sig", "T" => Object::string_literal("Extra"), "Kids" => kids,
        });
        list_field(prev, new, f);
    });
    check("Name under new Extra too", &e, Some(moved("Name")));
    let e = edit(&approved, |prev, new| {
        let (f, w) = add_extra(prev, new);
        let (to, kids) = (titled(prev, "Name"), vec![Object::from(w)]);
        change(prev, new, to, |d| d.set("Kids", kids));
        list_first(prev, new, f);
    });
    check("Extra's widget under Name too", &e, Some(moved("Name")));
    let e = edit(&approved, |prev, new| {
        let (f, w) = add_extra(prev, new);
        relist(prev, new, |l| l.extend([Object::from(f), Object::from(w)]));
    });
    let added = ChangeKind::FieldAdded("Extra".into());
    check("Extra's widget in /Fields too", &e, Some(added));
    let e = edit(&approved, |prev, new| {
        let (f, _) = add_extra(prev, new);
        relist(prev, new, |l| l.extend([Object::from(f), Object::from(f)]));
    });
    check("Extra listed twice", &e, None);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with widget `G` on the page and its `/Parent` text field `B`, valued
/// `old`: `B` listed nowhere, with `G` its kid, and `G` alone in `/Fields` (`G listed`) or
/// `/Fields` empty (`G unlisted`); both in `/Fields`, `B` with no kids (`B listed apart`); or
/// `B` alone in `/Fields`, with `G` its kid (`B listed`).
fn parent_apart(shape: &str) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let b = new.new_object_id();
        let ap = appearance(new, "");
        let g = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "T" => Object::string_literal("G"),
            "F" => 4, "P" => page(prev), "Parent" => b,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 120.into()],
            "AP" => dictionary! { "N" => ap },
        });
        add_annot(prev, new, g);
        let apart = shape == "B listed apart";
        let kids: Vec<Object> = if apart { vec![] } else { vec![g.into()] };
        new.set_object(
            b,
            dictionary! {
                "T" => Object::string_literal("B"), "FT" => "Tx",
                "V" => Object::string_literal("old"), "Kids" => kids,
            },
        );
        let fields: Vec<Object> = match shape {
            "G listed" => vec![g.into()],
            "G unlisted" => vec![],
            "B listed" => vec![b.into()],
            _ => vec![g.into(), b.into()],
        };
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set(
            "AcroForm",
            dictionary! { "Fields" => fields, "DA" => Object::string_literal("/Helv 0 Tf 0 g") },
        );
        new.set_object(r, Object::Dictionary(c));
    })
}

/// A widget's `/Parent` other than the field listing it, which readers following `/Parent`
/// take its name, type, value and actions from: `B` of [`parent_apart`], listed nowhere,
/// renamed and refilled, refilled, made a list, or given a script. Each is refused after a
/// certification, an approval or a lock naming the widget either way, as a change to field
/// `G`, or to an annotation with `G` not in `/Fields`; so is filling `G` in, named `B.G` by
/// such readers, with `B` listed nowhere or listed apart. Only filling `G` in after a lock
/// naming `G` or a certification allowing no changes was refused before. With `B` listed and
/// `G` its kid, filling `G` in is still allowed after a certification allowing it or an
/// approval.
#[test]
fn a_field_s_parent_other_than_its_listing_is_refused() {
    // An edit to `B`'s dictionary.
    type FieldEdit = fn(&mut Dictionary);
    let edits: [(&str, FieldEdit); 4] = [
        ("B renamed C and refilled", |d| {
            d.set("T", Object::string_literal("C"));
            d.set("V", Object::string_literal("new"));
        }),
        ("B refilled", |d| d.set("V", Object::string_literal("new"))),
        ("B made a list", |d| d.set("FT", "Ch")),
        ("B given a script", |d| {
            let js = Object::string_literal("app.alert(1)");
            let action = dictionary! { "S" => "JavaScript", "JS" => js };
            d.set("AA", dictionary! { "F" => action });
        }),
    ];
    let signers = [
        "P1",
        "P2",
        "an approval",
        "a lock naming B.G",
        "a lock naming G",
    ];
    let sign = |b: &[u8], signer: &str| match signer {
        "P1" => certify(b, 1),
        "P2" => certify(b, 2),
        "an approval" => approve(b),
        "a lock naming B.G" => locked_by(b, lock("Include", &["B.G"], None)),
        _ => locked_by(b, lock("Include", &["G"], None)),
    };
    let mut wrong = Vec::new();
    for shape in ["G listed", "G unlisted", "B listed apart", "B listed"] {
        let want = match shape {
            "G unlisted" => (ChangeKind::AnnotationChanged, Some(Refusal::Never)),
            _ => (ChangeKind::FieldChanged("G".into()), Some(Refusal::Never)),
        };
        for signer in signers {
            let signed = sign(&parent_apart(shape), signer);
            // `B` listed is a field of its own, its changes judged as such.
            let edits = if shape.starts_with("B listed") {
                &[][..]
            } else {
                &edits[..]
            };
            for (what, edit_b) in edits {
                let e = edit(&signed, |prev, new| {
                    let parent = dict(prev, titled(prev, "G")).get(b"Parent").cloned();
                    change(prev, new, parent.unwrap().as_reference().unwrap(), edit_b);
                });
                let got = changes(&e);
                let allowed = got.iter().any(|c| c.1.is_none());
                if !got.contains(&want) || allowed || report(&e).all_ok() {
                    wrong.push(format!("{shape}, {what} after {signer}: {got:?}"));
                }
            }
            if shape != "G unlisted" {
                let e = edit(&signed, |prev, new| {
                    let ap = appearance(new, "BT (Jane) Tj ET");
                    change(prev, new, titled(prev, "G"), |d| {
                        d.set("V", Object::string_literal("Jane"));
                        d.set("AP", dictionary! { "N" => ap });
                    });
                });
                let got = changes(&e);
                let mistaken = match shape {
                    "B listed" if ["P2", "an approval"].contains(&signer) => !report(&e).all_ok(),
                    "B listed" => false,
                    _ => !got.contains(&want) || report(&e).all_ok(),
                };
                if mistaken {
                    wrong.push(format!("{shape}, G filled after {signer}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn actions_and_scripts_are_refused() {
    let b = approve(&base_pdf());
    let js = dictionary! { "S" => "JavaScript", "JS" => Object::string_literal("app.alert(1)") };
    let open = edit(&b, |prev, new| {
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set("OpenAction", js.clone());
        new.set_object(r, Object::Dictionary(c));
    });
    assert_refused(&open, &ChangeKind::Actions);
    // A comment that runs a script when the page opens isn't just a comment.
    let note = comment(&b, dictionary! { "AA" => dictionary! { "PO" => js } });
    assert_refused(&note, &ChangeKind::Actions);
    // A link isn't a comment.
    let link = edit(&b, |prev, new| {
        let id = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Link",
            "Rect" => vec![0.into(), 0.into(), 300.into(), 200.into()],
            "A" => dictionary! { "S" => "URI", "URI" => Object::string_literal("https://example.com") },
        });
        add_annot(prev, new, id);
    });
    assert_refused(&link, &ChangeKind::AnnotationChanged);
}

/// What a signature made in each way allows: an ordinary one, and certifications allowing
/// form filling and signing (P2), and comments too (P3).
fn signed_three_ways() -> [(Vec<u8>, &'static str); 3] {
    [
        (approve(&base_pdf()), "an ordinary signature"),
        (certify(&base_pdf(), 2), "P2"),
        (certify(&base_pdf(), 3), "P3"),
    ]
}

#[test]
fn a_new_signature_field_s_actions_are_refused() {
    // The ways a new signature field can carry an action (A-03).
    let actions: [(&str, bool, Entries); 7] = [
        ("/AA", false, |_| on_open()),
        ("/A", false, |_| dictionary! { "A" => next_page() }),
        ("/AA an object of its own", false, |new| {
            dictionary! { "AA" => new.add_object(dictionary! { "PO" => next_page() }) }
        }),
        ("an action in /AA an object of its own", false, |new| {
            dictionary! { "AA" => dictionary! { "PO" => new.add_object(next_page()) } }
        }),
        ("/A with /Next to a script", false, |new| {
            let js = new.add_object(dictionary! {
                "S" => "JavaScript", "JS" => Object::string_literal("app.alert(1)"),
            });
            let mut a = next_page();
            a.set("Next", js);
            dictionary! { "A" => a }
        }),
        ("/AA on a kid", true, |_| on_open()),
        ("/A on a kid", true, |_| dictionary! { "A" => next_page() }),
    ];
    let added = (ChangeKind::SignatureFieldAdded("Extra".into()), None);
    let mut wrong = Vec::new();
    for (signed, after) in signed_three_ways() {
        // Without an action, allowed as before; a null one is none.
        let none: [(&str, Entries); 2] = [
            ("no action", |_| Dictionary::new()),
            ("/AA null", |_| dictionary! { "AA" => Object::Null }),
        ];
        for ((what, make), kid) in none.into_iter().flat_map(|n| [(n, false), (n, true)]) {
            let b = extra_field(&signed, kid, make);
            let got = changes(&b);
            if got != [added.clone()] || !report(&b).all_ok() {
                wrong.push(format!("{what} (kid {kid}) after {after}: {got:?}"));
            }
        }
        for (what, kid, make) in actions {
            let b = extra_field(&signed, kid, make);
            let got = changes(&b);
            let want = [(ChangeKind::Actions, Some(Refusal::Never)), added.clone()];
            if got != want || report(&b).all_ok() {
                wrong.push(format!("{what} after {after}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A signature field added after signing with a text field of its own among its kids: the
/// text field is a field added, which nothing allows, listed beside the signature field. It was
/// reported as nothing before, the signature field's adding allowed after an approval or a
/// certification allowing signing.
#[test]
fn a_field_inside_a_new_signature_field_is_refused() {
    let held = ChangeKind::FieldAdded("Extra.Text".into());
    let held = (held, Some(Refusal::Never));
    let signed = [
        (approve(&base_pdf()), "an approval"),
        (certify(&base_pdf(), 2), "P2"),
        (certify(&base_pdf(), 1), "P1"),
    ];
    let mut wrong = Vec::new();
    for (signed, after) in signed {
        let b = edit(&signed, |prev, new| {
            let top = new.new_object_id();
            let w = new.add_object(dictionary! {
                "Type" => "Annot", "Subtype" => "Widget", "P" => page(prev), "Parent" => top,
                "Rect" => vec![Object::from(0); 4],
            });
            let t = new.add_object(dictionary! {
                "Type" => "Annot", "Subtype" => "Widget", "P" => page(prev), "Parent" => top,
                "Rect" => vec![Object::from(0); 4],
                "FT" => "Tx", "T" => Object::string_literal("Text"),
            });
            add_annot(prev, new, w);
            add_annot(prev, new, t);
            let kids = vec![Object::from(w), t.into()];
            let field = dictionary! {
                "FT" => "Sig", "T" => Object::string_literal("Extra"), "Kids" => kids,
            };
            new.set_object(top, Object::Dictionary(field));
            list_field(prev, new, top);
        });
        let got = changes(&b);
        if !got.contains(&held) || report(&b).all_ok() {
            wrong.push(format!("after {after}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_signature_field_signed_as_it_is_added_with_an_action_is_refused() {
    let mut wrong = Vec::new();
    for (signed, after) in signed_three_ways() {
        for action in [false, true] {
            let f = Field {
                name: "Signature2",
                invisible: true,
                widget: if action { on_open() } else { Dictionary::new() },
                ..Field::default()
            };
            let b = sign(&signed, &id("p256"), &f, &Cms::default());
            let got = changes(&b);
            let mut want = vec![(ChangeKind::Signed("Signature2".into()), None)];
            if action {
                want.insert(0, (ChangeKind::Actions, Some(Refusal::Never)));
            }
            if got != want || report(&b).all_ok() == action {
                wrong.push(format!("action {action} after {after}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn signing_an_existing_field_while_adding_an_action_is_refused() {
    let f = Field {
        name: "Extra",
        existing: true,
        widget: on_open(),
        ..Field::default()
    };
    // In the version the first signature signed: a changed field.
    let before = approve(&extra_field(&base_pdf(), false, |_| Dictionary::new()));
    let b = sign(&before, &id("p256"), &f, &Cms::default());
    let got = changes(&b);
    assert!(got.iter().any(|(_, r)| r.is_some()), "{got:#?}");
    assert!(!report(&b).all_ok());
    // Added after it: a new field to the first signature, its action that field's.
    let after = extra_field(&approve(&base_pdf()), false, |_| Dictionary::new());
    let b = sign(&after, &id("p256"), &f, &Cms::default());
    let want = vec![
        (ChangeKind::Actions, Some(Refusal::Never)),
        (ChangeKind::Signed("Extra".into()), None),
    ];
    assert_eq!(changes(&b), want);
    assert!(!report(&b).all_ok());
}

/// `b` with an empty signature field `Deep` on the page, `depth` untitled fields below the
/// top of the form.
fn deep_signature_field(b: &[u8], depth: usize) -> Vec<u8> {
    edit(b, |prev, new| {
        let p = page(prev);
        let w = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig",
            "T" => Object::string_literal("Deep"), "F" => 4, "P" => p,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
        });
        add_annot(prev, new, w);
        let mut top = w;
        for _ in 0..depth {
            top = new.add_object(dictionary! { "Kids" => vec![Object::from(top)] });
        }
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set(
            "AcroForm",
            dictionary! { "Fields" => vec![Object::from(top)] },
        );
        new.set_object(r, Object::Dictionary(c));
    })
}

/// Gives field (or widget) `id` a made-up signature (a document timestamp if `stamp`), not a
/// real one, and a drawing.
fn fake_sign(prev: &Document, new: &mut Document, id: ObjectId, stamp: bool) {
    let v = new.add_object(dictionary! {
        "Type" => if stamp { "DocTimeStamp" } else { "Sig" },
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => if stamp { "ETSI.RFC3161" } else { "adbe.pkcs7.detached" },
        "ByteRange" => vec![0.into(), 10.into(), 20.into(), 10.into()],
        "Contents" => Object::String(vec![0; 4], lopdf::StringFormat::Hexadecimal),
    });
    let ap = appearance(new, "BT (PAID) Tj ET");
    let mut d = dict(prev, id);
    d.set("V", v);
    d.set("AP", dictionary! { "N" => ap });
    new.set_object(id, Object::Dictionary(d));
}

/// `b` with a made-up signature in field `Deep` (see [`fake_sign`]).
fn fake_signature(b: &[u8], stamp: bool) -> Vec<u8> {
    edit(b, |prev, new| {
        fake_sign(prev, new, titled(prev, "Deep"), stamp)
    })
}

/// The first kid field `id` lists.
fn first_kid(d: &Document, id: ObjectId) -> ObjectId {
    let field = dict(d, id);
    let kids = field.get(b"Kids").unwrap().as_array().unwrap();
    kids[0].as_reference().unwrap()
}

/// A field signed after a certification allowing no changes (with a timestamp) or after an
/// ordinary signature, made up both times: at the top of the form the report lists it (as
/// broken) and the signing is allowed; nested 33 deep, past what the report lists, nothing
/// would check it, so it's refused.
#[test]
fn a_signature_the_report_doesnt_list_is_refused() {
    let mut wrong = Vec::new();
    for depth in [0, 33] {
        let field = deep_signature_field(&base_pdf(), depth);
        for (stamp, signed) in [(true, certify(&field, 1)), (false, approve(&field))] {
            let b = fake_signature(&signed, stamp);
            let r = report(&b);
            let listed = (r.signatures.iter()).any(|s| s.fields.iter().any(|f| f == "Deep"));
            let kind = match stamp {
                true => ChangeKind::DocumentTimestamp("Deep".into()),
                false => ChangeKind::Signed("Deep".into()),
            };
            let got = changes(&b);
            let fine = match listed {
                true => depth == 0 && got == [(kind, None)],
                false => depth == 33 && !got.iter().any(|(k, r)| *k == kind || r.is_none()),
            };
            if !fine || got.is_empty() {
                wrong.push(format!("depth {depth}, timestamp {stamp}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// An empty signature field given, after a certification allowing no changes or after an
/// approval and a document timestamp, the timestamp's signature or the first one, and a
/// drawing: the report lists the earlier signature in it too, but nothing was signed in that
/// step, so it's refused. It was allowed as that field's signing or timestamp. A copy of the
/// timestamp's dictionary in an object of its own is a signature the report finds copied.
#[test]
fn an_earlier_signature_put_in_a_field_is_refused() {
    let field = extra_field(&base_pdf(), false, |_| Dictionary::new());
    let what = "a signature in field \"Extra\" it can't check";
    let refused = (ChangeKind::Unrecognised(what.into()), Some(Refusal::Never));
    let mut wrong = Vec::new();
    for (signed, after) in [(certify(&field, 1), "P1"), (approve(&field), "an approval")] {
        let stamped = timestamp(&signed, true);
        for from in ["Timestamp1", "Signature1"] {
            let b = edit(&stamped, |prev, new| {
                let v = dict(prev, titled(prev, from)).get(b"V").unwrap().clone();
                let extra = titled(prev, "Extra");
                let mut d = dict(prev, extra);
                let look = appearance(new, "BT (PAID) Tj ET");
                d.set("V", v);
                d.set("AP", dictionary! { "N" => look });
                new.set_object(extra, Object::Dictionary(d));
            });
            let got = changes(&b);
            let credited = |k: &ChangeKind| {
                let in_extra = |n: &String| n == "Extra";
                matches!(k, ChangeKind::Signed(n) | ChangeKind::DocumentTimestamp(n) if in_extra(n))
            };
            let fine = got.contains(&refused) && !got.iter().any(|(k, _)| credited(k));
            if !fine || report(&b).all_ok() {
                wrong.push(format!("after {after}, {from}'s: {got:?}"));
            }
        }
        // A copy in an object of its own: a new signature, found copied.
        let b = edit(&stamped, |prev, new| {
            let stamp = dict(prev, titled(prev, "Timestamp1"));
            let v = stamp.get(b"V").unwrap().as_reference().unwrap();
            let copy = new.add_object(dict(prev, v));
            let extra = titled(prev, "Extra");
            let mut d = dict(prev, extra);
            d.set("V", copy);
            new.set_object(extra, Object::Dictionary(d));
        });
        let status = sig(&b, "Extra").status;
        let copied = matches!(&status,
            SigStatus::Broken(why) if why.contains("added after the version"));
        if !copied || report(&b).all_ok() {
            wrong.push(format!("after {after}, a copy: {status:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A made-up signature on the widget of an empty signature field rather than on the field:
/// the report reads a field's signature from the field, so it doesn't list this one, and with
/// nothing to check it the signing is refused. It was allowed (after an ordinary signature,
/// and as a document timestamp after a certification allowing no changes).
#[test]
fn a_signature_on_a_fields_widget_is_refused() {
    let field = extra_field(&base_pdf(), true, |_| Dictionary::new());
    let what = "a signature in field \"Extra\" it can't check";
    let want = [(ChangeKind::Unrecognised(what.into()), Some(Refusal::Never))];
    let mut wrong = Vec::new();
    for (stamp, signed) in [(true, certify(&field, 1)), (false, approve(&field))] {
        let b = edit(&signed, |prev, new| {
            let w = first_kid(prev, titled(prev, "Extra"));
            fake_sign(prev, new, w, stamp);
        });
        let got = changes(&b);
        if got != want || report(&b).all_ok() {
            wrong.push(format!("timestamp {stamp}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// An empty signature field whose widget is a kid with a drawing of its own, signed after an
/// approval and after a certification allowing form filling (made up), the kid's drawing
/// redrawn in place as it is signed: allowed. It was refused, the drawing taken for a change
/// to an unsigned field.
#[test]
fn signing_redraws_a_widget_kids_own_drawing() {
    let field = extra_field(&base_pdf(), true, |new| {
        dictionary! { "AP" => dictionary! { "N" => appearance(new, "") } }
    });
    let want = [(ChangeKind::Signed("Extra".into()), None)];
    let mut wrong = Vec::new();
    for (signed, after) in [(approve(&field), "an approval"), (certify(&field, 2), "P2")] {
        let b = edit(&signed, |prev, new| {
            let top = titled(prev, "Extra");
            let mut v = dict(prev, top);
            v.set("V", new.add_object(dictionary! { "Type" => "Sig" }));
            new.set_object(top, Object::Dictionary(v));
            let kid = dict(prev, first_kid(prev, top));
            let ap = kid.get(b"AP").unwrap().as_dict().unwrap();
            let look = ap.get(b"N").unwrap().as_reference().unwrap();
            let mut s = prev.get_object(look).unwrap().as_stream().unwrap().clone();
            s.set_content(b"BT (Signed) Tj ET".to_vec());
            new.set_object(look, Object::Stream(s));
        });
        let got = changes(&b);
        if got != want {
            wrong.push(format!("after {after}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with text field `A`, its widget `F` (titled if `named`) on the page, and
/// after it empty signature field `B`, whose kids are in an array of their own: `F` again,
/// `depth` untitled fields down, if `shared`; none if not.
fn two_parents(depth: usize, named: bool, shared: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let a = new.new_object_id();
        let mut w = dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "F" => 4, "P" => page(prev), "Parent" => a,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
        };
        if named {
            w.set("T", Object::string_literal("F"));
        }
        let f = new.add_object(w);
        add_annot(prev, new, f);
        let (t, kids) = (Object::string_literal("A"), vec![Object::from(f)]);
        let field = dictionary! { "FT" => "Tx", "T" => t, "Kids" => kids };
        new.set_object(a, Object::Dictionary(field));
        let mut top = f;
        for _ in 0..depth {
            top = new.add_object(dictionary! { "Kids" => vec![Object::from(top)] });
        }
        let kids: Vec<Object> = if shared { vec![top.into()] } else { Vec::new() };
        let kids = new.add_object(kids);
        let b = new.add_object(dictionary! {
            "FT" => "Sig", "T" => Object::string_literal("B"), "Kids" => kids,
        });
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set(
            "AcroForm",
            dictionary! { "Fields" => vec![Object::from(a), Object::from(b)] },
        );
        new.set_object(r, Object::Dictionary(c));
    })
}

/// `F` of [`two_parents`] made `B`'s by edits to lists of kids and fields alone (`A` listing
/// it no more, or `B` listed first, `B` listing it too if it didn't), and given a made-up
/// signature in the same revision: refused as a change to `A`'s field. Before, listed by `B`
/// only in the revision, `F`'s signing was never judged and nothing was reported; 33 levels
/// down, past the 32 the form was followed to, `F` stayed `A`'s: refused as removed when `A`
/// dropped it, or taken for `A.F` filled in when `B` came first, allowed after an approval.
#[test]
fn a_widget_moved_under_a_signature_field_and_signed_is_refused() {
    let mut wrong = Vec::new();
    for (depth, named, shared) in [(33, true, true), (0, false, false)] {
        let form = two_parents(depth, named, shared);
        for (stamp, signed) in [(true, certify(&form, 1)), (false, approve(&form))] {
            for drop in [true, false] {
                let b = edit(&signed, |prev, new| {
                    let (a, b) = (titled(prev, "A"), titled(prev, "B"));
                    let f = first_kid(prev, a);
                    if !shared {
                        let kids = dict(prev, b).get(b"Kids").unwrap().as_reference().unwrap();
                        new.set_object(kids, vec![Object::from(f)]);
                    }
                    if drop {
                        let mut d = dict(prev, a);
                        d.set("Kids", Vec::<Object>::new());
                        new.set_object(a, Object::Dictionary(d));
                    } else {
                        list_first(prev, new, b);
                    }
                    fake_sign(prev, new, f, stamp);
                });
                let got = changes(&b);
                let moved = ChangeKind::FieldChanged((if named { "A.F" } else { "A" }).into());
                if !got.contains(&(moved, Some(Refusal::Never))) || report(&b).all_ok() {
                    let case = format!("depth {depth}, timestamp {stamp}, A drops it {drop}");
                    wrong.push(format!("{case}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with empty signature field `B`, its widget `W` on the page, and text
/// field `A`, whose kids are in an array of their own: `W` again if `shared`, `B` listed first
/// so `W` is `B`'s; none if not, `A` listed first.
fn widget_of_a_signature_field(shared: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let b = new.new_object_id();
        let w = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "F" => 4, "P" => page(prev), "Parent" => b,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
        });
        add_annot(prev, new, w);
        let (t, kids) = (Object::string_literal("B"), vec![Object::from(w)]);
        let field = dictionary! { "FT" => "Sig", "T" => t, "Kids" => kids };
        new.set_object(b, Object::Dictionary(field));
        let kids: Vec<Object> = if shared { vec![w.into()] } else { Vec::new() };
        let kids = new.add_object(kids);
        let a = new.add_object(dictionary! {
            "FT" => "Tx", "T" => Object::string_literal("A"), "Kids" => kids,
        });
        let fields = match shared {
            true => vec![Object::from(b), a.into()],
            false => vec![Object::from(a), b.into()],
        };
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set("AcroForm", dictionary! { "Fields" => fields });
        new.set_object(r, Object::Dictionary(c));
    })
}

/// `W` of [`widget_of_a_signature_field`] made `A`'s by edits to lists of kids and fields alone
/// (`A` listed first, or `A` listing it too), and filled in as `A`'s in the same revision:
/// refused as a change to `B`'s field, after an approval and after a certification allowing
/// form filling, either of which allows filling in `A`.
#[test]
fn a_widget_moved_out_of_a_signature_field_is_refused() {
    let moved = (ChangeKind::FieldChanged("B".into()), Some(Refusal::Never));
    let mut wrong = Vec::new();
    for shared in [true, false] {
        let form = widget_of_a_signature_field(shared);
        for (after, signed) in [("an approval", approve(&form)), ("P2", certify(&form, 2))] {
            let e = edit(&signed, |prev, new| {
                let (a, b) = (titled(prev, "A"), titled(prev, "B"));
                let w = first_kid(prev, b);
                if shared {
                    list_first(prev, new, a);
                } else {
                    let kids = dict(prev, a).get(b"Kids").unwrap().as_reference().unwrap();
                    new.set_object(kids, vec![Object::from(w)]);
                }
                let mut d = dict(prev, a);
                d.set("V", Object::string_literal("PAID"));
                new.set_object(a, Object::Dictionary(d));
                let ap = appearance(new, "BT (PAID) Tj ET");
                let mut d = dict(prev, w);
                d.set("AP", dictionary! { "N" => ap });
                new.set_object(w, Object::Dictionary(d));
            });
            let got = changes(&e);
            if !got.contains(&moved) || report(&e).all_ok() {
                wrong.push(format!("shared {shared}, after {after}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with text field `T`, a widget of its own on the page, and empty signature
/// field `B`, whose kids are in an array of their own: `T` if `inside`, `B` alone listed in the
/// form; none if not, `T` listed first.
fn typed_and_signature_field(inside: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let b = new.new_object_id();
        let mut t = dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "F" => 4, "P" => page(prev),
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
            "FT" => "Tx", "T" => Object::string_literal("T"),
        };
        if inside {
            t.set("Parent", b);
        }
        let t = new.add_object(t);
        add_annot(prev, new, t);
        let kids: Vec<Object> = if inside { vec![t.into()] } else { Vec::new() };
        let kids = new.add_object(kids);
        let (n, kids) = (Object::string_literal("B"), Object::from(kids));
        let field = dictionary! { "FT" => "Sig", "T" => n, "Kids" => kids };
        new.set_object(b, Object::Dictionary(field));
        let fields = match inside {
            true => vec![Object::from(b)],
            false => vec![Object::from(t), b.into()],
        };
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set("AcroForm", dictionary! { "Fields" => fields });
        new.set_object(r, Object::Dictionary(c));
    })
}

/// `T` of [`typed_and_signature_field`] moved into `B` or out of it by edits to lists of kids
/// and fields alone (listed in its new place only, or in both, the new one first):
/// refused as a change to `T`'s field, after an approval and after a certification allowing no
/// changes. Its own type keeps it a text field, so only its parent and name changing show the
/// move; before they were compared, it was reported as nothing.
#[test]
fn a_typed_field_moved_into_or_out_of_a_signature_field_is_refused() {
    let mut wrong = Vec::new();
    for inside in [false, true] {
        let form = typed_and_signature_field(inside);
        for (after, signed) in [("an approval", approve(&form)), ("P1", certify(&form, 1))] {
            for both in [false, true] {
                let e = edit(&signed, |prev, new| {
                    let (t, b) = (titled(prev, "T"), titled(prev, "B"));
                    let kids = dict(prev, b).get(b"Kids").unwrap().as_reference().unwrap();
                    match (inside, both) {
                        (false, false) => {
                            new.set_object(kids, vec![Object::from(t)]);
                            unlist(prev, new, t);
                        }
                        (false, true) => {
                            new.set_object(kids, vec![Object::from(t)]);
                            list_first(prev, new, b);
                        }
                        (true, false) => {
                            new.set_object(kids, Vec::<Object>::new());
                            list_field(prev, new, t);
                        }
                        (true, true) => list_first(prev, new, t),
                    }
                });
                let name = if inside { "B.T" } else { "T" };
                let moved = (ChangeKind::FieldChanged(name.into()), Some(Refusal::Never));
                let got = changes(&e);
                if !got.contains(&moved) || report(&e).all_ok() {
                    let case = format!("inside {inside}, after {after}, both {both}");
                    wrong.push(format!("{case}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with node `X` of no kind and empty signature field `T`, both listing
/// widget `K` (titled, of no kind of its own, with no `/Parent`): `X` listed first in the form
/// if `x_first`. `K` is `T`'s, `T.K`, either way.
fn kid_of_no_kind_and_of_a_signature_field(x_first: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let k = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "F" => 4, "P" => page(prev),
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
            "T" => Object::string_literal("K"),
        });
        add_annot(prev, new, k);
        let kids = vec![Object::from(k)];
        let x = dictionary! { "T" => Object::string_literal("X"), "Kids" => kids.clone() };
        let x = new.add_object(x);
        let t = dictionary! { "FT" => "Sig", "T" => Object::string_literal("T"), "Kids" => kids };
        let t = new.add_object(t);
        let fields = match x_first {
            true => vec![Object::from(x), t.into()],
            false => vec![Object::from(t), x.into()],
        };
        let r = root(prev);
        let mut c = dict(prev, r);
        c.set("AcroForm", dictionary! { "Fields" => fields });
        new.set_object(r, Object::Dictionary(c));
    })
}

/// `K` of [`kid_of_no_kind_and_of_a_signature_field`] signed, then approved, then its
/// signature taken out: refused as a change to the signature in `T.K`, whichever of `X` and
/// `T` is listed first. Before, with `X` first, the check named and typed `K` through `X`, a
/// field of no kind, while the report showed the signature in `T.K`: its removal passed as
/// `X.K` filled in, allowed.
#[test]
fn a_signature_in_a_field_a_node_of_no_kind_lists_first_stays_one() {
    let mut wrong = Vec::new();
    for x_first in [true, false] {
        let form = kid_of_no_kind_and_of_a_signature_field(x_first);
        let k = Field {
            name: "K",
            existing: true,
            ..Field::default()
        };
        let signed = approve(&sign(&form, &id("p256"), &k, &Cms::default()));
        let shown: Vec<_> = report(&signed)
            .signatures
            .into_iter()
            .map(|s| s.fields)
            .collect();
        assert_eq!(
            shown,
            [vec!["T.K"], vec!["Signature1"]],
            "X first {x_first}"
        );
        let e = edit(&signed, |prev, new| {
            let k = titled(prev, "K");
            let mut d = dict(prev, k);
            d.remove(b"V");
            new.set_object(k, Object::Dictionary(d));
        });
        let got = changes(&e);
        let removed = (
            ChangeKind::SignatureChanged("T.K".into()),
            Some(Refusal::Never),
        );
        if !got.contains(&removed) || report(&e).all_ok() {
            wrong.push(format!("X first {x_first}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// `K` of [`kid_of_no_kind_and_of_a_signature_field`] locked by the first signature, by the
/// name the report shows, `T.K`, then signed: refused as locked, whichever of `X` and `T` is
/// listed first. Before, with `X` first, the check named it `X.K`, which no lock named, and
/// allowed its signing as `X.K` filled in.
#[test]
fn a_lock_reaches_a_field_a_node_of_no_kind_lists_first() {
    let mut wrong = Vec::new();
    for x_first in [true, false] {
        let form = kid_of_no_kind_and_of_a_signature_field(x_first);
        let locked = locked_by(&form, lock("Include", &["T.K"], None));
        let k = Field {
            name: "K",
            existing: true,
            ..Field::default()
        };
        let b = sign(&locked, &id("p256"), &k, &Cms::default());
        let got = changes(&b);
        let signed = (ChangeKind::Signed("T.K".into()), Some(Refusal::Locked));
        if !got.contains(&signed) || report(&b).all_ok() {
            wrong.push(format!("X first {x_first}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The base document with signature field `Signature1`, its widget `W` on the page, and empty
/// signature field `S2`: the kids of each in an array of their own if `arrays` (`S2`'s none),
/// else `Signature1`'s listed in it and `S2` with none.
fn two_signature_fields(arrays: bool) -> Vec<u8> {
    edit(&base_pdf(), |prev, new| {
        let s1 = new.new_object_id();
        let w = new.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "F" => 4, "P" => page(prev), "Parent" => s1,
            "Rect" => vec![150.into(), 100.into(), 250.into(), 140.into()],
        });
        add_annot(prev, new, w);
        let mut first = dictionary! { "FT" => "Sig", "T" => Object::string_literal("Signature1") };
        let mut second = dictionary! { "FT" => "Sig", "T" => Object::string_literal("S2") };
        let kids = vec![Object::from(w)];
        if arrays {
            first.set("Kids", new.add_object(kids));
            second.set("Kids", new.add_object(Vec::<Object>::new()));
        } else {
            first.set("Kids", kids);
        }
        new.set_object(s1, Object::Dictionary(first));
        let s2 = new.add_object(second);
        let r = root(prev);
        let mut c = dict(prev, r);
        let fields = vec![Object::from(s1), s2.into()];
        c.set("AcroForm", dictionary! { "Fields" => fields });
        new.set_object(r, Object::Dictionary(c));
    })
}

/// `W` of [`two_signature_fields`] made `S2`'s once `Signature1` is signed, by edits to the
/// arrays of kids alone, or by `S2` listed first and then signed with `W` as its kid: refused
/// as a change to `Signature1`'s field, as the signature would show as `S2`'s. `W` holds no
/// value, so only its parent and name changing show the move; before they were compared, it
/// was allowed.
#[test]
fn a_signed_fields_widget_moved_to_another_signature_field_is_refused() {
    let moved = ChangeKind::FieldChanged("Signature1".into());
    let mut wrong = Vec::new();
    for arrays in [true, false] {
        let f = Field {
            existing: true,
            ..Field::default()
        };
        let form = two_signature_fields(arrays);
        let signed = sign(&form, &id("rsa3072"), &f, &Cms::default());
        let e = if arrays {
            edit(&signed, |prev, new| {
                let kids = |field| {
                    let d = dict(prev, titled(prev, field));
                    d.get(b"Kids").unwrap().as_reference().unwrap()
                };
                let (from, to) = (kids("Signature1"), kids("S2"));
                let w = prev.get_object(from).unwrap().as_array().unwrap()[0].clone();
                new.set_object(from, Vec::<Object>::new());
                new.set_object(to, vec![w]);
            })
        } else {
            let first = edit(&signed, |prev, new| {
                list_first(prev, new, titled(prev, "S2"))
            });
            let d = Document::load_mem(&first).unwrap();
            let w = first_kid(&d, titled(&d, "Signature1"));
            let f = Field {
                name: "S2",
                existing: true,
                widget: dictionary! { "Kids" => vec![Object::from(w)] },
                ..Field::default()
            };
            sign(&first, &id("p256"), &f, &Cms::default())
        };
        let got = changes(&e);
        if !got.contains(&(moved.clone(), Some(Refusal::Never))) || report(&e).all_ok() {
            wrong.push(format!("arrays {arrays}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Signed, timestamped, then an untitled signature field added and listed first with the
/// timestamp's field among its kids (and a valued text field too, `hidden`): the field added is
/// judged as one, refused after a certification or a lock allowing no changes, and the
/// timestamp's field moved, never allowed. Before, the timestamp found in the new field was
/// taken for its signing, and the field added went unreported.
#[test]
fn a_new_signature_field_holding_an_earlier_signature_is_no_signing() {
    let form = form(&["Name"]);
    let locked = locked_by(&form, lock("All", &[], Some(1)));
    let signed = [
        (certify(&form, 1), "P1", true),
        (locked, "a P1 lock", true),
        (approve(&form), "an approval", false),
    ];
    let added = ChangeKind::SignatureFieldAdded("".into());
    let moved = ChangeKind::FieldChanged("Timestamp1".into());
    let mut wrong = Vec::new();
    for (signed, after, refused) in signed {
        let stamped = timestamp(&signed, true);
        for hidden in [false, true] {
            let b = edit(&stamped, |prev, new| {
                let w = new.new_object_id();
                let mut kids = vec![Object::from(titled(prev, "Timestamp1"))];
                if hidden {
                    let t = new.add_object(dictionary! {
                        "FT" => "Tx", "T" => Object::string_literal("Hidden"),
                        "V" => Object::string_literal("1,000,000"), "Parent" => w,
                    });
                    kids.push(t.into());
                }
                let field = dictionary! { "FT" => "Sig", "Kids" => kids };
                new.set_object(w, Object::Dictionary(field));
                list_first(prev, new, w);
            });
            let got = changes(&b);
            let judged = (got.iter()).any(|(k, r)| *k == added && r.is_some() == refused);
            let never = got.contains(&(moved.clone(), Some(Refusal::Never)));
            if !judged || !never || report(&b).all_ok() {
                wrong.push(format!("hidden {hidden} after {after}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_change_undone_before_the_next_signature_still_counts() {
    let b = approve(&base_pdf());
    let rotate = |b: &[u8], r: Option<i64>| {
        edit(b, |prev, new| {
            let p = page(prev);
            let mut d = dict(prev, p);
            match r {
                Some(r) => d.set("Rotate", r),
                None => _ = d.remove(b"Rotate"),
            }
            new.set_object(p, Object::Dictionary(d));
        })
    };
    // Turned, countersigned, turned back: the page ends as the first signer signed it, but
    // the second signer signed something else. Before, as the second signature ends just
    // before the end of line its revision's end takes in, the first was checked against
    // the end alone, and only the second signing was seen. So too when the signed version is
    // followed by "\r\n", the most end of line a revision's end takes in.
    let turned = countersign(&rotate(&b, Some(90)), "Signature2", false);
    assert!(turned.ends_with(b"%%EOF"));
    for eol in ["", "\r\n"] {
        let turned = [&turned, eol.as_bytes()].concat();
        let b = rotate(&turned, None);
        let d = Document::load_mem(&b).unwrap();
        assert!(!dict(&d, page(&d)).has(b"Rotate"));
        assert_refused(&b, &ChangeKind::PageContent);
        assert!(!sig(&b, "Signature2").changes_allowed());
    }
}

// ---------------------------------------------------------------- attacks

/// Shadow attack, hide: an update that only frees an object still in use. Some apps find it
/// by scanning, so it is refused, by LimarePDF's own reader.
#[test]
fn freeing_an_object_still_in_use_is_refused() {
    let b = approve(&base_pdf());
    let c = contents(&b);
    let freed = append_raw(&b, &[], &[c.0], &[], "");
    let got = changes(&freed);
    assert!(
        matches!(&got[..], [(ChangeKind::Unrecognised(w), Some(Refusal::Never))] if w.contains("deleted but is still used")),
        "{got:#?}"
    );
}

/// Shadow attack, hide-and-replace: an update re-pointing an object at bytes inside the
/// signed part (an unused object planted before signing).
#[test]
fn pointing_back_into_the_signed_part_is_refused() {
    let b = approve(&base_pdf());
    let c = contents(&b);
    let moved = append_raw(&b, &[], &[], &[(c.0, 9)], "");
    assert!(matches!(
        &changes(&moved)[..],
        [(ChangeKind::Malformed(w), _)] if w.contains("outside the revision")
    ));
    // An entry pointing at another object's header (DSS hide.pdf). The kit starts the
    // revision on a new line.
    let at = b.len() + usize::from(!b.ends_with(b"\n"));
    let num = Document::load_mem(&b).unwrap().max_id + 1;
    let wrong = append_raw(&b, &[(num, b"<< >>")], &[], &[(c.0, at)], "");
    assert!(matches!(
        &changes(&wrong)[..],
        [(ChangeKind::Malformed(w), _)] if w.contains("isn't where")
    ));
}

/// With several objects that don't read as their entries say, the reason names the same one
/// (the lowest number) every time the file is checked, so saving it doesn't take a reason
/// that merely names another object for a new change (DSS modified_after_signature.pdf).
#[test]
fn a_malformed_revision_gives_the_same_reason_each_time() {
    let b = approve(&base_pdf());
    let d = Document::load_mem(&b).unwrap();
    let c = contents(&b);
    let p = page(&d);
    let at = b.len() + usize::from(!b.ends_with(b"\n"));
    let num = d.max_id + 1;
    let wrong = append_raw(&b, &[(num, b"<< >>")], &[], &[(c.0, at), (p.0, at)], "");
    let low = c.0.min(p.0);
    for _ in 0..20 {
        let got = changes(&wrong);
        assert!(
            matches!(&got[..], [(ChangeKind::Malformed(w), _)]
                if *w == format!("object {low} isn't where its cross-reference entry says")),
            "{got:#?}"
        );
    }
}

#[test]
fn data_after_the_last_revision_is_refused() {
    let mut b = fill(&approve(&form(&["Name"])), "Name", "Jane");
    b.extend_from_slice(b"9 0 obj << /Junk true >> endobj\n");
    assert!(matches!(
        &changes(&b)[..],
        [(ChangeKind::Malformed(w), _)] if w.contains("complete revision")
    ));
}

/// Shadow attack shape: an object the page draws is also listed as an annotation, so
/// changing it might pass as "comment changed".
#[test]
fn page_content_posing_as_a_comment_is_still_page_content() {
    let base = edit(&base_pdf(), |prev, new| {
        let p = page(prev);
        let c = dict(prev, p)
            .get(b"Contents")
            .unwrap()
            .as_reference()
            .unwrap();
        let mut d = dict(prev, p);
        d.set("Annots", vec![Object::from(c)]);
        new.set_object(p, Object::Dictionary(d));
    });
    let b = approve(&base);
    let c = contents(&b);
    let changed = edit(&b, |_, new| {
        new.set_object(c, Stream::new(Dictionary::new(), b"0 0 m 9 9 l S".to_vec()));
    });
    assert_refused(&changed, &ChangeKind::PageContent);
}

/// An object the signed version referred to but didn't have, filled in later.
#[test]
fn filling_in_a_missing_object_is_refused() {
    let base = edit(&base_pdf(), |prev, new| {
        let p = page(prev);
        let mut d = dict(prev, p);
        d.set("Thumb", Object::Reference((900, 0)));
        new.set_object(p, Object::Dictionary(d));
    });
    let b = approve(&base);
    let b = append_raw(&b, &[(900, b"<< /Late true >>")], &[], &[], "");
    let got = changes(&b);
    assert!(
        got.iter()
            .any(|(k, r)| matches!(k, ChangeKind::Unrecognised(_)) && r.is_some()),
        "{got:#?}"
    );
}

/// Truncated or damaged appended data never panics and never passes as unchanged.
#[test]
fn damaged_appended_data_is_never_clean() {
    let b = fill(&approve(&form(&["Name"])), "Name", "Jane");
    let end = sig(&b, "Signature1").signed_len.unwrap();
    let clean = |x: &[u8]| -> Option<bool> {
        let r = verify_signatures(x, None, &TrustList::default()).ok()?;
        let s = r.signatures.iter().find(|s| s.fields == ["Signature1"])?;
        Some(s.status == SigStatus::Valid && s.changes.is_empty())
    };
    for cut in (end + 1..b.len()).step_by(3) {
        let x = &b[..cut];
        if clean(x) == Some(true) {
            assert!(x[end..].iter().all(u8::is_ascii_whitespace), "cut at {cut}");
        }
    }
    for at in (end..b.len()).step_by(5) {
        for flip in [0x01u8, 0x20, 0x80] {
            let mut x = b.clone();
            x[at] ^= flip;
            assert_ne!(clean(&x), Some(true), "byte {at} ^ {flip:#x}");
        }
    }
}

// ---------------------------------------------------------------- signed versions

#[test]
fn the_signed_version_is_the_file_as_signed() {
    let signed = approve(&form(&["Name"]));
    let b = comment(&fill(&signed, "Name", "Jane"), Dictionary::new());
    let s = sig(&b, "Signature1");
    let len = s.signed_len.unwrap();
    assert_eq!(&b[..len], &signed[..]);
    let then = sig(&b[..len], "Signature1");
    assert_eq!(then.status, SigStatus::Valid);
    assert!(then.covers_whole_file && then.changes.is_empty());
}
