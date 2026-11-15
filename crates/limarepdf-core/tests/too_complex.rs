//! Reading a page has a budget (S1-06, H-07): a page whose drawings draw each other over and
//! over is refused quickly with a typed reason, and what relies on reading it (editing,
//! redacting, search, finding its pictures) says so and changes nothing. A drawing that draws
//! itself is read once. Drawing annotations has a budget too: flattening and redacting
//! annotations too complex to draw are refused, and listing them places those past it at
//! their own `/Rect`.

mod common;

use common::apart::{self, Ran};
use limarepdf_core::{render, FontChoice, Pdf, Query, TextIndex};
use lopdf::{dictionary, Dictionary, Object, ObjectId, Stream};
use std::time::{Duration, Instant};

/// Pages with "Zebra" on them, `pages` of them.
fn zebras(pages: usize) -> Pdf {
    let (mut p, font) = (Pdf::new(), FontChoice::default());
    for i in 0..pages {
        p.insert_blank(i, 612.0, 792.0).unwrap();
        p.add_text(i, (72.0, 100.0), "Zebra", font, 20.0, [0.0; 3])
            .unwrap();
    }
    p
}

/// Page `page` of `p` draws a form that, with resources of its own, draws itself `times`
/// times over.
fn draw_itself(p: &mut Pdf, page: usize, times: usize) {
    let me = p.doc.new_object_id();
    let form = Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Me" => me } },
        },
        "/Me Do ".repeat(times).into_bytes(),
    );
    p.doc.objects.insert(me, form.into());
    draw_form(p, page, me);
}

/// Page `page` of `p` draws `form` (as `/Me`) after what it drew.
fn draw_form(p: &mut Pdf, page: usize, form: ObjectId) {
    let id = p.page_ids()[page];
    let content = [p.doc.get_page_content(id).as_slice(), b" q /Me Do Q"].concat();
    let content = p.doc.add_object(Stream::new(Dictionary::new(), content));
    let page = p.doc.get_dictionary(id).unwrap();
    let mut res = match page.get(b"Resources").ok().cloned() {
        Some(Object::Reference(r)) => p.doc.get_dictionary(r).unwrap().clone(),
        Some(Object::Dictionary(d)) => d,
        _ => Dictionary::new(),
    };
    res.set("XObject", dictionary! { "Me" => form });
    let d = p.doc.get_dictionary_mut(id).unwrap();
    d.set("Contents", content);
    d.set("Resources", res);
}

/// Page `page` of `p` draws a tree of forms `depth` deep, each drawing the one below it
/// `width` times; the last ends a path that isn't there (`n`), one operator.
fn draw_tree(p: &mut Pdf, page: usize, width: usize, depth: usize) {
    let form = |content: String, res: Dictionary| {
        let d = dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Resources" => res,
        };
        Stream::new(d, content.into_bytes())
    };
    let mut below = p.doc.add_object(form("n".into(), Dictionary::new()));
    for _ in 0..depth {
        let res = dictionary! { "XObject" => dictionary! { "Me" => below } };
        below = p.doc.add_object(form("/Me Do ".repeat(width), res));
    }
    draw_form(p, page, below);
}

/// The steps reading a page drawing [`draw_tree`]'s tree takes, counted from the rule, not
/// by the parser: an operator is a step, and so is each form opened (its content is under
/// a KiB, so nothing more for its size).
fn tree_steps(width: u64, depth: u32) -> u64 {
    // The leaf: opened, and its one operator.
    let mut form = 2;
    for _ in 0..depth {
        // Opened, and `width` operators each opening the form below.
        form = 1 + width * (1 + form);
    }
    // The page draws "Zebra" (BT, Tf, Td, Tj, ET as add_text writes it, measured below
    // with no tree) and q, Do, Q.
    3 + form
}

/// The steps a page of [`zebras`] alone takes.
fn zebra_steps() -> u64 {
    use limarepdf_core::budget_seam;
    let p = zebras(1);
    let (read, taken) = budget_seam::with_limit(u64::MAX, || p.page_objects(0).map(|_| ()));
    read.unwrap();
    assert_eq!(taken.len(), 1, "one budget for the page: {taken:?}");
    taken[0]
}

/// The budget is charged across every form a page draws, however often: a tree of forms
/// three wide and four deep (121 forms opened) is read within the steps it needs, and
/// refused one step short of them, or with 40.
#[test]
fn a_page_drawing_forms_over_and_over_is_refused_past_its_budget() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    draw_tree(&mut p, 0, 3, 4);
    common::seeds::pdf(&p);
    let needed = zebra_steps() + tree_steps(3, 4);
    let (read, taken) = budget_seam::with_limit(u64::MAX, || p.page_objects(0).map(|_| ()));
    read.unwrap();
    assert_eq!(taken, [needed]);
    let (read, taken) = budget_seam::with_limit(needed, || p.page_objects(0).map(|_| ()));
    read.unwrap();
    assert_eq!(taken, [needed]);
    for short in [needed - 1, 40] {
        let (read, taken) = budget_seam::with_limit(short, || p.page_objects(0).map(|_| ()));
        let e = read.unwrap_err();
        let too = e.downcast_ref::<TooComplex>().expect("too complex");
        assert_eq!(too.limit, short, "{e:#}");
        assert!(taken.len() == 1 && taken[0] <= short, "{taken:?}");
    }
}

/// A spot colour whose tint transform is stitched `depth` levels deep, each level listing the
/// one below `width` times, down to one exponential function.
fn shared_tint(p: &mut Pdf, width: usize, depth: usize) -> Object {
    let mut part = p.doc.add_object(dictionary! {
        "FunctionType" => 2, "Domain" => vec![0.into(), 1.into()],
        "C0" => vec![0.into()], "C1" => vec![1.into()], "N" => 1,
    });
    for _ in 0..depth {
        let bounds = (1..width).map(|i| Object::Real(i as f32 / width as f32));
        part = p.doc.add_object(dictionary! {
            "FunctionType" => 3, "Domain" => vec![0.into(), 1.into()],
            "Functions" => vec![Object::Reference(part); width],
            "Bounds" => bounds.collect::<Vec<_>>(),
            "Encode" => (0..width).flat_map(|_| [0.into(), 1.into()]).collect::<Vec<Object>>(),
        });
    }
    Object::Array(vec![
        "Separation".into(),
        "Spot".into(),
        "DeviceGray".into(),
        part.into(),
    ])
}

/// The steps reading [`shared_tint`]'s space takes, counted from the rule: the space and its
/// alternate, each function once, and each part a stitching function lists.
fn tint_steps(width: u64, depth: u64) -> u64 {
    2 + (depth + 1) + depth * width
}

/// Page 0 of `p` draws a form with the colour spaces `spaces`, whose content is `content`.
fn draw_colours(p: &mut Pdf, spaces: Dictionary, content: String) {
    let form = p.doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Resources" => dictionary! { "ColorSpace" => spaces },
        },
        content.into_bytes(),
    ));
    draw_form(p, 0, form);
}

/// Page 0 of `p` is read within the `needed` steps, taking them all, and refused one short.
fn read_within(p: &Pdf, needed: u64) {
    use limarepdf_core::{budget_seam, TooComplex};
    let (read, taken) = budget_seam::with_limit(needed, || p.page_objects(0).map(|_| ()));
    read.unwrap();
    assert_eq!(taken, [needed]);
    let (read, taken) = budget_seam::with_limit(needed - 1, || p.page_objects(0).map(|_| ()));
    let e = read.unwrap_err();
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.limit, needed - 1, "{e:#}");
    assert!(taken.len() == 1 && taken[0] < needed, "{taken:?}");
}

/// Reading a colour space is charged to its page's budget, each function read once: a page
/// choosing a spot colour stitched three levels deep from parts it shares (8,421 functions
/// read before) is read within the steps it needs, and refused one step short.
#[test]
fn a_page_s_colour_spaces_are_charged_to_its_budget() {
    let mut p = zebras(1);
    let space = shared_tint(&mut p, 20, 3);
    draw_colours(&mut p, dictionary! { "CS0" => space }, "/CS0 cs".into());
    // q, Do and Q; the form opened; its one operator.
    read_within(&p, zebra_steps() + 3 + 1 + 1 + tint_steps(20, 3));
}

/// A spot colour whose tint transform is a calculator program of `steps` steps, leaving the
/// tint as it was; and the program's length.
fn calculated_tint(p: &mut Pdf, steps: usize) -> (Object, u64) {
    let code = format!("{{ {}}}", "dup pop ".repeat(steps / 2));
    let len = code.len() as u64;
    let tint = p.doc.add_object(Stream::new(
        dictionary! {
            "FunctionType" => 4, "Domain" => vec![0.into(), 1.into()],
            "Range" => vec![0.into(), 1.into()],
        },
        code.into_bytes(),
    ));
    let space = vec![
        "Separation".into(),
        "Spot".into(),
        "DeviceGray".into(),
        tint.into(),
    ];
    (Object::Array(space), len)
}

/// Setting a colour is charged what showing it takes, each time: a spot colour whose tint
/// transform runs 8,192 steps, chosen and set 40 times to fill and as many to stroke, is
/// charged 8 more steps each time (one for each 1,024 values read and steps run: the tint,
/// the program and the grey it gives). Before, each was charged only as an operator.
#[test]
fn a_colour_is_charged_what_showing_it_takes_each_time_it_is_set() {
    let mut p = zebras(1);
    let (space, len) = calculated_tint(&mut p, 8192);
    let times = 40;
    let fill = " 0.5 scn".repeat(times);
    let stroke = " 0.5 SCN".repeat(times);
    let content = format!("/CS0 cs{fill} /CS0 CS{stroke}");
    draw_colours(&mut p, dictionary! { "CS0" => space }, content);
    // The space and its alternate read once, the program a step and one for each KiB.
    let read = 2 + 1 + len / 1024;
    let each = (1 + 8192 + 1) / 1024;
    let set = 2 * times as u64 + 2;
    // q, Do and Q; the form opened (under a KiB).
    read_within(&p, zebra_steps() + 3 + 1 + read + set * (1 + each));
}

/// Setting a colour of many inks is charged them each time: 4,096 inks chosen 40 times, and
/// an indexed colour over them set 40 times, are charged 4 more steps each time. Before,
/// each was charged only as an operator.
#[test]
fn a_colour_of_many_inks_is_charged_them_each_time_it_is_set() {
    let mut p = zebras(1);
    let inks: u64 = 4096;
    let tint = p.doc.add_object(dictionary! {
        "FunctionType" => 2, "Domain" => vec![0.into(), 1.into()],
        "C0" => vec![0.into()], "C1" => vec![1.into()], "N" => 1,
    });
    let names = (0..inks).map(|i| Object::Name(format!("Ink{i}").into_bytes()));
    let many = Object::Array(vec![
        "DeviceN".into(),
        Object::Array(names.collect()),
        "DeviceGray".into(),
        tint.into(),
    ]);
    let table = Object::string_literal(vec![255; inks as usize]);
    let indexed = Object::Array(vec!["Indexed".into(), many.clone(), 0.into(), table]);
    let times = 40;
    let fill = "/CS0 cs ".repeat(times);
    let stroke = " 0 SC".repeat(times);
    let content = format!("{fill} /CS1 CS{stroke}");
    let spaces = dictionary! { "CS0" => many, "CS1" => indexed };
    draw_colours(&mut p, spaces, content);
    // Each space read once: the inks' space, one more for each 1,024 inks, its tint
    // transform and its alternate; the indexed space, its table's KiB and the inks under it.
    let many_read = 1 + inks / 1024 + 1 + 1;
    let indexed_read = 1 + inks / 1024 + many_read;
    // The inks, the tint's one output and the grey it gives; and the index over them.
    let many_each = (inks + 1 + 1) / 1024;
    let indexed_each = (1 + inks + 1 + 1) / 1024;
    let set = times as u64 * (1 + many_each) + (1 + times as u64) * (1 + indexed_each);
    read_within(&p, zebra_steps() + 3 + 1 + many_read + indexed_read + set);
}

/// A form whose content can't be decoded is passed over, as before: the rest of the page
/// is read.
#[test]
fn a_form_that_can_t_be_decoded_is_passed_over() {
    let mut p = zebras(1);
    let broken = p.doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Filter" => "FlateDecode",
        },
        b"not deflated at all".to_vec(),
    ));
    draw_form(&mut p, 0, broken);
    let objs = p.page_objects(0).unwrap();
    assert!(objs.iter().any(|o| o.text.as_deref() == Some("Zebra")));
    assert!(p.find_text_boxes(0, "zebra").unwrap().len() == 1);
}

/// The name page `page` of `p` knows its font by, as [`zebras`] wrote it.
fn font_name(p: &Pdf, page: usize) -> String {
    let id = p.page_ids()[page];
    let res = p.doc.get_dictionary(id).unwrap().get(b"Resources").unwrap();
    let res = p.doc.dereference(res).unwrap().1.as_dict().unwrap();
    let fonts = p.doc.dereference(res.get(b"Font").unwrap()).unwrap().1;
    let (name, _) = fonts.as_dict().unwrap().iter().next().unwrap();
    String::from_utf8(name.clone()).unwrap()
}

/// Page `page` of `p` draws `A`, a form writing "Alpha" that draws `B`, writing "Beta",
/// which draws `A` again (as pdf.js's `issue19800-eq.pdf`).
fn draw_each_other(p: &mut Pdf, page: usize) {
    let font = font_name(p, page);
    let form = |word: &str, next: &str| {
        let content = format!("BT /{font} 20 Tf 72 300 Td ({word}) Tj ET /{next} Do");
        let d = dictionary! { "Type" => "XObject", "Subtype" => "Form" };
        Stream::new(d, content.into_bytes())
    };
    let a = p.doc.add_object(form("Alpha", "B"));
    let b = p.doc.add_object(form("Beta", "A"));
    draw_form(p, page, a);
    let id = p.page_ids()[page];
    let page = p.doc.get_dictionary_mut(id).unwrap();
    let res = page.get_mut(b"Resources").unwrap().as_dict_mut().unwrap();
    res.set("XObject", dictionary! { "Me" => a, "A" => a, "B" => b });
}

/// Two forms drawing each other are each read once, on the way down: the drawing that
/// would repeat is passed over, and the rest of the page is read.
#[test]
fn forms_drawing_each_other_are_read_once() {
    let mut p = zebras(1);
    draw_each_other(&mut p, 0);
    common::seeds::pdf(&p);
    let text = p.page_text(0);
    let words: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(words, ["Zebra", "Alpha", "Beta"], "{text}");
    let boxes = p.find_text_boxes(0, "beta").unwrap();
    assert_eq!(boxes.len(), 1);
}

/// The child process of the next test: reads a page whose form draws itself ten times over,
/// which unchecked is read 10⁸ times.
#[test]
#[ignore = "started by a_page_drawing_itself_is_read_at_once"]
fn too_complex_child() {
    if std::env::var("TOO_COMPLEX_CHILD").is_err() {
        return;
    }
    let mut p = zebras(1);
    draw_itself(&mut p, 0, 10);
    common::seeds::pdf(&p);
    match p.page_objects(0) {
        Ok(objs) => {
            let text: Vec<_> = objs.into_iter().filter_map(|o| o.text).collect();
            println!("complex|read|{}", text.join(" "));
        }
        Err(e) => println!("complex|refused|{e:#}"),
    }
}

/// A page whose form draws itself is read at once, the form once, not until the nesting
/// limit stops it (ten times over, eight deep: 10⁸ forms read).
#[test]
fn a_page_drawing_itself_is_read_at_once() {
    let start = Instant::now();
    let env = [("TOO_COMPLEX_CHILD", "1".to_string())];
    let ran = apart::run("too_complex_child", &env, Duration::from_secs(30));
    let Ran::Ended(text, status) = ran else {
        panic!("not read within 30 s");
    };
    let said = apart::reports(&text, "complex|");
    assert_eq!(said.len(), 1, "{}", apart::why_stopped(status));
    assert_eq!(said[0], "read|Zebra");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// A page too complex to read is refused for editing, with nothing changed; its words
/// aren't found, and the page's text is empty, as for any page that can't be read.
#[test]
fn a_page_too_complex_to_read_isn_t_read_or_edited() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    draw_tree(&mut p, 0, 3, 4);
    common::seeds::pdf(&p);
    let ((), _) = budget_seam::with_limit(40, || {
        let e = p.page_objects(0).unwrap_err();
        let too = e.downcast_ref::<TooComplex>().expect("too complex");
        assert_eq!(too.what, "reading the page");
        assert!(p.page_words(0).is_err());
        assert!(p.find_text_boxes(0, "zebra").is_err());
        assert_eq!(p.page_text(0), "");
        let before = p.state_before();
        let e = p.delete_object(0, 0).unwrap_err();
        assert!(e.downcast_ref::<TooComplex>().is_some(), "{e:#}");
        let moved = [1.0, 0.0, 0.0, 1.0, 5.0, 5.0];
        let e = p.transform_object(0, 0, moved).unwrap_err();
        assert!(e.downcast_ref::<TooComplex>().is_some(), "{e:#}");
        assert_eq!(p.state_since(&before), []);
    });
}

/// A redaction over a page too complex to read is refused before any page changes: the
/// text under each mark is read first.
#[test]
fn a_redaction_over_a_page_too_complex_to_read_changes_nothing() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(2);
    draw_tree(&mut p, 1, 3, 4);
    let before = p.state_before();
    let whole = [0.0, 0.0, 612.0, 792.0];
    let (e, _) = budget_seam::with_limit(40, || p.redact(&[(0, whole), (1, whole)]));
    let e = e.unwrap_err();
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.what, "reading the page", "{e:#}");
    assert_eq!(p.state_since(&before), []);
}

/// Page 1 of `p`, saved, drawn at 72 dpi.
fn drawn(p: &mut Pdf) -> render::Bitmap {
    let doc = render::load(p.snapshot().unwrap(), None).unwrap();
    render::Renderer::new(&doc).render(0, 1.0).unwrap()
}

/// A redaction over a form that draws itself twice follows the form once: drawn again
/// inside itself, it goes whole, twice, not once for each copy down to the nesting limit
/// (PB-104), and the page outside the mark draws as before.
#[test]
fn a_redaction_over_a_form_drawing_itself_follows_it_once() {
    let mut p = zebras(1);
    draw_itself(&mut p, 0, 2);
    let before = drawn(&mut p);
    // Over the form, clear of "Zebra": 300 to 400 points (and pixels) each way.
    let rep = p.redact(&[(0, [300.0, 300.0, 400.0, 400.0])]).unwrap();
    assert_eq!(rep.pages[0].images, 2, "{rep:?}");
    assert_eq!(p.page_text(0).trim(), "Zebra");
    let after = drawn(&mut p);
    let outside = |i: usize| {
        let (x, y) = (i % after.width, i / after.width);
        !(299..=401).contains(&x) || !(299..=401).contains(&y)
    };
    let px = |b: &render::Bitmap, i: usize| b.rgba[i * 4..i * 4 + 4].to_vec();
    let changed = (0..after.width * after.height)
        .filter(|&i| outside(i) && px(&before, i) != px(&after, i))
        .count();
    assert_eq!(changed, 0);
}

/// Search reads the pages it can and names those it can't, with why.
#[test]
fn search_names_the_pages_it_can_t_read() {
    use limarepdf_core::budget_seam;
    let mut p = zebras(3);
    draw_tree(&mut p, 1, 3, 4);
    let mut index = TextIndex::new(&p);
    let (read, _) = budget_seam::with_limit(40, || index.read(&p, 0..3, &|| false));
    assert!(read);
    let found = index.find(&Query::new("zebra"), 0..3, 0);
    let pages: Vec<usize> = found.hits.iter().map(|h| h.page).collect();
    assert_eq!(pages, [0, 2]);
    assert_eq!(found.unread, [(1, "it is too complex to read".to_string())]);
    // Only the pages looked in are named.
    assert!(index.find(&Query::new("zebra"), 2..3, 0).unread.is_empty());
}

/// Finding the pictures, which follows every drawing every page draws, has the same budget:
/// naming, saving or reducing the pictures of a document with a page too complex to follow
/// is refused, with nothing written or changed. Failed on the old code: named, not refused.
#[test]
fn pictures_on_a_page_too_complex_to_follow_are_refused() {
    use limarepdf_core::{budget_seam, ReduceOptions, TooComplex};
    let mut p = zebras(2);
    draw_tree(&mut p, 1, 3, 4);
    let scratch = common::tool::Scratch::new("too-complex");
    let dir = scratch.join("pictures");
    let before = p.state_before();
    let ((), _) = budget_seam::with_limit(40, || {
        let e = p.picture_names("zebras").unwrap_err();
        let too = e.downcast_ref::<TooComplex>().expect("too complex");
        assert_eq!(too.what, "finding the pictures", "{e:#}");
        let e = p.save_all_pictures(&dir, "zebras").unwrap_err();
        assert!(e.downcast_ref::<TooComplex>().is_some(), "{e:#}");
        let opts = ReduceOptions::default();
        let e = p.reduce_pictures(&[0], &opts).unwrap_err();
        assert!(e.downcast_ref::<TooComplex>().is_some(), "{e:#}");
    });
    assert!(!dir.exists());
    assert_eq!(p.state_since(&before), []);
    // Within the steps it needs, the tree is followed: it draws no pictures.
    assert!(p.picture_names("zebras").unwrap().is_empty());
}

/// The child process of the next test: names the pictures of a page drawing a tree of
/// forms ten wide and eight deep, which unchecked is followed 10⁸ times.
#[test]
#[ignore = "started by pictures_of_a_page_drawing_forms_over_and_over_are_refused_at_once"]
fn too_complex_pictures_child() {
    if std::env::var("TOO_COMPLEX_PICTURES_CHILD").is_err() {
        return;
    }
    let mut p = zebras(1);
    draw_tree(&mut p, 0, 10, 8);
    match p.picture_names("zebras") {
        Ok(names) => println!("pictures|named|{}", names.len()),
        Err(e) => println!("pictures|refused|{e:#}"),
    }
}

/// Failed on the old code: not named within 30 s.
#[test]
fn pictures_of_a_page_drawing_forms_over_and_over_are_refused_at_once() {
    let start = Instant::now();
    let env = [("TOO_COMPLEX_PICTURES_CHILD", "1".to_string())];
    let ran = apart::run("too_complex_pictures_child", &env, Duration::from_secs(30));
    let Ran::Ended(text, status) = ran else {
        panic!("not named within 30 s");
    };
    let said = apart::reports(&text, "pictures|");
    assert_eq!(said.len(), 1, "{}", apart::why_stopped(status));
    assert!(said[0].starts_with("refused|"), "{}", said[0]);
    assert!(said[0].contains("finding the pictures"), "{}", said[0]);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// Adds `d` to the end of page 1's annotations.
fn annotate(p: &mut Pdf, d: Dictionary) -> ObjectId {
    let id = p.doc.add_object(d);
    let page = p.page_ids()[0];
    let pd = p.doc.get_dictionary_mut(page).unwrap();
    let mut list = (pd.get(b"Annots")).map_or(Vec::new(), |a| a.as_array().unwrap().clone());
    list.push(id.into());
    pd.set("Annots", list);
    id
}

/// `n` freehand drawings on page 1 of `p`, without drawings of their own, sharing one
/// 10,000-point stroke zigzagging from (100, 200) to (299, 250). Their `/Rect` has no area
/// (at 100, 200), so each is placed where it is drawn (PB-114).
fn shared_strokes(p: &mut Pdf, n: usize) -> Vec<ObjectId> {
    let stroke: Vec<Object> = (0..10_000i64)
        .flat_map(|i| [100 + i % 200, 200 + i % 2 * 50].map(Object::from))
        .collect();
    let stroke = p.doc.add_object(stroke);
    let rect = [100i64, 200, 100, 200].map(Object::from).to_vec();
    (0..n)
        .map(|_| {
            let d = dictionary! {
                "Type" => "Annot", "Subtype" => "Ink", "Rect" => rect.clone(),
                "InkList" => vec![Object::Reference(stroke)], "C" => vec![Object::from(0i64)],
            };
            annotate(p, d)
        })
        .collect()
}

/// Drawing annotations has a budget (WP-04 step 5): 20 drawings sharing one 10,000-point
/// stroke draw it 20 times, and flattening them past the budget is refused, with nothing
/// changed; within it, they are drawn. Each was drawn, however many shared the stroke.
#[test]
fn annotations_too_complex_to_draw_aren_t_flattened() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    shared_strokes(&mut p, 20);
    common::seeds::pdf(&p);
    let before = p.state_before();
    let (e, _) = budget_seam::with_limit(100_000, || p.flatten_annotations(None));
    let e = e.expect_err("refused");
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.what, "drawing the annotations", "{e:#}");
    assert_eq!(p.state_since(&before), []);
    let (done, _) = budget_seam::with_limit(4_000_000, || p.flatten_annotations(None));
    assert_eq!(done.unwrap().drawn, 20);
}

/// Listing annotations draws those placed where they are drawn (PB-114) within one budget,
/// and lists those past it at their own `/Rect` rather than leave them out: the first are
/// placed where they are drawn, the rest at (100, 200), 592 down the page.
#[test]
fn annotations_past_the_drawing_budget_are_listed_at_their_own_box() {
    use limarepdf_core::{budget_seam, Annot};
    let mut p = zebras(1);
    shared_strokes(&mut p, 20);
    let own = |a: &Annot| a.bbox == [100.0, 592.0, 100.0, 592.0];
    for limit in [u64::MAX, 500_000] {
        let (all, _) = budget_seam::with_limit(limit, || p.annotations());
        let (page, _) = budget_seam::with_limit(limit, || p.page_annotations(0).unwrap());
        for listed in [all, page] {
            assert_eq!(listed.len(), 20);
            let drawn = listed.iter().take_while(|a| !own(a)).count();
            assert!(listed[drawn..].iter().all(own), "{limit}");
            if limit == u64::MAX {
                assert_eq!(drawn, 20);
            } else {
                assert!((1..20).contains(&drawn), "{drawn} drawn within {limit}");
            }
        }
    }
}

/// A text box's text is charged to drawing it: 20 text boxes sharing one 20,004-character
/// text set it 20 times, and flattening them past the budget is refused, with nothing
/// changed. Each was set, however many shared the text.
#[test]
fn text_boxes_sharing_a_long_text_are_charged_it_each() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    let text = p
        .doc
        .add_object(Object::string_literal("zebra ".repeat(3_334)));
    let rect = [72i64, 400, 300, 500].map(Object::from).to_vec();
    for _ in 0..20 {
        let d = dictionary! {
            "Type" => "Annot", "Subtype" => "FreeText", "Rect" => rect.clone(),
            "Contents" => text, "DA" => Object::string_literal("/Helv 12 Tf 0 g"),
        };
        annotate(&mut p, d);
    }
    let before = p.state_before();
    let (e, _) = budget_seam::with_limit(200_000, || p.flatten_annotations(None));
    let e = e.expect_err("refused");
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.what, "drawing the annotations", "{e:#}");
    assert_eq!(p.state_since(&before), []);
    let (done, _) = budget_seam::with_limit(2_000_000, || p.flatten_annotations(None));
    assert_eq!(done.unwrap().drawn, 20);
}

/// How many annotations of the one-page `bytes` have a drawing.
fn with_drawings(bytes: &[u8]) -> usize {
    let p = Pdf::from_bytes(bytes, None).unwrap();
    let page = p.doc.get_dictionary(p.page_ids()[0]).unwrap();
    let list = page.get(b"Annots").and_then(Object::as_array).unwrap();
    let drawn = |id| p.doc.get_dictionary(id).unwrap().has(b"AP");
    (list.iter())
        .filter(|a| drawn(a.as_reference().unwrap()))
        .count()
}

/// Showing a document draws the annotations without drawings of their own within the
/// budget and leaves those past it without one, as other readers show them, rather than
/// not show it: the app's pages, and the page under text being edited, draw the first
/// and not the rest.
#[test]
fn a_document_with_annotations_past_the_drawing_budget_is_still_shown() {
    use limarepdf_core::budget_seam;
    let mut p = zebras(1);
    shared_strokes(&mut p, 20);
    for limit in [u64::MAX, 500_000] {
        let (app, _) = budget_seam::with_limit(limit, || p.app_snapshot());
        let (page, _) = budget_seam::with_limit(limit, || p.page_without(0, &[]));
        for shown in [app, page] {
            let drawn = with_drawings(&shown.unwrap());
            if limit == u64::MAX {
                assert_eq!(drawn, 20);
            } else {
                assert!((1..20).contains(&drawn), "{drawn} drawn within {limit}");
            }
        }
    }
}

/// Redacting draws the annotations placed where they are drawn (PB-114) to find those the
/// marks cover, within the budget; past it the redaction is refused, with nothing changed,
/// rather than miss one.
#[test]
fn a_redaction_over_annotations_too_complex_to_draw_changes_nothing() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    shared_strokes(&mut p, 20);
    let before = p.state_before();
    let mark = [(0, [150.0, 500.0, 160.0, 600.0])];
    let (e, _) = budget_seam::with_limit(100_000, || p.redact(&mark));
    let e = e.expect_err("refused");
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.what, "drawing the annotations", "{e:#}");
    assert_eq!(p.state_since(&before), []);
    let (done, _) = budget_seam::with_limit(4_000_000, || p.redact(&mark));
    assert_eq!(done.unwrap().pages[0].annots, 20);
}

/// An annotation placed where it is drawn (PB-114) is moved from there; past the budget
/// moving it is refused, with nothing changed.
#[test]
fn moving_an_annotation_too_complex_to_draw_is_refused() {
    use limarepdf_core::{budget_seam, TooComplex};
    let mut p = zebras(1);
    let id = shared_strokes(&mut p, 1)[0];
    let before = p.state_before();
    let to = [10.0, 10.0, 50.0, 50.0];
    let (e, _) = budget_seam::with_limit(1_000, || p.move_annotation(0, id, to));
    let e = e.expect_err("refused");
    let too = e.downcast_ref::<TooComplex>().expect("too complex");
    assert_eq!(too.what, "drawing the annotations", "{e:#}");
    assert_eq!(p.state_since(&before), []);
}
