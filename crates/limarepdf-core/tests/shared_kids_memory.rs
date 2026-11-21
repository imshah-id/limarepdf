//! The memory opening a file takes whose page list nodes share a list with pages written
//! in it (`repair.rs`'s `mend_page_tree`), measured by a counting allocator, in a file of
//! its own as the count is the whole process's. Each node takes its own copy of the list,
//! and a file whose copies would take more than 64 MiB is refused.

use limarepdf_core::Pdf;
use lopdf::{dictionary, Dictionary, Document, Object};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// The heap's live bytes, and the most since last set, counted on every allocation as
/// glibc's malloc takes it, the same on every system.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// What glibc's malloc takes for `n` bytes on a 64-bit system: the bytes and an 8-byte
/// header, in 16-byte steps, at least 32 (a large allocation's page rounding left out). A
/// tiny key or name takes 32 bytes, not its length.
fn taken(n: usize) -> usize {
    (n + 8).next_multiple_of(16).max(32)
}

fn grew(by: usize) {
    let now = LIVE.fetch_add(taken(by), Relaxed) + taken(by);
    PEAK.fetch_max(now, Relaxed);
}

fn shrank(by: usize) {
    LIVE.fetch_sub(taken(by), Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            grew(l.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            grew(l.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        shrank(l.size());
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        let q = System.realloc(p, l, size);
        if !q.is_null() {
            grew(size);
            shrank(l.size());
        }
        q
    }
}

#[global_allocator]
static HEAP: Counting = Counting;

/// The most the copies may take between them, as `repair.rs`'s `MAX_SHARED_KIDS_COPIES`.
const MAX_COPIES: usize = 64 << 20;

/// A file whose root lists `k` nodes, each listing one list object holding the pages written
/// in it, `pages`.
fn file(k: usize, pages: &[Dictionary]) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let kids: Vec<Object> = pages.iter().cloned().map(Object::Dictionary).collect();
    let list = doc.add_object(kids);
    let nodes: Vec<Object> = (0..k)
        .map(|_| {
            let media_box: Vec<Object> = vec![0.into(), 0.into(), 200.into(), 100.into()];
            let node = dictionary! { "Type" => "Pages", "Kids" => list, "MediaBox" => media_box };
            doc.add_object(node).into()
        })
        .collect();
    let root = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => nodes });
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => root });
    doc.trailer.set("Root", catalog);
    let mut b = Vec::new();
    doc.save_to(&mut b).unwrap();
    b
}

/// Whether `k` nodes sharing a list holding `pages` open, and the most heap opening them
/// took over what it began with. A file not opened must be refused as too complex.
fn opening(k: usize, pages: &[Dictionary]) -> (bool, usize) {
    let bytes = file(k, pages);
    let start = LIVE.load(Relaxed);
    PEAK.store(start, Relaxed);
    let opened = Pdf::from_bytes(&bytes, None).map(|pdf| pdf.page_count());
    let peak = PEAK.load(Relaxed) - start;
    match &opened {
        Ok(n) => assert_eq!(*n, k * pages.len()),
        Err(e) => assert!(format!("{e:#}").contains("too complex"), "{k}: {e:#}"),
    }
    (opened.is_ok(), peak)
}

/// The most nodes sharing a list holding `pages` that open, at most 63, and how much more
/// heap opening that many takes than opening two.
fn most_opened(pages: &[Dictionary]) -> (usize, usize) {
    let (opened, two) = opening(2, pages);
    assert!(opened);
    let (mut lo, mut hi) = (2, 4);
    while opening(hi, pages).0 {
        assert!(hi < 64, "{hi} nodes open");
        (lo, hi) = (hi, hi * 2);
    }
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if opening(mid, pages).0 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (lo, opening(lo, pages).1.saturating_sub(two))
}

/// A page holding `key` too.
fn page_with(key: &str, value: Object) -> Dictionary {
    dictionary! { "Type" => "Page", key => value }
}

#[test]
fn copies_of_a_shared_list_take_no_more_than_their_budget() {
    // Each case's copies are charged near what they take: the nodes that open take at most
    // 64 MiB over two nodes, and at least half that. A page of 20,000 small entries took 1.9
    // times what it was charged: 27 nodes opened, taking 114 MiB more than two. 2,000 pages
    // of one entry took 1.4 times (49 nodes, 92 MiB): each copy's place among the document's
    // objects and its `/Parent` weren't charged (review 9's #6). Pages of three entries check
    // that a copy's room to grow to hold a fourth is charged, and 10,000 one-letter names that
    // each is charged the 32 bytes malloc takes for it.
    let mut many = Dictionary::new();
    many.set("Type", "Page");
    for i in 0..20_000 {
        many.set(format!("k{i}"), Object::Name(b"x".to_vec()));
    }
    let string = page_with("Text", Object::string_literal(vec![b'a'; 4 << 20]));
    let integers = (0..30_000).map(Object::Integer).collect::<Vec<_>>();
    let array = page_with("Junk", integers.into());
    let letters = vec![Object::Name(b"x".to_vec()); 10_000];
    let names = page_with("Junk", letters.into());
    let small = vec![dictionary! { "Type" => "Page" }; 2_000];
    let three = vec![dictionary! { "Type" => "Page", "Rotate" => 0, "UserUnit" => 1 }; 1_000];
    let mb = |n: usize| n as f64 / (1 << 20) as f64;
    let cases = [
        ("entries", vec![many]),
        ("string", vec![string]),
        ("array", vec![array]),
        ("names", vec![names]),
        ("small pages", small),
        ("pages of three entries", three),
    ];
    for (case, pages) in cases {
        let (k, took) = most_opened(&pages);
        println!("{case}: {k} nodes open, {:.1} MiB over two", mb(took));
        assert!(
            (MAX_COPIES / 2..=MAX_COPIES).contains(&took),
            "{case}: {k} nodes open, {:.1} MiB over two",
            mb(took)
        );
    }
}
