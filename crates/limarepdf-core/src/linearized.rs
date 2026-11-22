//! Linearized files: where Poppler and pdf.js read a file otherwise than lopdf because its
//! first object is a linearization parameter dictionary.
//!
//! When that dictionary's `/L` is the file's length, both apps read the cross-references
//! from just after the object's `endobj`, not from the last `startxref`. pdf.js then opens
//! the first page at `/O` and counts `/N` pages. Poppler, the newest section a table, looks
//! up a number that section doesn't list in the main table at `/T`, row by row, and when its
//! hint tables read cleanly it takes each page at the number they give, without the entries
//! a page inherits. lopdf reads none of this, so a signed file could show other pages there
//! than LimarePDF checked.

use crate::doc::pages;
use crate::sig_changes::{
    decode_name, decodes_alike, header_id, read_object, skipped, word_num, Entry, Reading,
    MAX_OBJECT_STREAM,
};
use crate::sig_verify::{is_white, Lexer, Tok};
use crate::unfillable::inherited_at;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

const MAY: &str = "they may read it as a linearized file";
const HINTS: &str = "they may read its hint tables otherwise";
const HINTED_MAY: &str = "they may take its pages from its hint tables at objects read otherwise";

/// The parameters Poppler and pdf.js take from a file's first object: `None` for an app that
/// doesn't take the file as linearized.
pub(crate) struct Linearized {
    poppler: Option<Poppler>,
    pdfjs: Option<PdfJs>,
}

/// Poppler's parameters as its `lookupInt` gives them, 0 where it takes none: a whole number
/// above 0 that fits 32 bits. `/P` is a page below `/N`, or 0; `h` the hint streams' offsets
/// and lengths.
struct Poppler {
    h: [i32; 4],
    o: i32,
    n: i32,
    t: i32,
    p: i32,
}

/// pdf.js's: the first page's object `o` and page number `p`, and the page count `n`.
struct PdfJs {
    o: i64,
    n: i64,
    p: i64,
}

/// The parameters each app takes from `whole`, the file, whose header is at `start`. Fails
/// when they may take it as linearized in a way this doesn't follow.
pub(crate) fn params(whole: &[u8], start: usize) -> Result<Linearized, String> {
    let len = whole.len();
    let head = len.min(1024);
    // Poppler reads the first object from the header on, pdf.js from past its version, when
    // the header is near enough the start.
    let poppler_at = if start + 6 <= head { start } else { 0 };
    let pdfjs_at = if start + 5 <= head {
        let k = (whole[start + 5..].iter())
            .take(7)
            .take_while(|&&c| c > b' ')
            .count();
        (start + 5 + k + 1).min(len)
    } else {
        0
    };
    let (p_at, j_at) = (token_start(whole, poppler_at), token_start(whole, pdfjs_at));
    let p_dict = first_object(whole, p_at)?;
    let j_dict = match j_at == p_at {
        true => None,
        false => Some(first_object(whole, j_at)?),
    };
    let j_dict = j_dict.as_ref().map_or(p_dict.as_ref(), Option::as_ref);
    let [p_dict, j_dict] = [p_dict.as_ref(), j_dict].map(|d| d.filter(|d| positive(d)));
    let both = || [p_dict, j_dict].into_iter().flatten();
    let int = |d: &Dictionary, k: &[u8]| match d.get(k) {
        Ok(Object::Integer(n)) => Some(*n),
        _ => None,
    };
    if both().any(|d| matches!(d.get(b"L"), Ok(Object::Real(_)))) {
        return Err(MAY.into());
    }
    // lopdf's offsets count from the header; the apps' may count from the file's start.
    if start > 0 {
        let lengths = [len, len - start].map(|l| i64::try_from(l).ok());
        if both().any(|d| int(d, b"L").is_some_and(|l| lengths.contains(&Some(l)))) {
            return Err(format!("{MAY}, its offsets counted from another place"));
        }
        return Ok(Linearized {
            poppler: None,
            pdfjs: None,
        });
    }
    let len = i64::try_from(len).unwrap_or(i64::MAX);
    let hints = |d: &Dictionary| match d.get(b"H") {
        Ok(Object::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    for d in both().filter(|d| int(d, b"L") == Some(len)) {
        let named = [&b"O"[..], b"E", b"N", b"T", b"P"].map(|k| d.get(k).ok());
        if (hints(d).iter().chain(named.into_iter().flatten()))
            .any(|o| matches!(o, Object::Real(_)))
        {
            return Err(MAY.into());
        }
    }
    let poppler = p_dict
        .filter(|d| int(d, b"L").is_some_and(|l| l == len && l <= i64::from(i32::MAX)))
        .map(|d| {
            let look = |o: Option<&Object>| match o {
                Some(Object::Integer(n)) => i32::try_from(*n).ok().filter(|n| *n > 0).unwrap_or(0),
                _ => 0,
            };
            let h = hints(d);
            let n = look(d.get(b"N").ok());
            let p = match d.get(b"P") {
                Ok(Object::Integer(p)) => i32::try_from(*p).ok().filter(|p| (0..n).contains(p)),
                _ => None,
            };
            Poppler {
                h: std::array::from_fn(|i| {
                    let need = if i < 2 { 2 } else { 4 };
                    look(h.get(i).filter(|_| h.len() >= need))
                }),
                o: look(d.get(b"O").ok()),
                n,
                t: look(d.get(b"T").ok()),
                p: p.unwrap_or(0),
            }
        });
    let pdfjs = j_dict
        .filter(|d| {
            let h = hints(d);
            int(d, b"L") == Some(len)
                && matches!(h.len(), 2 | 4)
                && h.iter().all(|o| matches!(o, Object::Integer(n) if *n > 0))
                && ([&b"O"[..], b"E", b"N", b"T"].into_iter())
                    .all(|k| int(d, k).is_some_and(|n| n > 0))
                && (!d.has(b"P") || int(d, b"P").is_some_and(|p| p >= 0))
        })
        .map(|d| PdfJs {
            o: int(d, b"O").unwrap_or(0),
            n: int(d, b"N").unwrap_or(0),
            p: int(d, b"P").unwrap_or(0),
        });
    Ok(Linearized { poppler, pdfjs })
}

/// Whether `d`'s `/Linearized` is positive, as the apps take it.
fn positive(d: &Dictionary) -> bool {
    match d.get(b"Linearized") {
        Ok(Object::Integer(n)) => *n > 0,
        // Never NaN: a real reads as digits.
        Ok(Object::Real(r)) => *r >= 0.0,
        _ => false,
    }
}

/// Where the token the apps read from `at` starts: past white space and comments.
fn token_start(bytes: &[u8], at: usize) -> usize {
    let mut lx = Lexer::new(bytes, at);
    match lx.next() {
        Some((start, _, _)) => start,
        None => lx.pos(),
    }
}

/// The dictionary of the object at `at`, when one is there as both apps and LimarePDF read
/// it: `N G obj <<`. Fails when the apps may read a dictionary there otherwise and some name
/// in the file from `at` on may be `/Linearized`.
fn first_object(bytes: &[u8], at: usize) -> Result<Option<Dictionary>, String> {
    let mut lx = Lexer::new(bytes, at);
    let t: [_; 3] = std::array::from_fn(|_| lx.next());
    if !t.iter().all(|t| matches!(t, Some((_, Tok::Word(_), _)))) {
        return Ok(None);
    }
    // No app reads a word that can't start a number as one.
    if matches!(whole::<i32>(t[0]), Whole::No) {
        return Ok(None);
    }
    let clean = word_num::<i32>(t[0]).is_some()
        && word_num::<i32>(t[1]).is_some()
        && matches!(t[2], Some((_, Tok::Word(b"obj"), _)));
    if clean {
        if !matches!(lx.clone().next(), Some((_, Tok::DictOpen, _))) {
            return Ok(None);
        }
        match read_object(&mut lx, 0) {
            Some(Object::Dictionary(d)) => return Ok(Some(d)),
            Some(_) => return Ok(None),
            None => {}
        }
    }
    may_name_linearized(bytes, at)
}

/// Fails when a name in `bytes` from `at` on, read token by token, may be `/Linearized`.
/// Where a token doesn't read, the walk goes on past its first byte; it stops at a string
/// that is never ended, which the apps read to the end.
fn may_name_linearized(bytes: &[u8], at: usize) -> Result<Option<Dictionary>, String> {
    let mut lx = Lexer::new(bytes, at);
    loop {
        match lx.next() {
            Some((_, Tok::Name(n), _)) => {
                if decode_name(n).is_none_or(|n| n == b"Linearized") {
                    return Err(MAY.into());
                }
            }
            Some(_) => {}
            None => {
                let p = lx.pos();
                let next = match bytes.get(p) {
                    None | Some(b'(') => return Ok(None),
                    Some(b'<') => {
                        let run = (bytes[p + 1..].iter())
                            .take_while(|&&c| c.is_ascii_hexdigit() || is_white(c))
                            .count();
                        p + 1 + run
                    }
                    Some(_) => p + 1,
                };
                lx = Lexer::new(bytes, next);
            }
        }
    }
}

impl Linearized {
    /// Whether either app takes the file as linearized.
    fn taken(&self) -> bool {
        self.poppler.is_some() || self.pdfjs.is_some()
    }

    /// Fails when the apps read the cross-references, of `bytes` from the header on, from
    /// elsewhere than `at`, where lopdf reads them: they read them from just after the first
    /// `endobj` in the first 1,024 bytes.
    pub(crate) fn starts_alike(&self, bytes: &[u8], at: usize) -> Result<(), String> {
        if !self.taken() {
            return Ok(());
        }
        let head = &bytes[..bytes.len().min(1024)];
        let Some(e) = head.windows(6).position(|w| w == b"endobj") else {
            return Err(
                "they look for its cross-references after its first object, which \
                 doesn't end in its first 1,024 bytes"
                    .into(),
            );
        };
        if token_start(bytes, e + 6) != token_start(bytes, at) {
            return Err("they read its cross-references from where its first object ends".into());
        }
        Ok(())
    }

    /// Whether Poppler looks a number up in the main table at `/T` when the newest section
    /// doesn't list it: it takes the file as linearized, the newest section a table.
    pub(crate) fn t_mode(&self, newest_table: bool) -> bool {
        newest_table && self.poppler.as_ref().is_some_and(|p| p.t > 0)
    }

    /// In T-mode, adds to `unsure` each number Poppler may read otherwise than `spec` gives it:
    /// one below `size_lo` the newest section doesn't list reads from its row at `/T`, 20
    /// bytes each, and one past the file's end or at `size_lo` or above reads as free.
    pub(crate) fn main_rows(
        &self,
        bytes: &[u8],
        spec: &HashMap<u32, Entry>,
        newest: &HashSet<u32>,
        size_lo: u64,
        unsure: &mut HashSet<u32>,
    ) {
        let Some(t) = (self.poppler.as_ref()).and_then(|p| usize::try_from(p.t).ok()) else {
            return;
        };
        let rows = bytes.len().saturating_sub(t).div_ceil(20);
        let read = u64::try_from(rows).map_or(size_lo, |r| r.min(size_lo));
        for num in (0..read).map_while(|i| u32::try_from(i).ok()) {
            if newest.contains(&num) {
                continue;
            }
            let at = t + 20 * num as usize;
            let (Ok(row) | Err(row)) = read_row(&bytes[at..bytes.len().min(at + 20)]);
            let agrees = match (row, spec.get(&num)) {
                (Row::Missing | Row::Free, None | Some(Entry::Free)) => true,
                (Row::InUse(o, g), Some(&Entry::InUse { offset, gen })) => {
                    i64::try_from(offset) == Ok(o) && i32::from(gen) == g
                }
                _ => false,
            };
            if !agrees {
                unsure.insert(num);
            }
        }
        for (&num, e) in spec {
            let listed = matches!(e, Entry::InUse { .. } | Entry::Compressed { .. });
            if listed && u64::from(num) >= read && !newest.contains(&num) {
                unsure.insert(num);
            }
        }
    }

    /// Fails when the apps take the pages of `bytes`, lopdf's `doc` read as `r`, otherwise
    /// than LimarePDF: they count another number of them, pdf.js opens the first at another
    /// object, or Poppler takes them from its hint tables. `sizes` is from the size Poppler
    /// has reading the newest section to the largest it may grow to reading older ones.
    /// Adds to `r.unsure` what Poppler may read otherwise along the way.
    pub(crate) fn check(
        &self,
        bytes: &[u8],
        doc: &Document,
        r: &mut Reading,
        sizes: Range<u64>,
        encrypted: bool,
    ) -> Result<(), String> {
        if !self.taken() {
            return Ok(());
        }
        let count = pages(doc).count();
        let poppler_n = (self.poppler.as_ref())
            .map(|p| i64::from(p.n))
            .filter(|&n| n > 0);
        for n in poppler_n
            .into_iter()
            .chain(self.pdfjs.as_ref().map(|j| j.n))
        {
            if usize::try_from(n).ok() != Some(count) {
                return Err(format!("they count {n} pages in it"));
            }
        }
        if let Some(j) = &self.pdfjs {
            if usize::try_from(j.p).is_ok_and(|p| p < count) && j.first_page_differs(bytes, doc, r)
            {
                return Err("they open its first page at another object".into());
            }
        }
        match &self.poppler {
            Some(p) => p.hinted_pages(bytes, doc, r, &sizes, encrypted),
            None => Ok(()),
        }
    }
}

impl Poppler {
    /// Fails when Poppler may take the pages of `bytes` from its hint tables otherwise than
    /// the page tree gives them; see [`Linearized::check`].
    fn hinted_pages(
        &self,
        bytes: &[u8],
        doc: &Document,
        r: &mut Reading,
        sizes: &Range<u64>,
        encrypted: bool,
    ) -> Result<(), String> {
        let t_mode = r.table && self.t > 0;
        // Outside T-mode, Poppler looks up the first page's object first, or object 0 when
        // the number is past its size.
        if !t_mode {
            let o = self.o.unsigned_abs();
            if o > 0 && sizes.contains(&u64::from(o)) {
                return Err(MAY.into());
            }
            let x = if u64::from(o) >= sizes.end { 0 } else { o };
            if r.table && !r.spec.contains_key(&x) && u64::from(x) < sizes.end {
                return Err(skipped(x));
            }
        }
        let Some(nums) = self.hint_tables(bytes, doc, r, sizes, t_mode, encrypted)? else {
            return Ok(());
        };
        // It takes each page where the tables say, until one it can't take as a page:
        // then it reads every page from the page tree.
        let mut hinted = Vec::new();
        for p in 1..=nums.len() {
            let num = match self.page_object_num(&nums, p) {
                n @ 1.. => n.unsigned_abs(),
                _ => return Ok(()),
            };
            let n = u64::from(num);
            if (t_mode && n >= sizes.start) || n >= sizes.end {
                return Ok(());
            }
            if sizes.contains(&n) {
                return Err(HINTED_MAY.into());
            }
            let gen = match r.spec.get(&num) {
                Some(&Entry::InUse { gen, .. }) => gen,
                Some(Entry::Compressed { .. }) => 0,
                _ => return Err(HINTED_MAY.into()),
            };
            let id = (num, gen);
            let Some(o) = held(doc, r, id) else {
                return Err(HINTED_MAY.into());
            };
            let page = match o {
                Object::Dictionary(d) => {
                    matches!(d.get(b"Type"), Ok(Object::Name(n)) if n == b"Page")
                }
                _ => false,
            };
            if !page {
                return Ok(());
            }
            hinted.push(id);
        }
        let inherits = |id: ObjectId| {
            [&b"MediaBox"[..], b"CropBox", b"Rotate", b"Resources"]
                .into_iter()
                .any(|k| inherited_at(doc, id, k).is_some_and(|(at, _)| at != id))
        };
        if !pages(doc).eq(hinted.iter().copied()) || hinted.iter().any(|&id| inherits(id)) {
            return Err(
                "they take its pages from its hint tables, which give other pages or \
                 none of what they inherit"
                    .into(),
            );
        }
        Ok(())
    }

    /// Poppler's `getPageObjectNum`: page `p`'s object as the hint tables' `nums` give it, the
    /// first page `/P` at `/O`, or 0.
    fn page_object_num(&self, nums: &[i32], p: usize) -> i32 {
        let first = usize::try_from(self.p).unwrap_or(0);
        let at = match (p - 1).cmp(&first) {
            std::cmp::Ordering::Greater => p - 1,
            std::cmp::Ordering::Less => p,
            std::cmp::Ordering::Equal => 0,
        };
        nums.get(at).copied().unwrap_or(0)
    }

    /// The page objects Poppler's hint tables give, each page's but the first counted on
    /// from object 1, or `None` when it doesn't take the tables. Fails when it may read the
    /// hint stream otherwise than this follows. When it may not read the stream at all, adds
    /// it, and what it holds, to `r.unsure`.
    fn hint_tables(
        &self,
        bytes: &[u8],
        doc: &Document,
        r: &mut Reading,
        sizes: &Range<u64>,
        t_mode: bool,
        encrypted: bool,
    ) -> Result<Option<Vec<i32>>, String> {
        let [h0, h1, _, h3] = self.h.map(i32::unsigned_abs).map(|h| h as usize);
        if h3 > 0 {
            return Err(HINTS.into());
        }
        let Some(buf) = bytes.get(h0..h0 + h1).filter(|_| h0 > 0 && h1 > 0) else {
            return Ok(None);
        };
        let mut lx = Lexer::new(buf, 0);
        let mut id = [0i32; 2];
        for n in &mut id {
            match whole(lx.next()) {
                Whole::Fits(v) => *n = v,
                Whole::Odd => return Err(HINTS.into()),
                Whole::Big | Whole::No => return Ok(None),
            }
        }
        if !matches!(lx.next(), Some((_, Tok::Word(b"obj"), _))) {
            return Ok(None);
        }
        let dict = match read_object(&mut lx, 0) {
            Some(Object::Dictionary(d)) => d,
            Some(_) => return Ok(None),
            None => return Err(HINTS.into()),
        };
        let Some((_, Tok::Word(b"stream"), keyword)) = lx.next() else {
            return Ok(None);
        };
        // Poppler now makes the stream, looking up its object first.
        let num = id[0].unsigned_abs();
        if !t_mode && r.table && !r.spec.contains_key(&num) && u64::from(num) < sizes.end {
            return Err(skipped(num));
        }
        // It takes the length from the object a reference names, as lopdf holds it when
        // they read that object alike.
        let length = match dict.get(b"Length") {
            Ok(&Object::Reference(id)) => Some(held(doc, r, id).ok_or(HINTS)?),
            length => length.ok(),
        };
        let Some(data) = stream_data(buf, keyword, length)? else {
            r.unsure.insert(num);
            let held = r.spec.iter().filter_map(|(&n, e)| {
                matches!(e, Entry::Compressed { container, .. } if *container == num).then_some(n)
            });
            r.unsure.extend(held);
            return Ok(None);
        };
        let s = match dict.get(b"S") {
            Ok(Object::Reference(_)) => return Err(HINTS.into()),
            Ok(&Object::Integer(s)) if (1..=i64::from(i32::MAX)).contains(&s) => s as usize,
            _ => return Ok(None),
        };
        // It decrypts the data as the object its header names. lopdf holds that decrypted when
        // the cross-references list the object here and they read it alike.
        let data = match encrypted {
            false => data.to_vec(),
            true => {
                let gen = u16::try_from(id[1]).map_err(|_| HINTS)?;
                let here = match r.spec.get(&num) {
                    Some(&Entry::InUse { offset, .. }) => {
                        token_start(bytes, offset) == token_start(bytes, h0)
                    }
                    _ => false,
                };
                match held(doc, r, (num, gen)).filter(|_| here) {
                    Some(Object::Stream(s)) => s.content.clone(),
                    _ => return Err(HINTS.into()),
                }
            }
        };
        let stream = Stream::new(dict, data);
        if !decodes_alike(&stream, MAX_OBJECT_STREAM) {
            return Err(HINTS.into());
        }
        let Ok(plain) = stream.get_plain_content_with_limit(MAX_OBJECT_STREAM) else {
            return Err(HINTS.into());
        };
        let pages = if self.n >= i32::MAX / 4 { 0 } else { self.n };
        let Some(nums) = page_offsets(&plain, pages, self.o) else {
            return Ok(None);
        };
        Ok(shared_objects(plain.get(s..).unwrap_or_default()).then_some(nums))
    }
}

/// The data of the stream `length` long whose keyword `stream` ends at `keyword` in `buf`,
/// as Poppler reads it: `None` when it can't. Fails when it may read it otherwise.
fn stream_data<'a>(
    buf: &'a [u8],
    keyword: usize,
    length: Option<&Object>,
) -> Result<Option<&'a [u8]>, String> {
    let eol = (buf[keyword..].iter()).position(|&c| c == b'\n' || c == b'\r');
    let Some(eol) = eol.map(|i| keyword + i) else {
        return Ok(None);
    };
    let start = eol + 1 + usize::from(buf[eol..].starts_with(b"\r\n"));
    let length = match length {
        Some(&Object::Integer(n)) => usize::try_from(n).ok().filter(|&n| n <= buf.len() - start),
        _ => None,
    };
    let Some(length) = length else {
        return Ok(None);
    };
    match Lexer::new(buf, start + length).next() {
        Some((_, Tok::Word(b"endstream"), _)) => Ok(Some(&buf[start..start + length])),
        Some((_, Tok::Word(w), _)) if w.starts_with(b"endstream") => Err(HINTS.into()),
        _ => Ok(None),
    }
}

/// The object lopdf holds at `id` when the apps find the same there: the cross-references
/// list it with that generation, and the readings agree on it.
fn held<'a>(doc: &'a Document, r: &Reading, id: ObjectId) -> Option<&'a Object> {
    let listed = match r.spec.get(&id.0) {
        Some(&Entry::InUse { gen, .. }) => gen == id.1,
        Some(Entry::Compressed { .. }) => id.1 == 0,
        _ => false,
    };
    let agree = listed && !r.hidden.contains(&id) && !r.unsure.contains(&id.0);
    doc.objects.get(&id).filter(|_| agree)
}

/// Poppler's `readPageOffsetTable` on `data`, for `pages` pages, the first at object
/// `first`: each page's object, or `None` when it fails.
fn page_offsets(data: &[u8], pages: i32, first: i32) -> Option<Vec<i32>> {
    let pages = usize::try_from(pages).ok().filter(|&n| n >= 1)?;
    let mut b = Bits::new(data);
    let least = b.read(32);
    b.read(32);
    let diff_objects = b.read(16);
    if least == 0 || diff_objects > 32 {
        return None;
    }
    let [_, page_length, _, offset_stream, _, length_stream] =
        [32, 16, 32, 16, 32, 16].map(|n| b.read(n));
    let [num_shared, shared, numerator, _] = [16; 4].map(|n| b.read(n));
    let widths = [
        page_length,
        offset_stream,
        length_stream,
        num_shared,
        shared,
        numerator,
    ];
    if widths.into_iter().any(|w| w > 32) {
        return None;
    }
    let mut objects = Vec::new();
    for _ in 0..pages {
        objects.push(least.wrapping_add(b.read(diff_objects)));
        if b.eof {
            return None;
        }
    }
    objects[0] = 0;
    let mut num = 1i32;
    let mut nums: Vec<i32> = (objects.iter())
        .map(|&k| {
            let at = num;
            num = num.wrapping_add_unsigned(k);
            at
        })
        .collect();
    nums[0] = first;
    b.reset();
    b.skip(pages as u64 * u64::from(page_length));
    if b.eof {
        return None;
    }
    b.reset();
    b.read(num_shared);
    let mut shared_ids = 0u64;
    for _ in 1..pages {
        if b.eof {
            break;
        }
        let k = b.read(num_shared);
        if k >= 536_870_911 {
            return None;
        }
        shared_ids += u64::from(k);
    }
    if b.eof {
        return None;
    }
    b.reset();
    b.skip(shared_ids * u64::from(shared));
    (!b.eof).then_some(nums)
}

/// Poppler's `readSharedObjectsTable` on `data`: whether it succeeds.
fn shared_objects(data: &[u8]) -> bool {
    let mut b = Bits::new(data);
    let [_, _, first, groups] = [32; 4].map(|n| b.read(n));
    let num_objects = b.read(16);
    b.read(32);
    let diff_length = b.read(16);
    if groups == 0 || groups >= 536_870_911 || first == 0 || first > groups {
        return false;
    }
    if num_objects > 32 || diff_length > 32 {
        return false;
    }
    let groups = u64::from(groups);
    b.reset();
    b.skip(groups * u64::from(diff_length));
    if b.eof {
        return false;
    }
    b.reset();
    let signed = b.ones(groups);
    if b.eof {
        return false;
    }
    b.reset();
    b.skip(signed * 4 * 32);
    if b.eof {
        return false;
    }
    b.reset();
    b.skip(groups * u64::from(num_objects));
    !b.eof
}

/// Poppler's `StreamBitReader`: bits from each byte's highest on.
struct Bits<'a> {
    data: &'a [u8],
    /// The bits read.
    at: u64,
    /// Whether a read went past the end. It stays.
    eof: bool,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            at: 0,
            eof: false,
        }
    }

    fn left(&self) -> u64 {
        self.data.len() as u64 * 8 - self.at
    }

    /// The next `n` bits, at most 32, as a number. Past the end, `u32::MAX`, the rest read.
    fn read(&mut self, n: u32) -> u32 {
        if u64::from(n) > self.left() {
            self.skip(u64::from(n));
            return u32::MAX;
        }
        let mut v = 0;
        for _ in 0..n {
            let byte = self.data[(self.at / 8) as usize];
            v = (v << 1) | u32::from((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        v
    }

    /// Reads `n` bits.
    fn skip(&mut self, n: u64) {
        if n > self.left() {
            self.at = self.data.len() as u64 * 8;
            self.eof = true;
        } else {
            self.at += n;
        }
    }

    /// Reads `n` bits, counting the 1s; 0 past the end.
    fn ones(&mut self, n: u64) -> u64 {
        if n > self.left() {
            self.skip(n);
            return 0;
        }
        // The 1s in the first `i` bits.
        let before = |i: u64| {
            let (whole, rest) = ((i / 8) as usize, i % 8);
            let ones = |b: &u8| u64::from(b.count_ones());
            let part = (rest > 0).then(|| u64::from((self.data[whole] >> (8 - rest)).count_ones()));
            self.data[..whole].iter().map(ones).sum::<u64>() + part.unwrap_or(0)
        };
        let count = before(self.at + n) - before(self.at);
        self.at += n;
        count
    }

    /// Drops the rest of the byte read.
    fn reset(&mut self) {
        self.at = self.at.next_multiple_of(8);
    }
}

impl PdfJs {
    /// Whether pdf.js may open the first page at `/O`'s object where the page tree has
    /// another page `p`, or may read that object otherwise. It takes the page tree's page
    /// when `/O`'s entry gives another generation or leads to another object's header.
    fn first_page_differs(&self, bytes: &[u8], doc: &Document, r: &Reading) -> bool {
        let Ok(o) = u32::try_from(self.o) else {
            return false;
        };
        let entry = r.spec.get(&o).copied();
        if let Some(Entry::InUse { offset, gen }) = entry {
            if gen != 0 || header_id(bytes, offset).is_some_and(|id| id != (o, 0)) {
                return false;
            }
        }
        let held = doc
            .objects
            .get(&(o, 0))
            .filter(|_| !r.hidden.contains(&(o, 0)));
        let listed = matches!(entry, Some(Entry::InUse { .. } | Entry::Compressed { .. }));
        let page = usize::try_from(self.p).ok().and_then(|p| pages(doc).nth(p));
        (listed && held.is_none())
            || r.unsure.contains(&o)
            || held.is_some_and(|x| page_like(doc, x) && page != Some((o, 0)))
    }
}

/// How Poppler reads a main table row.
enum Row {
    /// No entry: the number reads as free.
    Missing,
    /// Digits it may read otherwise than lopdf.
    Unclear,
    Free,
    /// An offset and generation.
    InUse(i64, i32),
}

/// Poppler's reading of `row`, as `Err` when it stops before the row's end.
fn read_row(row: &[u8]) -> Result<Row, Row> {
    let mut lx = Lexer::new(row, 0);
    let offset = row_num::<i64>(lx.next())?;
    let gen = row_num::<i32>(lx.next())?;
    Ok(match lx.next() {
        Some((_, Tok::Word(b"n"), _)) => Row::InUse(offset, gen),
        Some((_, Tok::Word(b"f"), _)) => Row::Free,
        _ => Row::Missing,
    })
}

/// A row's number: digits that fit `T`, unclear for others, missing for no number.
fn row_num<T: std::str::FromStr>(t: Option<(usize, Tok, usize)>) -> Result<T, Row> {
    match whole(t) {
        Whole::Fits(n) => Ok(n),
        Whole::Big | Whole::Odd => Err(Row::Unclear),
        Whole::No => Err(Row::Missing),
    }
}

/// How Poppler may read a token where it wants a whole number.
enum Whole<T> {
    /// Digits that fit `T`.
    Fits(T),
    /// Digits that don't.
    Big,
    /// Other number-like characters it may read otherwise than lopdf.
    Odd,
    /// No number.
    No,
}

fn whole<T: std::str::FromStr>(t: Option<(usize, Tok, usize)>) -> Whole<T> {
    match t {
        Some((_, Tok::Word(w), _)) if w.iter().all(u8::is_ascii_digit) => {
            word_num(t).map_or(Whole::Big, Whole::Fits)
        }
        Some((_, Tok::Word([c, ..]), _)) if c.is_ascii_digit() || b"+-.".contains(c) => Whole::Odd,
        _ => Whole::No,
    }
}

/// Whether pdf.js takes `o` as a page: `/Type /Page`, perhaps through a reference, or no
/// `/Type` or `/Kids` and a `/Contents`.
fn page_like(doc: &Document, o: &Object) -> bool {
    let Object::Dictionary(d) = o else {
        return false;
    };
    let ty = match d.get(b"Type") {
        Ok(Object::Reference(id)) => doc.objects.get(id),
        t => t.ok(),
    };
    match ty {
        Some(Object::Name(n)) => n == b"Page",
        Some(_) => false,
        None => !d.has(b"Kids") && d.has(b"Contents"),
    }
}

#[cfg(test)]
mod tests {
    use super::HINTS;
    use crate::sig_changes::tests::encrypt_with_identity;
    use crate::sig_changes::{compare_reading, Reading};
    use lopdf::{Document, Object, StringFormat, Writer};
    use std::collections::{HashMap, HashSet};

    fn read(b: &[u8]) -> Result<Reading, String> {
        compare_reading(b, &Document::load_mem(b).unwrap())
    }

    /// Bytes being written, with ten-digit numbers filled in at the end: `{name}` in what
    /// [`Asm::put`] writes leaves room for the offset [`Asm::mark`] records under `name`
    /// (`len`: the file's length), `{name+k}` for that plus `k`.
    #[derive(Default)]
    struct Asm {
        out: Vec<u8>,
        holes: Vec<(usize, String)>,
        marks: HashMap<String, usize>,
    }

    impl Asm {
        fn mark(&mut self, name: &str) {
            self.marks.insert(name.into(), self.out.len());
        }

        fn put(&mut self, s: &str) {
            let mut rest = s;
            while let Some((before, after)) = rest.split_once('{') {
                let (name, after) = after.split_once('}').unwrap();
                self.out.extend_from_slice(before.as_bytes());
                self.holes.push((self.out.len(), name.into()));
                self.out.extend_from_slice(b"0000000000");
                rest = after;
            }
            self.out.extend_from_slice(rest.as_bytes());
        }

        fn finish(mut self) -> Vec<u8> {
            self.marks.insert("len".into(), self.out.len());
            for (at, hole) in &self.holes {
                let (name, k) = hole.split_once('+').unwrap_or((hole.as_str(), "0"));
                let n = self.marks[name] + k.parse::<usize>().unwrap();
                self.out[*at..at + 10].copy_from_slice(format!("{n:010}").as_bytes());
            }
            self.out
        }
    }

    /// Page 6 as signed, and the copy of it review round 4 had other apps show.
    const PAGE6: &str =
        "<< /Type /Page /Parent 1 0 R /MediaBox [0 0 595.28 841.89] /Contents 4 0 R \
         /Resources 5 0 R /Annots [8 0 R] >>";
    const ALT6: &str = "<< /Type /Page /Parent 1 0 R /MediaBox [0 0 300 300] /Rotate 90 /Contents \
                        12 0 R /Resources 5 0 R /Annots [8 0 R] >>";

    fn stream(data: &str) -> String {
        format!("<< /Length {} >>\nstream\n{data}\nendstream", data.len())
    }

    /// A linearized file laid out as review round 4's `mk_lin.py` lays it out: the header;
    /// the parameter dictionary as object 20, its `/L` the file's length plus `l` and its `/T`
    /// where the main table's first row starts plus `t`; a first-page section listing object
    /// 0 and `first`, its trailer giving the main section as `/Prev`; `objects`; and the main
    /// section listing 0 to 20. The last `startxref` gives the first-page section or, with
    /// `later`, the main one, followed by a later revision listing object 0 alone.
    #[derive(Clone)]
    struct Lin {
        /// The parameter dictionary's entries past `/Linearized`, `/L` and `/T`.
        params: String,
        /// The numbers the first-page section lists past 0, each with the mark giving its
        /// row's offset: `o{n}` where object `n` is first written, `s{n}` where again.
        first: Vec<(u32, &'static str)>,
        /// Each object's number and what follows `obj`, in order.
        objects: Vec<(u32, String)>,
        /// The trailers' entries past `/Size`. Without an `/ID`, the main and later ones get
        /// one.
        trailer: String,
        /// Whether there is a later revision, and then whether a stray copy of page 6
        /// (`ALT6`) comes before its section.
        later: Option<bool>,
        l: usize,
        t: usize,
        /// What comes before the header.
        junk: &'static str,
        /// The line after the header.
        second: &'static str,
    }

    impl Lin {
        /// `mk_lin.py`'s file `variant`, its later revision too when `later`. Every variant
        /// it names takes the page tree's page 6 at another copy or `/O` another object;
        /// another, such as `plain`, leaves them alone.
        fn round_4(variant: &str, later: bool) -> Lin {
            let o = match variant {
                "o-only" => 11,
                "o-dangling" | "o-missing" => 16,
                _ => 6,
            };
            let n = if variant == "n-three" { 3 } else { 1 };
            let mut objects: Vec<(u32, String)> = vec![
                (
                    7,
                    "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached \
                     /ByteRange [0 0 0 0] /Contents <00> /M (D:20261120000000Z) >>"
                        .into(),
                ),
                (1, "<< /Type /Pages /Kids [6 0 R] /Count 1 >>".into()),
                (
                    2,
                    "<< /Type /Catalog /Pages 1 0 R /AcroForm 9 0 R >>".into(),
                ),
                (
                    3,
                    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
                ),
                (
                    4,
                    stream("BT /F1 24 Tf 72 720 Td (SIGNED PAGE AS LOPDF READS IT) Tj ET"),
                ),
                (5, "<< /Font << /F1 3 0 R >> >>".into()),
                (6, PAGE6.into()),
                (
                    8,
                    "<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /V 7 0 R /T \
                     (Signature1) /F 4 /P 6 0 R >>"
                        .into(),
                ),
                (9, "<< /Fields [8 0 R] /SigFlags 3 >>".into()),
                (10, "<< /Producer (lin-test) >>".into()),
                (12, stream("BT /F1 24 Tf 20 150 Td (ALTERED) Tj ET")),
            ];
            if variant == "o-only" {
                objects.insert(10, (11, ALT6.replace("/Parent 1 0 R ", "")));
            }
            if variant == "alt-in-signed" {
                objects.push((6, ALT6.into()));
            }
            let first = match variant {
                "alt-in-signed" | "alt-in-later" => vec![(6, "s6")],
                "o-dangling" => vec![(16, "o5")],
                "control-reparse" => vec![(6, "o5")],
                _ => vec![],
            };
            let stray = matches!(
                variant,
                "alt-in-later" | "o-dangling" | "o-missing" | "control-reparse"
            );
            Lin {
                params: format!("/H [ 1 1 ] /O {o} /E 1 /N {n}"),
                first,
                objects,
                trailer: "/Root 2 0 R /Info 10 0 R".into(),
                later: later.then_some(stray),
                l: 0,
                t: 0,
                junk: "",
                second: "%âãÏÓ",
            }
        }

        fn build(&self) -> Vec<u8> {
            let id = match self.trailer.contains("/ID") {
                true => "",
                false => {
                    "/ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>]"
                }
            };
            let mut a = Asm::default();
            a.put(&format!("%PDF-1.7\n{}\n", self.second));
            a.put(&format!(
                "20 0 obj\n<< /Linearized 1 /L {{len+{}}} {} /T {{T+{}}} >>\nendobj\n",
                self.l, self.params, self.t
            ));
            a.mark("first");
            a.put("xref\n0 1\n0000000000 65535 f \n");
            for (n, at) in &self.first {
                a.put(&format!("{n} 1\n{{{at}}} 00000 n \n"));
            }
            a.put(&format!(
                "trailer\n<< /Size 21 {} /Prev {{main}} >>\n",
                self.trailer
            ));
            let mut written = HashSet::new();
            for (n, body) in &self.objects {
                let mark = if written.insert(*n) { "o" } else { "s" };
                a.mark(&format!("{mark}{n}"));
                a.put(&format!("{n} 0 obj\n{body}\nendobj\n"));
            }
            a.mark("main");
            a.put("xref\n0 21\n");
            a.mark("T");
            for n in 0..21 {
                if written.contains(&n) {
                    a.put(&format!("{{o{n}}} 00000 n \n"));
                } else {
                    a.put("0000000000 65535 f \n");
                }
            }
            a.put(&format!("trailer\n<< /Size 21 {} {id} >>\n", self.trailer));
            let Some(stray) = self.later else {
                a.put(&format!("startxref\n{}\n%%EOF\n", a.marks["first"]));
                return [self.junk.as_bytes(), &a.finish()].concat();
            };
            a.put(&format!("startxref\n{}\n%%EOF\n", a.marks["main"]));
            a.put(&format!("%{}\n", "p".repeat(100)));
            if stray {
                a.mark("s6");
                a.put(&format!("6 0 obj\n{ALT6}\nendobj\n"));
            }
            let x = a.out.len();
            a.put(&format!(
                "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 21 {} {id} /Prev {} >>\n\
                 startxref\n{x}\n%%EOF\n",
                self.trailer, a.marks["main"]
            ));
            [self.junk.as_bytes(), &a.finish()].concat()
        }
    }

    /// The files review round 4 opened in Poppler and pdf.js. With `/L` the file's length
    /// they read the cross-references from just after the first object, where lopdf reads
    /// them from the last `startxref`, and showed another page 6 or another first page.
    #[test]
    fn a_file_read_from_after_its_first_object_differs() {
        for v in [
            "alt-in-signed",
            "alt-in-later",
            "o-only",
            "o-dangling",
            "o-missing",
            "control-reparse",
            "n-three",
        ] {
            assert!(read(&Lin::round_4(v, true).build()).is_err(), "{v}");
        }
        // Not linearized with `/L` another length, and in one revision they start where
        // lopdf does.
        let other = Lin {
            l: 1,
            ..Lin::round_4("alt-in-signed", true)
        };
        assert!(read(&other.build()).is_ok());
        assert!(read(&Lin::round_4("plain", false).build()).is_ok());
    }

    /// pdf.js opens the first page at `/O` and counts `/N` pages, whatever the page tree
    /// holds; when it can't read `/O`'s object it takes the page tree's first page.
    #[test]
    fn a_first_page_or_page_count_lopdf_doesnt_take_differs() {
        assert!(read(&Lin::round_4("o-only", false).build()).is_err());
        assert!(read(&Lin::round_4("n-three", false).build()).is_err());
        assert!(read(&Lin::round_4("o-missing", false).build()).is_ok());
        assert!(read(&Lin::round_4("o-dangling", false).build()).is_ok());
    }

    /// Without an `endobj` in its first 1,024 bytes, Poppler reads a linearized file's
    /// cross-references from its start, finds none there and scans the file for objects.
    #[test]
    fn a_first_object_ending_past_1024_bytes_differs() {
        let mut long = Lin::round_4("plain", false);
        long.params += &format!(" /Pad ({})", "x".repeat(1024));
        assert!(read(&long.build()).is_err());
    }

    /// With bytes before the header, `/L` may be the length from the header or the whole
    /// file's, and the apps' offsets may not count from where lopdf's do.
    #[test]
    fn a_linearized_file_after_other_bytes_differs() {
        let junk = Lin {
            junk: "junk\n",
            ..Lin::round_4("plain", false)
        };
        assert!(read(&junk.build()).is_err());
        let five = Lin {
            l: 5,
            ..junk.clone()
        };
        assert!(read(&five.build()).is_err());
        assert!(read(&Lin { l: 6, ..junk }.build()).is_ok());
    }

    /// Poppler looks up a number the newest table doesn't list in the main table at `/T`, 20
    /// bytes a row, where lopdf reads the sections.
    #[test]
    fn a_main_table_row_poppler_reads_otherwise_is_unsure() {
        let lin = Lin {
            first: vec![(6, "o6")],
            ..Lin::round_4("plain", false)
        };
        assert!(!read(&lin.build()).unwrap().unsure.contains(&2));
        let off = Lin { t: 20, ..lin };
        assert!(read(&off.build()).unwrap().unsure.contains(&2));
    }

    /// Three pages at objects 10, 1 and 3, in the page tree in `kids`' order, each with
    /// `entries`, the page tree with `inherited`, and hint tables giving pages 10, 1 and 3.
    /// With `length`, the hint stream's `/Length` is a reference to that object, and object
    /// 16, which the first-page section lists, holds the length.
    fn hinted(kids: &str, entries: &str, inherited: &str, length: Option<u32>) -> Lin {
        // The page offset table: at least 1 object a page, 2 bits for the difference, every
        // other field 0, then differences 0, 1 and 0: page 2 holds 2 objects from object 1.
        // The shared object table: one group, the first page's, unsigned.
        let mut data: Vec<u8> = [
            &[0, 0, 0, 1][..],
            &[0; 4],
            &[0, 2],
            &[0; 26],
            &[0b0001_0000],
        ]
        .concat();
        data.extend([&[0; 8][..], &[0, 0, 0, 1, 0, 0, 0, 1], &[0; 8], &[0]].concat());
        let data = String::from_utf8(data).unwrap();
        let hint = format!(
            "<< /Length {} /S 37 >>\nstream\n{data}\nendstream",
            length.map_or(data.len().to_string(), |n| format!("{n} 0 R"))
        );
        let len = format!("15 0 obj\n{hint}\nendobj\n").len();
        let page = format!("<< /Type /Page /Parent 5 0 R {entries}>>");
        let mut lin = Lin {
            params: format!("/H [ {{o15}} {len} ] /O 10 /E 1 /N 3"),
            first: vec![(10, "o10"), (15, "o15")],
            objects: vec![
                (1, page.clone()),
                (2, "<< /Type /Catalog /Pages 5 0 R >>".into()),
                (3, page.clone()),
                (
                    5,
                    format!("<< /Type /Pages /Kids [{kids}] /Count 3 {inherited}>>"),
                ),
                (10, page),
                (15, hint),
            ],
            trailer: "/Root 2 0 R".into(),
            later: None,
            l: 0,
            t: 0,
            junk: "",
            second: "%âãÏÓ",
        };
        if length.is_some() {
            lin.first.push((16, "o16"));
            lin.objects.push((16, data.len().to_string()));
        }
        lin
    }

    /// When its hint tables read cleanly, Poppler takes each page where they say, without
    /// the entries a page inherits from the page tree.
    #[test]
    fn hinted_pages_must_be_the_page_tree_s() {
        let own = "/MediaBox [0 0 300 200] ";
        assert!(read(&hinted("10 0 R 1 0 R 3 0 R", own, "", None).build()).is_ok());
        for lin in [
            hinted("10 0 R 3 0 R 1 0 R", own, "", None),
            hinted("10 0 R 1 0 R 3 0 R", "", own, None),
        ] {
            let e = read(&lin.build()).err().unwrap();
            assert!(e.contains("from its hint tables, which give"), "{e}");
        }
    }

    /// Poppler takes a hint stream's `/Length` from the object a reference names, which
    /// lopdf holds as it reads it when the readings agree on that object.
    #[test]
    fn a_hint_stream_s_length_in_another_object_is_read() {
        let own = "/MediaBox [0 0 300 200] ";
        let ok = hinted("10 0 R 1 0 R 3 0 R", own, "", Some(16));
        assert_eq!(read(&ok.build()).err(), None);
        let swapped = hinted("10 0 R 3 0 R 1 0 R", own, "", Some(16));
        let e = read(&swapped.build()).err().unwrap();
        assert!(e.contains("from its hint tables, which give"), "{e}");
        // A free object gives no length.
        let free = hinted("10 0 R 1 0 R 3 0 R", own, "", Some(17));
        assert_eq!(read(&free.build()).err().as_deref(), Some(HINTS));
    }

    /// In an encrypted file, Poppler decrypts the hint stream as the object its header names,
    /// which lopdf holds decrypted when the cross-references list that object at `/H`.
    #[test]
    fn an_encrypted_file_s_hint_tables_are_read_decrypted() {
        let mut d = Document::with_version("1.7");
        let e = encrypt_with_identity(&mut d);
        let text = |o: &Object| {
            let mut out = Vec::new();
            Writer::write_object(&mut out, o).unwrap();
            String::from_utf8(out).unwrap()
        };
        let mut dict = d.objects[&e].clone();
        for (_, v) in dict.as_dict_mut().unwrap().iter_mut() {
            if let Object::String(_, format) = v {
                *format = StringFormat::Hexadecimal;
            }
        }
        let id = text(d.trailer.get(b"ID").unwrap());
        let own = "/MediaBox [0 0 300 200] ";
        let encrypted = |kids: &str| {
            let mut lin = hinted(kids, own, "", None);
            lin.trailer = format!("/Root 2 0 R /Encrypt 14 0 R /ID {id}");
            lin.objects.push((14, text(&dict)));
            lin
        };
        assert_eq!(read(&encrypted("10 0 R 1 0 R 3 0 R").build()).err(), None);
        let swapped = encrypted("10 0 R 3 0 R 1 0 R");
        let e = read(&swapped.build()).err().unwrap();
        assert!(e.contains("from its hint tables, which give"), "{e}");
        // The cross-references list another copy of the hint stream than `/H` gives.
        let mut copy = encrypted("10 0 R 1 0 R 3 0 R");
        let hint = (copy.objects.iter()).find(|(n, _)| *n == 15).cloned();
        copy.objects.push(hint.unwrap());
        copy.first = vec![(10, "o10"), (15, "s15")];
        assert_eq!(read(&copy.build()).err().as_deref(), Some(HINTS));
    }

    /// No app takes a file as linearized when the first word past its header can't start a
    /// number, whatever names follow it.
    #[test]
    fn a_file_whose_first_word_is_no_number_is_not_linearized() {
        let junk = Lin {
            second: "junk",
            ..Lin::round_4("alt-in-signed", true)
        };
        assert_eq!(read(&junk.build()).err(), None);
    }
}
