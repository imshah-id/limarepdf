//! Opening files whose cross-reference information is damaged: offsets that point at the
//! wrong bytes, a cross-reference stream that doesn't read, or no table at all. lopdf
//! trusts the table and then finds no pages, so the objects are found by scanning the
//! bytes instead, as other PDF apps do, and a rebuilt table is appended for lopdf to read.
//! A page tree that lopdf reads with no pages, for reasons other readers look past, is
//! mended too (see [`mend_page_tree`]).

use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::Cursor;
use std::ops::Range;

/// The highest object number the PDF format allows; a scanned header above it is noise.
const MAX_OBJECT: u32 = 8_388_607;
/// How many trailers, newest first, are tried for the catalog.
const MAX_TRAILERS: usize = 16;
/// The longest trailer dictionary read, in bytes.
const MAX_TRAILER_BYTES: usize = 64 * 1024;
/// The deepest page tree mended, as deep as page attributes are inherited from.
const MAX_PAGE_TREE_DEPTH: usize = 64;
/// The most memory, roughly, mending a page tree takes for the copies of a shared `/Kids`
/// list with pages written in it that each node after the first takes; a file needing more
/// is refused.
const MAX_SHARED_KIDS_COPIES: usize = 64 << 20;
/// The most bytes an object stream is unpacked to.
const MAX_OBJECT_STREAM: usize = 64 << 20;
/// Trailer entries carried into the rebuilt table. `/Encrypt` and `/ID` must be there when
/// lopdf reads the objects, since decrypting them needs both.
const TRAILER_KEYS: [&[u8]; 4] = [b"Root", b"Info", b"ID", b"Encrypt"];

/// `bytes` with a rebuilt cross-reference table appended, listing every object found by
/// scanning (a later copy of a number wins) under the newest trailer that names a catalog.
/// `None` when no objects are found. Objects inside object streams come with their
/// stream: lopdf takes the members of every object stream it reads.
pub(crate) fn rebuild(bytes: &[u8]) -> Option<Vec<u8>> {
    // lopdf reads from the header on, and its offsets count from there.
    let start = bytes.windows(5).position(|w| w == b"%PDF-")?;
    let body = &bytes[start..];
    let scan = scan_objects(body);
    if scan.objects.is_empty() {
        return None;
    }
    let trailer = newest_trailer(body, &scan).unwrap_or_default();
    let objects = scan.objects;

    let mut out = bytes.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let xref = out.len() - start;
    let mut table = String::from("xref\n0 1\n0000000000 65535 f \n");
    let mut run: Vec<(u32, usize, u16)> = Vec::new();
    let flush = |run: &mut Vec<(u32, usize, u16)>, table: &mut String| {
        if let Some(&(first, ..)) = run.first() {
            let _ = writeln!(table, "{first} {}", run.len());
            for (_, offset, generation) in run.drain(..) {
                let _ = write!(table, "{offset:010} {generation:05} n\r\n");
            }
        }
    };
    for (&num, &(offset, generation)) in &objects {
        if run.last().is_some_and(|&(last, ..)| last + 1 != num) {
            flush(&mut run, &mut table);
        }
        run.push((num, offset, generation));
    }
    flush(&mut run, &mut table);
    let size = objects.keys().next_back().map_or(1, |n| n + 1);
    let _ = write!(table, "trailer\n<< /Size {size}");
    for key in TRAILER_KEYS {
        if let Ok(v) = trailer.get(key) {
            table.push(' ');
            write_name(&mut table, key);
            table.push(' ');
            write_object(&mut table, v, 0);
        }
    }
    let _ = write!(table, " >>\nstartxref\n{xref}\n%%EOF\n");
    out.extend_from_slice(table.as_bytes());
    Some(out)
}

/// The catalog among `doc`'s objects when its trailer names none that is there: the
/// highest-numbered object of type Catalog that has a page tree.
pub(crate) fn find_catalog(doc: &Document) -> Option<lopdf::ObjectId> {
    doc.objects
        .iter()
        .rev()
        .find(|(_, o)| {
            o.as_dict()
                .is_ok_and(|d| d.has_type(b"Catalog") && d.get(b"Pages").is_ok())
        })
        .map(|(id, _)| *id)
}

/// Adds the members of `doc`'s object streams that `doc` doesn't hold, reading each on its
/// own. A rebuilt table lists none of them, so the check against other readers drops those
/// lopdf took (as never listed), and lopdf passes over one it can't read (before 0.47, one
/// starting with a comment). An object already in `doc` is kept.
pub(crate) fn unpack_object_streams(doc: &mut Document) {
    let mut found = Vec::new();
    for o in doc.objects.values() {
        let Object::Stream(s) = o else { continue };
        if !s.dict.has_type(b"ObjStm") {
            continue;
        }
        let Some(first) = s
            .dict
            .get(b"First")
            .and_then(Object::as_i64)
            .ok()
            .and_then(|f| usize::try_from(f).ok())
        else {
            continue;
        };
        let Ok(content) = s.get_plain_content_with_limit(MAX_OBJECT_STREAM) else {
            continue;
        };
        let Some(index) = content.get(..first) else {
            continue;
        };
        let numbers: Vec<usize> = index
            .split(|c| is_white(*c))
            .filter(|w| !w.is_empty())
            .map_while(|w| std::str::from_utf8(w).ok()?.parse().ok())
            .collect();
        let mut members: Vec<(usize, u32)> = numbers
            .as_chunks::<2>()
            .0
            .iter()
            .filter_map(|&[num, at]| Some((first.checked_add(at)?, u32::try_from(num).ok()?)))
            .filter(|&(at, _)| at < content.len())
            .collect();
        members.sort_unstable();
        for (i, &(at, num)) in members.iter().enumerate() {
            if doc.objects.contains_key(&(num, 0)) {
                continue;
            }
            let end = members.get(i + 1).map_or(content.len(), |m| m.0);
            if let Some(o) = read_object(&content[at..end]) {
                found.push(((num, 0), o));
            }
        }
    }
    for (id, o) in found {
        doc.objects.entry(id).or_insert(o);
    }
    if let Some(&(top, _)) = doc.objects.keys().next_back() {
        doc.max_id = doc.max_id.max(top);
    }
}

/// Mends a page tree in which lopdf finds no pages although other readers do: a page or
/// page tree node written directly in a `/Kids` array is made an object of its own, and a
/// kid whose object isn't a page or a node takes another copy of that object in `bytes` that
/// is one (the file may give a second object the page's number, and lopdf keeps that one).
/// The tree is walked a depth at a time, so a node several nodes list is mended from the one
/// nearest the top, within [`MAX_PAGE_TREE_DEPTH`] as often as any is.
/// Returns whether anything changed, or an error if the copies that nodes sharing a list of
/// kids take would be more than [`MAX_SHARED_KIDS_COPIES`]; the tree is then part mended.
pub(crate) fn mend_page_tree(doc: &mut Document, bytes: &[u8]) -> Result<bool, PagesTooComplex> {
    let Some(root) = doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"Pages").ok())
        .and_then(|p| p.as_reference().ok())
    else {
        return Ok(false);
    };
    let start = bytes.windows(5).position(|w| w == b"%PDF-").unwrap_or(0);
    let body = &bytes[start..];
    let mut lines = None;
    // The kids no copy in `bytes` mends.
    let mut missing = HashSet::new();
    // Each `/Kids` array object, by how much a copy of it takes if pages are written in it (0
    // if none are). Nodes sharing one, as no well-made tree has, each take their own copy of
    // one with pages, so that each has pages of its own; the kids it lists by reference are
    // queued once, from the first node listing it, the nearest the top.
    let mut lists: HashMap<ObjectId, usize> = HashMap::new();
    let mut copies = 0usize;
    let mut changed = false;
    let mut seen = HashSet::new();
    let mut todo = VecDeque::from([(root, 0)]);
    while let Some((node, depth)) = todo.pop_front() {
        if depth > MAX_PAGE_TREE_DEPTH || !seen.insert(node) {
            continue;
        }
        let (kids, queue) = match doc.get_dictionary(node).and_then(|d| d.get(b"Kids")) {
            Ok(Object::Array(a)) => (a.clone(), true),
            Ok(Object::Reference(list)) => {
                let list = *list;
                let Ok(Object::Array(a)) = doc.get_object(list) else {
                    continue;
                };
                let queue = match lists.get(&list) {
                    Some(0) => continue,
                    Some(&size) => {
                        copies += size;
                        if copies > MAX_SHARED_KIDS_COPIES {
                            return Err(PagesTooComplex);
                        }
                        false
                    }
                    None => {
                        let size = if a.iter().any(is_written_page_node) {
                            a.iter().map(copy_size).sum()
                        } else {
                            0
                        };
                        lists.insert(list, size);
                        true
                    }
                };
                (a.clone(), queue)
            }
            _ => continue,
        };
        let mut mended = kids;
        let mut written = false;
        for kid in &mut mended {
            #[cfg(test)]
            tests::KIDS_READ.set(tests::KIDS_READ.get() + 1);
            let id = match kid {
                Object::Dictionary(d) if is_page_node(d) => {
                    let mut d = d.clone();
                    d.set("Parent", node);
                    written = true;
                    doc.add_object(d)
                }
                Object::Reference(_) if !queue => continue,
                Object::Reference(id) => {
                    let id = *id;
                    if !doc.get_dictionary(id).is_ok_and(is_page_node) {
                        if missing.contains(&id) {
                            continue;
                        }
                        let lines = lines.get_or_insert_with(|| object_lines(body));
                        match page_node_copy(body, lines, id) {
                            Some(d) => {
                                doc.objects.insert(id, Object::Dictionary(d));
                                changed = true;
                            }
                            None => {
                                missing.insert(id);
                                continue;
                            }
                        }
                    }
                    id
                }
                _ => continue,
            };
            *kid = Object::Reference(id);
            #[cfg(test)]
            tests::QUEUED.set(tests::QUEUED.get() + 1);
            todo.push_back((id, depth + 1));
        }
        if written {
            if let Ok(d) = doc.get_dictionary_mut(node) {
                d.set("Kids", mended);
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// A page tree whose mending would take more than [`MAX_SHARED_KIDS_COPIES`].
#[derive(Debug)]
pub(crate) struct PagesTooComplex;

/// Whether `d` is a page or a page tree node.
fn is_page_node(d: &Dictionary) -> bool {
    d.has_type(b"Page") || d.has_type(b"Pages")
}

/// Whether `o` is a page or a page tree node written directly, not by reference.
fn is_written_page_node(o: &Object) -> bool {
    matches!(o, Object::Dictionary(d) if is_page_node(d))
}

/// Roughly how much memory a copy of `o` takes, in bytes: the object, and what it holds on
/// the heap.
pub(crate) fn copy_size(o: &Object) -> usize {
    size_of::<Object>() + held(o)
}

/// Roughly how much heap a copy of `o` holds.
fn held(o: &Object) -> usize {
    match o {
        Object::Name(s) | Object::String(s, _) => allocation(s.len()),
        Object::Array(a) => {
            allocation(a.len() * size_of::<Object>()) + a.iter().map(held).sum::<usize>()
        }
        Object::Dictionary(d) => dictionary_held(d),
        Object::Stream(s) => dictionary_held(&s.dict) + allocation(s.content.len()),
        _ => 0,
    }
}

/// Roughly how much heap a copy of `d` holds. A copy of its map keeps room for as many
/// entries as its index has, at most twice as many as it holds and at least 3, each a hash,
/// a key and an object; its index has a slot for at most 16/7 of an entry each and at least
/// 4, each a `usize` and a control byte, and 16 control bytes more.
fn dictionary_held(d: &Dictionary) -> usize {
    let entry = size_of::<u64>() + size_of::<Vec<u8>>() + size_of::<Object>();
    let slots = (d.len() * 16 / 7 + 1).max(4);
    let room = allocation((2 * d.len()).max(3) * entry) + allocation(slots * 9 + 16);
    room + d
        .iter()
        .map(|(k, v)| allocation(k.len()) + held(v))
        .sum::<usize>()
}

/// The heap an allocation of `n` bytes takes: none for none, else at least the least an
/// allocator gives with its header.
fn allocation(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        n.max(32)
    }
}

/// Where each object's headers in `b` are, outside stream data, in the order they come: a
/// header starts a line, after any spaces and tabs.
fn object_lines(b: &[u8]) -> HashMap<ObjectId, Vec<usize>> {
    let scan = scan_objects(b);
    let mut lines: HashMap<ObjectId, Vec<usize>> = HashMap::new();
    let mut i = 0;
    while i < b.len() {
        #[cfg(test)]
        tests::LINES_READ.set(tests::LINES_READ.get() + 1);
        let line = i + b[i..]
            .iter()
            .take_while(|c| matches!(c, b' ' | b'\t'))
            .count();
        if let Some(id) = object_header(&b[line..]).filter(|_| !scan.in_stream(line)) {
            lines.entry(id).or_default().push(line);
        }
        i = match b[i..].iter().position(|c| matches!(c, b'\r' | b'\n')) {
            Some(n) => i + n + 1,
            None => b.len(),
        };
    }
    lines
}

/// The first copy of object `id` in `b`, of those `lines` finds, that is a page or a page
/// tree node.
fn page_node_copy(
    b: &[u8],
    lines: &HashMap<ObjectId, Vec<usize>>,
    id: ObjectId,
) -> Option<Dictionary> {
    lines.get(&id)?.iter().find_map(|&line| {
        #[cfg(test)]
        tests::COPIES_READ.set(tests::COPIES_READ.get() + 1);
        let after = line + find(&b[line..], b"obj")? + 3;
        let at = after + b[after..].iter().take_while(|c| is_white(**c)).count();
        read_dictionary(&b[at..]).filter(is_page_node)
    })
}

/// What a scan of a file's bytes finds.
#[derive(Default)]
struct Scan {
    /// Every `N G obj` header that starts a line, by object number: where it starts and its
    /// generation. A later copy of a number wins, as in an appended revision.
    objects: BTreeMap<u32, (usize, u16)>,
    /// Where each stream's data is, from its `stream` keyword to the end of `endstream`.
    streams: Vec<Range<usize>>,
}

impl Scan {
    fn in_stream(&self, at: usize) -> bool {
        let i = self.streams.partition_point(|s| s.end <= at);
        self.streams.get(i).is_some_and(|s| s.contains(&at))
    }
}

/// Where every `N G obj <integer> endobj` whose header starts a line is, and its value, by
/// number and generation, in file order: the candidates for an indirect `/Length`. Copies
/// inside stream data are included, since where the streams end isn't known yet.
fn integer_objects(b: &[u8]) -> HashMap<(u32, u16), Vec<(usize, u64)>> {
    let mut out: HashMap<(u32, u16), Vec<(usize, u64)>> = HashMap::new();
    let mut i = 0;
    while i < b.len() {
        let line = i + b[i..]
            .iter()
            .take_while(|c| matches!(c, b' ' | b'\t'))
            .count();
        if let Some(id) = object_header(&b[line..]) {
            let rest = &b[line + find(&b[line..], b"obj").unwrap_or(0) + 3..];
            let rest = &rest[rest.iter().take_while(|c| is_white(**c)).count()..];
            let digits = rest.iter().take_while(|c| c.is_ascii_digit()).count();
            let after = &rest[digits..];
            let space = after.iter().take_while(|c| is_white(**c)).count();
            if space > 0 && after[space..].starts_with(b"endobj") {
                let value = std::str::from_utf8(&rest[..digits]).ok();
                if let Some(v) = value.and_then(|v| v.parse().ok()) {
                    out.entry(id).or_default().push((line, v));
                }
            }
        }
        i = match b[i..].iter().position(|c| matches!(c, b'\r' | b'\n')) {
            Some(n) => i + n + 1,
            None => b.len(),
        };
    }
    out
}

/// Scans `b` for objects. Stream data is skipped, so headers inside an uncompressed stream
/// (an attached PDF, say) don't count.
fn scan_objects(b: &[u8]) -> Scan {
    let lengths = integer_objects(b);
    let mut out = Scan::default();
    let mut header = None;
    let mut line_start = true;
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"stream")
            && !b[..i].ends_with(b"end")
            && matches!(b.get(i + 6), Some(b'\r' | b'\n'))
        {
            if let Some(end) = stream_end(b, header, i, &lengths) {
                out.streams.push(i..end);
                i = end;
                line_start = false;
                continue;
            }
        }
        if line_start && b[i].is_ascii_digit() {
            if let Some((num, generation)) = object_header(&b[i..]) {
                header = Some(i);
                if (1..=MAX_OBJECT).contains(&num) {
                    out.objects.insert(num, (i, generation));
                }
            }
        }
        match b[i] {
            b'\r' | b'\n' => line_start = true,
            b' ' | b'\t' | b'\x0c' | b'\0' => {}
            _ => line_start = false,
        }
        i += 1;
    }
    out
}

/// Where the stream whose `stream` keyword is at `at` ends, just after its `endstream`,
/// given where its object's header is. Its `/Length` is used when `endstream` follows the
/// data there, as other PDF apps do: a direct number, or for an indirect one the latest of
/// `lengths`' copies of that object that fits and isn't part of the data, as it would be if
/// it were inside the data its value or another fitting copy's gives (an attached file can
/// hold a copy, to end the stream early). Else the stream ends at the first `endstream`.
/// `None` when there is no `endstream`, or the keyword is inside the object's dictionary
/// (in a string), so no stream starts there.
fn stream_end(
    b: &[u8],
    header: Option<usize>,
    at: usize,
    lengths: &HashMap<(u32, u16), Vec<(usize, u64)>>,
) -> Option<usize> {
    let dict = header.and_then(|h| {
        let obj = h + find(&b[h..at], b"obj")? + 3;
        let open = obj + b[obj..at].iter().position(|c| !is_white(*c))?;
        Some((open, open + dictionary_len(&b[open..])?))
    });
    if let Some((open, close)) = dict {
        if close > at {
            return None;
        }
        let eol = if b[at + 6..].starts_with(b"\r\n") {
            2
        } else {
            1
        };
        let data = at + 6 + eol;
        let ends_at = |n: u64| {
            let e = data
                .checked_add(usize::try_from(n).ok()?)
                .filter(|&e| e <= b.len())?;
            let e = e + b[e..].iter().take_while(|c| is_white(**c)).count();
            b[e..].starts_with(b"endstream").then_some(e)
        };
        let end = read_dictionary(&b[open..close]).and_then(|d| match d.get(b"Length").ok()? {
            Object::Integer(n) => ends_at(u64::try_from(*n).ok()?),
            Object::Reference(id) => {
                let fits: Vec<(usize, usize)> = lengths
                    .get(id)?
                    .iter()
                    .filter_map(|&(pos, n)| Some((pos, ends_at(n)?)))
                    .filter(|&(pos, end)| !(data..end).contains(&pos))
                    .collect();
                // Every copy's data starts at `data`: inside another's is inside the longest.
                let longest = fits.iter().map(|&(_, end)| end).max()?;
                fits.iter()
                    .rev()
                    .find(|&&(pos, _)| !(data..longest).contains(&pos))
                    .map(|&(_, end)| end)
            }
            _ => None,
        });
        if let Some(end) = end {
            return Some(end + 9);
        }
    }
    Some(at + 6 + find(&b[at + 6..], b"endstream")? + 9)
}

/// The object number and generation of an `N G obj` header at the start of `b`.
fn object_header(b: &[u8]) -> Option<(u32, u16)> {
    fn number(b: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
        let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
        (n > 0 && n <= max).then(|| b.split_at(n))
    }
    fn space(b: &[u8]) -> Option<&[u8]> {
        let n = b.iter().take_while(|c| is_white(**c)).count();
        (n > 0).then(|| &b[n..])
    }
    let (num, rest) = number(b, 10)?;
    let (generation, rest) = number(space(rest)?, 5)?;
    let rest = space(rest)?.strip_prefix(b"obj")?;
    if rest.first().is_some_and(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let num = std::str::from_utf8(num).ok()?.parse().ok()?;
    let generation = std::str::from_utf8(generation).ok()?.parse().ok()?;
    Some((num, generation))
}

/// The newest trailer whose `/Root` is an indirect reference: a table's `trailer`
/// dictionary or a cross-reference stream's, leaving out any inside stream data.
fn newest_trailer(b: &[u8], scan: &Scan) -> Option<Dictionary> {
    let mut places: Vec<usize> = Vec::new();
    let mut at = 0;
    while let Some(i) = find(&b[at..], b"trailer") {
        let after = at + i + 7;
        if let Some(d) = b[after..].iter().position(|c| !is_white(*c)) {
            if !scan.in_stream(at + i) {
                places.push(after + d);
            }
        }
        at = after;
    }
    // A cross-reference stream's dictionary follows its object's header.
    let mut streams: Vec<usize> = Vec::new();
    let mut at = 0;
    while let Some(i) = find(&b[at..], b"/XRef") {
        let pos = at + i;
        let start = (!scan.in_stream(pos))
            .then(|| scan.objects.values().filter(|(o, _)| *o < pos).max())
            .flatten();
        if let Some(&(start, _)) = start {
            if let Some(d) = find(&b[start..pos], b"<<") {
                streams.push(start + d);
            }
        }
        at = pos + 5;
    }
    places.extend(streams);
    places.sort_unstable();
    places.dedup();
    places
        .iter()
        .rev()
        .take(MAX_TRAILERS)
        .filter_map(|&p| read_dictionary(&b[p..]))
        .find(|d| d.get(b"Root").and_then(Object::as_reference).is_ok())
}

/// Reads the dictionary at the start of `b`.
fn read_dictionary(b: &[u8]) -> Option<Dictionary> {
    match read_object(&b[..dictionary_len(b)?])? {
        Object::Dictionary(d) => Some(d),
        _ => None,
    }
}

/// A lopdf load filter that keeps every object, so lopdf reads a file by its table as
/// written. Unfiltered, lopdf reads a file whose catalog doesn't lead to a page tree again by
/// scanning, which ends a stream at the first `endstream` and ignores `/Length`. lopdf uses
/// the object returned only for members of object streams, which are never streams, so no
/// stream is copied.
pub(crate) fn as_written(id: lopdf::ObjectId, o: &mut Object) -> Option<(lopdf::ObjectId, Object)> {
    match o {
        Object::Stream(_) => Some((id, Object::Null)),
        o => Some((id, o.clone())),
    }
}

/// Reads `b` as one object (a stream's data can't be reached), by having lopdf read it as
/// the one object of a small file.
fn read_object(b: &[u8]) -> Option<Object> {
    let mut doc = b"%PDF-1.7\n".to_vec();
    let at = doc.len();
    doc.extend_from_slice(b"1 0 obj\n");
    doc.extend_from_slice(b);
    doc.extend_from_slice(b"\nendobj\n");
    let xref = doc.len();
    doc.extend_from_slice(
        format!(
            "xref\n0 2\n0000000000 65535 f\r\n{at:010} 00000 n\r\ntrailer\n<< /Size 2 >>\n\
             startxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    match Document::load_from_with_options(Cursor::new(doc), LoadOptions::with_filter(as_written))
        .ok()?
        .objects
        .remove(&(1, 0))?
    {
        Object::Stream(s) => Some(Object::Dictionary(s.dict)),
        o => Some(o),
    }
}

/// The length of the dictionary at the start of `b`, from `<<` to its matching `>>`,
/// stepping over strings and comments.
fn dictionary_len(b: &[u8]) -> Option<usize> {
    if !b.starts_with(b"<<") {
        return None;
    }
    let mut depth = 0usize;
    let mut i = 0;
    while i < b.len().min(MAX_TRAILER_BYTES) {
        match b[i] {
            b'<' if b.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
            }
            b'>' if b.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'<' => i += b[i..].iter().position(|&c| c == b'>')? + 1,
            b'(' => {
                let mut nest = 0usize;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 1,
                        b'(' => nest += 1,
                        b')' => {
                            nest -= 1;
                            if nest == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
            }
            b'%' => {
                while i < b.len() && !matches!(b[i], b'\r' | b'\n') {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Writes `o` in PDF syntax. Strings are written in hexadecimal, which needs no escaping.
pub(crate) fn write_object(out: &mut String, o: &Object, depth: usize) {
    if depth > 32 {
        out.push_str("null");
        return;
    }
    match o {
        Object::Null => out.push_str("null"),
        Object::Boolean(v) => out.push_str(if *v { "true" } else { "false" }),
        Object::Integer(v) => {
            let _ = write!(out, "{v}");
        }
        Object::Real(v) => {
            let _ = write!(out, "{v}");
        }
        Object::Name(n) => write_name(out, n),
        Object::String(s, _) => {
            out.push('<');
            for c in s {
                let _ = write!(out, "{c:02X}");
            }
            out.push('>');
        }
        Object::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                write_object(out, v, depth + 1);
            }
            out.push(']');
        }
        Object::Dictionary(d) => {
            out.push_str("<<");
            for (k, v) in d.iter() {
                write_name(out, k);
                out.push(' ');
                write_object(out, v, depth + 1);
            }
            out.push_str(">>");
        }
        Object::Reference((n, g)) => {
            let _ = write!(out, "{n} {g} R");
        }
        // A stream can't be a trailer value.
        Object::Stream(_) => out.push_str("null"),
    }
}

/// Writes a name, with `#xx` for bytes that can't stand in a name as they are.
fn write_name(out: &mut String, n: &[u8]) {
    out.push('/');
    for &c in n {
        if c.is_ascii_graphic() && !b"#%()/<>[]{}".contains(&c) {
            out.push(c as char);
        } else {
            let _ = write!(out, "#{c:02X}");
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn is_white(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;
    use std::cell::Cell;

    thread_local! {
        /// Page tree kids queued to be mended on this thread.
        pub(super) static QUEUED: Cell<usize> = const { Cell::new(0) };
        /// Page tree kids looked at on this thread, queued or not.
        pub(super) static KIDS_READ: Cell<usize> = const { Cell::new(0) };
        /// Lines of a file looked at for an object's copies on this thread.
        pub(super) static LINES_READ: Cell<usize> = const { Cell::new(0) };
        /// Copies of an object read on this thread, for one that is a page or a node.
        pub(super) static COPIES_READ: Cell<usize> = const { Cell::new(0) };
    }

    /// A document whose catalog's page tree is `root`.
    fn with_root(doc: &mut Document, root: lopdf::ObjectId) {
        let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => root });
        doc.trailer.set("Root", catalog);
    }

    #[test]
    fn page_tree_nodes_sharing_their_kids_queue_them_once() {
        // Each node lists every node, and a page written directly, as its kids: the kids
        // were queued again for each node. Each node takes its own page.
        let n = 500;
        let mut doc = Document::with_version("1.7");
        let shared = doc.new_object_id();
        let nodes: Vec<Object> = (0..n)
            .map(|_| {
                let node = dictionary! { "Type" => "Pages", "Kids" => shared };
                doc.add_object(node).into()
            })
            .collect();
        let mut kids = nodes.clone();
        kids.push(dictionary! { "Type" => "Page" }.into());
        doc.objects.insert(shared, Object::Array(kids));
        let root = nodes[0].as_reference().unwrap();
        with_root(&mut doc, root);
        let before = doc.objects.len();
        QUEUED.set(0);
        assert!(mend_page_tree(&mut doc, b"%PDF-1.7\n").unwrap());
        assert!(QUEUED.get() < 4 * n, "queued {} kids", QUEUED.get());
        // A copy of the page for each node, in its own mended list.
        assert_eq!(doc.objects.len(), before + n);
        let last = nodes[n - 1].as_reference().unwrap();
        let list = doc.get_dictionary(last).unwrap().get(b"Kids").unwrap();
        let page = list.as_array().unwrap()[n].as_reference().unwrap();
        let page = doc.get_dictionary(page).unwrap();
        assert!(page.has_type(b"Page"));
        assert_eq!(page.get(b"Parent").unwrap(), &Object::Reference(last));
    }

    #[test]
    fn page_tree_nodes_sharing_a_list_with_no_page_written_in_it_read_it_once() {
        // Each node lists one list naming every node, with no page written in it: the first
        // node reads it, the others pass over it, and nothing is copied.
        let n = 2_000;
        let mut doc = Document::with_version("1.7");
        let shared = doc.new_object_id();
        let nodes: Vec<Object> = (0..n)
            .map(|_| {
                let node = dictionary! { "Type" => "Pages", "Kids" => shared };
                doc.add_object(node).into()
            })
            .collect();
        doc.objects.insert(shared, Object::Array(nodes.clone()));
        let root = nodes[0].as_reference().unwrap();
        with_root(&mut doc, root);
        KIDS_READ.set(0);
        assert!(!mend_page_tree(&mut doc, b"%PDF-1.7\n").unwrap());
        assert!(KIDS_READ.get() < 2 * n, "read {} kids", KIDS_READ.get());
    }

    #[test]
    fn kids_that_are_no_page_are_looked_for_in_one_pass() {
        // The root lists `n` objects that aren't pages, nor is their copy in the file one,
        // and `n` nodes that each list one more such object: the file was read again for
        // each, and the last object's copy for each node.
        let n = 2_000;
        let mut doc = Document::with_version("1.7");
        let mut b = b"%PDF-1.7\n".to_vec();
        let last = (n as u32 + 1, 0);
        let mut kids: Vec<Object> = Vec::new();
        for i in 1..=n as u32 + 1 {
            b.extend_from_slice(format!("{i} 0 obj\n<< /A 1 >>\nendobj\n").as_bytes());
            kids.push(Object::Reference((i, 0)));
        }
        doc.max_id = last.0;
        kids.pop();
        for _ in 0..n {
            let node = dictionary! { "Type" => "Pages", "Kids" => vec![last.into()] };
            kids.push(doc.add_object(node).into());
        }
        let root = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => kids });
        with_root(&mut doc, root);
        let lines = b.iter().filter(|&&c| c == b'\n').count();
        LINES_READ.set(0);
        COPIES_READ.set(0);
        assert!(!mend_page_tree(&mut doc, &b).unwrap());
        assert!(LINES_READ.get() <= lines, "read {} lines", LINES_READ.get());
        let copies = COPIES_READ.get();
        assert!(copies <= n + 1, "read {copies} copies");
    }

    #[test]
    fn dictionaries_end_at_their_own_brackets() {
        let b = b"<< /A (a >> b \\) c) /B <414243> /C << /D 1 >> % >>\n>> trailing";
        assert_eq!(dictionary_len(b), Some(b.len() - " trailing".len()));
        assert_eq!(dictionary_len(b"<< /A 1"), None);
    }

    #[test]
    fn headers_need_whole_tokens() {
        assert_eq!(object_header(b"12 0 obj\n<<"), Some((12, 0)));
        assert_eq!(object_header(b"12 0 obj<<"), Some((12, 0)));
        assert_eq!(object_header(b"12 0 objx"), None);
        assert_eq!(object_header(b"12 obj"), None);
    }

    #[test]
    fn objects_inside_stream_data_are_skipped() {
        let b = b"%PDF-1.7\n1 0 obj\n<< /Length 9 >>\nstream\n2 0 obj\nendstream\nendobj\n3 0 obj\n1\nendobj\n";
        assert_eq!(numbers(&scan_objects(b)), vec![1, 3]);
    }

    fn numbers(scan: &Scan) -> Vec<u32> {
        scan.objects.keys().copied().collect()
    }

    #[test]
    fn streams_end_by_their_length() {
        let b = b"1 0 obj\n<< /Length 18 >>\nstream\nendstream\n2 0 obj\nendstream\nendobj\n";
        let scan = scan_objects(b);
        assert_eq!(numbers(&scan), vec![1]);
        assert_eq!(scan.streams, vec![25..b.len() - 8]);
        // A length that doesn't reach an `endstream` isn't used, nor an indirect one with no
        // object holding it.
        for length in ["14", "16", "9 0 R", "-3"] {
            let b = format!("1 0 obj\n<< /Length {length} >>\nstream\nab\nendstream\n2 0 obj\n");
            assert_eq!(numbers(&scan_objects(b.as_bytes())), vec![1, 2]);
        }
    }

    #[test]
    fn streams_end_by_an_indirect_length() {
        // The length object comes after the stream; an earlier copy that doesn't fit is
        // passed over, and the latest that fits is used.
        let b = b"1 0 obj\n<< /Length 9 0 R >>\nstream\nendstream\n2 0 obj\nendstream\nendobj\n\
                  9 0 obj\n18\nendobj\n9 0 obj 3 endobj\n";
        assert_eq!(numbers(&scan_objects(b)), vec![1, 9]);
        let at = |s: &[u8]| b.windows(s.len()).position(|w| w == s).unwrap();
        assert_eq!(
            integer_objects(b).get(&(9, 0)),
            Some(&vec![(at(b"9 0 obj\n18"), 18), (at(b"9 0 obj 3"), 3)])
        );
        // A different generation isn't the same object.
        let b = b"1 0 obj\n<< /Length 9 1 R >>\nstream\nendstream\n2 0 obj\nendstream\nendobj\n\
                  9 0 obj\n18\nendobj\n";
        assert_eq!(numbers(&scan_objects(b)), vec![1, 2, 9]);
    }

    #[test]
    fn a_length_inside_the_stream_data_is_not_used() {
        // The data holds an `endstream` and then a later copy of the length object, which
        // would end the stream there and make the rest of the data objects.
        let data = "x\nendstream\n9 0 obj\n2\nendobj\n2 0 obj\n<< >>\nendobj";
        for before in [true, false] {
            let length = format!("9 0 obj\n{}\nendobj\n", data.len());
            let stream =
                format!("1 0 obj\n<< /Length 9 0 R >>\nstream\n{data}\nendstream\nendobj\n");
            let b = if before {
                length + &stream
            } else {
                stream + &length
            };
            let scan = scan_objects(b.as_bytes());
            assert_eq!(numbers(&scan), vec![1, 9], "length before: {before}");
            let at = b.find("stream\nx").unwrap();
            assert_eq!(scan.streams, vec![at..b.rfind("endstream").unwrap() + 9]);
        }
        // Nor one whose value would end the stream past itself: it would be data then too.
        let data = "x\n9 0 obj\n0000\nendobj";
        let b = format!(
            "1 0 obj\n<< /Length 9 0 R >>\nstream\n{data}\nendstream\nendobj\n9 0 obj\n{}\n\
             endobj\n2 0 obj\n<< /Length 3 >>\nstream\nabc\nendstream\nendobj\n",
            data.len()
        );
        let start = b.find("x\n").unwrap();
        let far = b.rfind("endstream").unwrap() - start;
        let b = b.replace("0000", &format!("{far:04}"));
        assert_eq!(numbers(&scan_objects(b.as_bytes())), vec![1, 2, 9]);
    }

    #[test]
    fn trailers_inside_streams_are_not_used() {
        let b = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
                  2 0 obj\n<< /Length 25 >>\nstream\ntrailer\n<< /Root 9 0 R >>\nendstream\n\
                  trailer\n<< /Root 1 0 R >>\n3 0 obj\n<< /Length 25 >>\nstream\n\
                  trailer\n<< /Root 9 0 R >>\nendstream\nendobj\n";
        let scan = scan_objects(b);
        let trailer = newest_trailer(b, &scan).unwrap();
        assert_eq!(
            trailer.get(b"Root").unwrap().as_reference().unwrap(),
            (1, 0)
        );
    }

    #[test]
    fn trailer_values_are_written_back_readably() {
        let mut d = Dictionary::new();
        d.set("Root", Object::Reference((4, 0)));
        d.set(
            "ID",
            vec![
                Object::string_literal(b"a)b".to_vec()),
                Object::Name(b"x y#".to_vec()),
            ],
        );
        let mut s = String::new();
        write_object(&mut s, &Object::Dictionary(d.clone()), 0);
        let back = read_dictionary(s.as_bytes()).unwrap();
        assert_eq!(back.get(b"Root").unwrap(), d.get(b"Root").unwrap());
        let id = back.get(b"ID").unwrap().as_array().unwrap();
        assert_eq!(id[0].as_str().unwrap(), b"a)b");
        assert_eq!(id[1].as_name().unwrap(), b"x y#");
    }
}
