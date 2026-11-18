//! What changed in a signed document after each signature, and whether the signer allowed
//! it: Acrobat's allowed-changes analysis. See docs/signatures-in-depth.md.
//!
//! A change made after signing is appended to the file as a new revision. For each
//! signature, the revisions after it are read with LimarePDF's own strict reader of
//! cross-reference sections, because lopdf is lenient in ways that would hide changes (it
//! corrects bad offsets and rebuilds broken tables). lopdf is used
//! only for object contents, after checking that it reads the same objects. Every file
//! LimarePDF opens gets the same check over its whole chain of revisions ([`compare_reading`]),
//! so what LimarePDF shows, edits and signs is what the specification's reading holds.
//!
//! Each version a later signature signed is compared with the one before it, so a change
//! made and undone between two signatures still counts. Every object that differs is
//! judged by each role it plays in the newer version (page content, comment, form field,
//! signature, ...); a change no role allows is disallowed, and so is anything LimarePDF doesn't
//! recognise. Links between structures (a bookmark pointing to a page, a tag pointing to an
//! annotation) don't make the target part of the linking structure.

use crate::budget;
use crate::forms;
use crate::sig_verify::{is_white, FieldLock, Lexer, Permissions, Tok, Versions};
use crate::Pdf;
use lopdf::xref::XrefEntry;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------- report types

/// Something that changed after a signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Change {
    pub kind: ChangeKind,
    /// The page it is on (zero-based), where it has one.
    pub page: Option<usize>,
    /// Why the signer didn't allow it; `None` when allowed.
    pub refused: Option<Refusal>,
}

impl Change {
    pub fn allowed(&self) -> bool {
        self.refused.is_none()
    }
}

/// The kinds of change, following Acrobat's list.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    /// A form field's value (and its appearance) changed.
    FieldFilled(String),
    /// A form field was made read-only, as signing a field that locks it does.
    FieldMadeReadOnly(String),
    /// An empty signature field was signed.
    Signed(String),
    /// A document timestamp was added.
    DocumentTimestamp(String),
    /// A signature field was added (signed in the same step or not).
    SignatureFieldAdded(String),
    CommentAdded,
    CommentChanged,
    CommentRemoved,
    /// Form-wide settings used for filling in (fonts, default appearance).
    FormSettings,
    /// Appearances stored for comment icons (Acrobat keeps them in the `/Names /AP` tree).
    CommentAppearances,
    /// Certificates and revocation information for long-term validation (`/DSS`).
    ValidationData,
    /// Adobe Reader usage rights removed (as Acrobat does when it saves).
    UsageRightsRemoved,
    /// The document information or XMP metadata.
    Metadata,
    // Never allowed after signing:
    PageContent,
    /// Pages added, removed or reordered.
    PagesChanged,
    /// A link or another annotation that isn't a comment.
    AnnotationChanged,
    FieldAdded(String),
    FieldRemoved(String),
    /// Anything about a field other than its value: position, type, flags, actions.
    FieldChanged(String),
    /// A signature, its dictionary or its appearance changed, or it was removed.
    SignatureChanged(String),
    /// Actions or scripts.
    Actions,
    /// Document-level structure, with what changed.
    DocumentChanged(String),
    /// A change LimarePDF doesn't recognise, with where.
    Unrecognised(String),
    /// The appended revisions aren't well formed, with why.
    Malformed(String),
}

/// Why a change isn't allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Never allowed after signing.
    Never,
    /// The document's certification allows less.
    Certification(Permissions),
    /// This signature locked the field, or limited changes to the document.
    Locked,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FieldFilled(n) => write!(f, "form field \"{n}\" filled in"),
            Self::FieldMadeReadOnly(n) => write!(f, "form field \"{n}\" made read-only"),
            Self::Signed(n) => write!(f, "signed in field \"{n}\""),
            Self::DocumentTimestamp(_) => write!(f, "document timestamp added"),
            Self::SignatureFieldAdded(n) => write!(f, "signature field \"{n}\" added"),
            Self::CommentAdded => write!(f, "comment added"),
            Self::CommentChanged => write!(f, "comment changed"),
            Self::CommentRemoved => write!(f, "comment removed"),
            Self::FormSettings => write!(f, "form settings for filling in changed"),
            Self::CommentAppearances => write!(f, "appearances for comments stored"),
            Self::ValidationData => write!(f, "validation data added"),
            Self::UsageRightsRemoved => write!(f, "Adobe Reader usage rights removed"),
            Self::Metadata => write!(f, "document information changed"),
            Self::PageContent => write!(f, "page content changed"),
            Self::PagesChanged => write!(f, "pages added, removed or reordered"),
            Self::AnnotationChanged => {
                write!(f, "a link or other annotation that isn't a comment changed")
            }
            Self::FieldAdded(n) => write!(f, "form field \"{n}\" added"),
            Self::FieldRemoved(n) => write!(f, "form field \"{n}\" removed"),
            Self::FieldChanged(n) => write!(f, "form field \"{n}\" changed beyond its value"),
            Self::SignatureChanged(n) => {
                write!(f, "the signature in field \"{n}\" changed or was removed")
            }
            Self::Actions => write!(f, "actions or scripts added or changed"),
            Self::DocumentChanged(w) => write!(f, "document structure changed ({w})"),
            Self::Unrecognised(w) => write!(f, "a change LimarePDF doesn't recognise ({w})"),
            Self::Malformed(w) => write!(f, "the later additions are malformed: {w}"),
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(p) = self.page {
            write!(f, " on page {}", p + 1)?;
        }
        Ok(())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Never => "never allowed after signing",
            Self::Certification(Permissions::NoChanges) => "the certification allows no changes",
            Self::Certification(Permissions::FormFilling) => {
                "the certification allows only form filling and signing"
            }
            Self::Certification(Permissions::FormFillingAndComments) => {
                "the certification allows only form filling, signing and comments"
            }
            Self::Locked => "this signature locked it",
        })
    }
}

// ---------------------------------------------------------------- entry point

/// What one signature needs for the analysis.
pub(crate) struct Signed<'a> {
    /// Where its signed version ends.
    pub end: usize,
    pub locks: Option<&'a FieldLock>,
}

/// The changes after each signature in `sigs`, judged against the certification
/// `certified` (the strictest level any certification in the document claims) and each
/// signature's own locks. `versions` opens the signed versions. `listed` are the fields
/// whose signatures the report lists: a field signed after signing is allowed as signing
/// only when it's one of them, as nothing else checks its signature.
pub(crate) fn analyse(
    versions: &mut Versions,
    sigs: &[Signed],
    listed: &HashSet<ObjectId>,
    certified: Option<Permissions>,
) -> Vec<Vec<Change>> {
    let bytes = versions.bytes;
    let ends: Vec<usize> = sigs.iter().map(|s| s.end).collect();
    let mut cache: HashMap<(usize, usize), Vec<Seen>> = HashMap::new();
    sigs.iter()
        .map(|s| {
            let seen = changes_after(versions, bytes, s.end, &ends, listed, &mut cache);
            let mut once: HashSet<Change> = HashSet::new();
            let mut out: Vec<Change> = Vec::new();
            for x in seen {
                let c = Change {
                    refused: refusal(&x.need, certified, s.locks),
                    kind: x.kind,
                    page: x.page,
                };
                if once.insert(c.clone()) {
                    out.push(c);
                }
            }
            out.sort_by(|a, b| (a.allowed(), &a.kind, a.page).cmp(&(b.allowed(), &b.kind, b.page)));
            out
        })
        .collect()
}

/// What a change needs to be allowed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Need {
    Never,
    /// Always allowed: validation data, metadata.
    Nothing,
    /// Form filling, of this field (`None`: form-wide settings).
    Fill(Option<String>),
    /// Signing in `field`. `new_visible` is set for a field added after signing: whether it
    /// shows on the page. A document timestamp needs no form-filling permission.
    Sign {
        field: String,
        new_visible: Option<bool>,
        timestamp: bool,
    },
    Comment,
}

/// A change found, before judging it for a particular signature.
#[derive(Clone, Debug)]
struct Seen {
    kind: ChangeKind,
    page: Option<usize>,
    need: Need,
}

fn seen(kind: ChangeKind, page: Option<usize>, need: Need) -> Seen {
    Seen { kind, page, need }
}

fn never(kind: ChangeKind, page: Option<usize>) -> Seen {
    seen(kind, page, Need::Never)
}

fn allowed_at(need: &Need, p: Permissions) -> bool {
    match need {
        Need::Never => false,
        Need::Nothing => true,
        Need::Fill(_) => p >= Permissions::FormFilling,
        Need::Sign {
            new_visible,
            timestamp,
            ..
        } => (*timestamp || p >= Permissions::FormFilling) && *new_visible != Some(true),
        Need::Comment => p >= Permissions::FormFillingAndComments,
    }
}

fn refusal(
    need: &Need,
    certified: Option<Permissions>,
    lock: Option<&FieldLock>,
) -> Option<Refusal> {
    if *need == Need::Never {
        return Some(Refusal::Never);
    }
    if let Some(p) = certified.filter(|&p| !allowed_at(need, p)) {
        return Some(Refusal::Certification(p));
    }
    let lock = lock?;
    if lock.permissions.is_some_and(|p| !allowed_at(need, p)) {
        return Some(Refusal::Locked);
    }
    let field = match need {
        Need::Fill(Some(f)) => f,
        Need::Sign {
            field,
            timestamp: false,
            ..
        } => field,
        _ => return None,
    };
    lock.locks(field).then_some(Refusal::Locked)
}

/// The changes after the version ending at `end` (see [`changes_between`]). A document
/// other PDF apps may read differently from LimarePDF has a change that is never allowed.
fn changes_after(
    versions: &mut Versions,
    bytes: &[u8],
    end: usize,
    sig_ends: &[usize],
    listed: &HashSet<ObjectId>,
    cache: &mut HashMap<(usize, usize), Vec<Seen>>,
) -> Vec<Seen> {
    if bytes[end..].iter().all(|&c| is_white(c)) {
        return Vec::new();
    }
    let mut out = changes_between(versions, bytes, end, sig_ends, listed, cache);
    // What LimarePDF shows of the document must be what other apps show, whatever changed.
    if let Some(why) = versions.peek(bytes.len()).and_then(|p| p.differs.as_ref()) {
        if !out.iter().any(|s| s.need == Need::Never) {
            out.push(never(
                ChangeKind::Malformed(format!(
                    "other PDF apps may read the document differently from LimarePDF ({why})"
                )),
                None,
            ));
        }
    }
    out
}

/// The changes after the version ending at `end`, version by version: each later
/// signature's signed version is compared with the one before it, and the whole file with
/// the last.
fn changes_between(
    versions: &mut Versions,
    bytes: &[u8],
    end: usize,
    sig_ends: &[usize],
    listed: &HashSet<ObjectId>,
    cache: &mut HashMap<(usize, usize), Vec<Seen>>,
) -> Vec<Seen> {
    let malformed = |why: String| vec![never(ChangeKind::Malformed(why), None)];
    let sections = match read_chain(bytes, end) {
        Ok(s) => s,
        Err(why) => return malformed(why),
    };
    // A revision ends at `at` when only white space lies between, either way round: a
    // signature may end at "%%EOF", before the end of line a revision's end takes in. That
    // is at most 2 bytes (`revision_end`), so a run of white space after `at` isn't looked
    // through once for each revision ending after it.
    let ends_at = |s: &Section, at: usize| {
        if s.end > at + 2 {
            return false;
        }
        let (lo, hi) = (s.end.min(at), s.end.max(at));
        let white = bytes[lo..hi].iter().take_while(|&&c| is_white(c)).count();
        #[cfg(test)]
        tests::SCANNED.set(tests::SCANNED.get() + (white + 1).min(hi - lo));
        white == hi - lo
    };
    let ends_by = |s: &Section, at: usize| s.end <= at || ends_at(s, at);
    // The versions to compare: this one, each later signed version that is one of the
    // revisions read, and the whole file.
    let mut anchors = vec![end];
    let mut later: Vec<usize> = sig_ends
        .iter()
        .copied()
        .filter(|&e| e > end && e < bytes.len())
        .filter(|&e| sections.iter().any(|s| ends_at(s, e)))
        .collect();
    later.sort_unstable();
    later.dedup();
    anchors.extend(later);
    anchors.push(bytes.len());

    let mut out = Vec::new();
    for w in anchors.windows(2) {
        let (a, b) = (w[0], w[1]);
        // Newest first, as read.
        let between: Vec<&Section> = sections
            .iter()
            .filter(|s| s.offset >= a && ends_by(s, b))
            .collect();
        if between.is_empty() {
            continue;
        }
        if let Some(found) = cache.get(&(a, b)) {
            out.extend(found.iter().cloned());
            continue;
        }
        let before: Vec<&Section> = sections
            .iter()
            .filter(|s| s.offset >= end && ends_by(s, a))
            .collect();
        let found = compare_versions(versions, end, a, b, &before, &between, listed);
        let stop = found
            .iter()
            .any(|s| matches!(s.kind, ChangeKind::Malformed(_)));
        out.extend(found.iter().cloned());
        cache.insert((a, b), found);
        if stop {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------- cross-reference sections

/// The most cross-reference sections read after a signature; more is refused as
/// malformed rather than spending unbounded time.
const MAX_SECTIONS: usize = 2000;
/// The largest decoded cross-reference stream accepted (bytes).
const MAX_XREF_STREAM: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Free,
    InUse { offset: usize, gen: u16 },
    Compressed { container: u32, index: u32 },
}

/// One revision appended after a signature: its cross-reference section.
#[derive(Debug)]
struct Section {
    /// Where the section starts, and where its revision ends (just after `%%EOF` and
    /// its end of line).
    offset: usize,
    end: usize,
    /// Its entries in precedence order: for a number listed twice, the first counts.
    entries: Vec<(u32, Entry)>,
    /// Where a hybrid revision's cross-reference stream starts.
    stream_at: Option<usize>,
}

/// The `startxref` value of the revision `prefix` ends with (`startxref N %%EOF`, perhaps
/// followed by white space).
pub(crate) fn last_startxref(prefix: &[u8]) -> Option<usize> {
    let t = trim_white_end(prefix).strip_suffix(b"%%EOF")?;
    let t = trim_white_end(t);
    let digits = t.iter().rev().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 || digits > 15 {
        return None;
    }
    let n = std::str::from_utf8(&t[t.len() - digits..])
        .ok()?
        .parse()
        .ok()?;
    trim_white_end(&t[..t.len() - digits])
        .ends_with(b"startxref")
        .then_some(n)
}

fn trim_white_end(b: &[u8]) -> &[u8] {
    let n = b.iter().rev().take_while(|&&c| is_white(c)).count();
    &b[..b.len() - n]
}

/// The cross-reference sections appended after the version ending at `signed_end`,
/// newest first, read from the end of the file along the `/Prev` chain, which must lead
/// back to that version's own section.
fn read_chain(bytes: &[u8], signed_end: usize) -> Result<Vec<Section>, String> {
    let signed_xref = last_startxref(&bytes[..signed_end])
        .ok_or("the signed version doesn't end with a cross-reference pointer")?;
    let mut at = last_startxref(bytes).ok_or(
        "the file doesn't end with a complete revision (data after the last end-of-file \
         marker, or no cross-reference pointer)",
    )?;
    let mut sections: Vec<Section> = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if at < signed_end {
            if at != signed_xref {
                return Err("a later revision doesn't build on the signed version".into());
            }
            return Ok(sections);
        }
        if !seen.insert(at) || sections.len() >= MAX_SECTIONS {
            return Err("the chain of revisions loops or is too long".into());
        }
        let read = read_section(bytes, at)?;
        let end = revision_end(bytes, read.after, at)
            .ok_or_else(|| format!("the revision at byte {at} isn't closed properly"))?;
        if let Some(newer) = sections.last() {
            if end > newer.offset {
                return Err("revisions overlap".into());
            }
        } else if end < bytes.len() && !bytes[end..].iter().all(|&c| is_white(c)) {
            return Err("data follows the last revision".into());
        }
        let mut entries = read.entries;
        // A hybrid file: a cross-reference stream adds to the table, ranking below it.
        if let Some(stm) = read.xref_stm {
            if stm < signed_end || stm >= at {
                return Err("a later revision points back into earlier data".into());
            }
            let extra = read_section(bytes, stm)?;
            if extra.kind != SectionKind::Stream {
                return Err("a hybrid revision's stream isn't a cross-reference stream".into());
            }
            entries.extend(extra.entries);
        }
        sections.push(Section {
            offset: at,
            end,
            entries,
            stream_at: read.xref_stm,
        });
        at = read
            .prev
            .ok_or("a later revision replaces the whole cross-reference instead of adding to it")?;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SectionKind {
    Table,
    Stream,
}

struct ReadSection {
    kind: SectionKind,
    entries: Vec<(u32, Entry)>,
    prev: Option<usize>,
    xref_stm: Option<usize>,
    /// Where the section (with its trailer, or its object) ends.
    after: usize,
}

fn read_section(bytes: &[u8], at: usize) -> Result<ReadSection, String> {
    let bad = || format!("the cross-reference section at byte {at} is malformed");
    let mut lx = Lexer::new(bytes, at);
    let (start, tok, _) = lx.next().ok_or_else(bad)?;
    if !bytes[at..start].iter().all(|&c| is_white(c)) {
        return Err(bad());
    }
    match tok {
        Tok::Word(b"xref") => read_table(bytes, lx).ok_or_else(bad),
        Tok::Word(_) => read_xref_stream(bytes, Lexer::new(bytes, at)).ok_or_else(bad),
        _ => Err(bad()),
    }
}

fn word_num<T: std::str::FromStr>(t: Option<(usize, Tok, usize)>) -> Option<T> {
    match t? {
        (_, Tok::Word(w), _) if w.iter().all(u8::is_ascii_digit) => {
            std::str::from_utf8(w).ok()?.parse().ok()
        }
        _ => None,
    }
}

fn read_table(bytes: &[u8], mut lx: Lexer) -> Option<ReadSection> {
    let mut entries = Vec::new();
    loop {
        let mut look = lx.clone();
        if let Some((_, Tok::Word(b"trailer"), _)) = look.next() {
            lx = look;
            break;
        }
        let first: u32 = word_num(lx.next())?;
        let count: usize = word_num(lx.next())?;
        if count > bytes.len() / 18 {
            return None;
        }
        for i in 0..count {
            let num = first.checked_add(u32::try_from(i).ok()?)?;
            let offset: usize = word_num(lx.next())?;
            let gen: u32 = word_num(lx.next())?;
            let e = match lx.next()? {
                (_, Tok::Word(b"n"), _) => Entry::InUse {
                    offset,
                    gen: u16::try_from(gen).ok()?,
                },
                (_, Tok::Word(b"f"), _) => Entry::Free,
                _ => return None,
            };
            entries.push((num, e));
        }
    }
    let trailer = match read_object(&mut lx, 0)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    Some(ReadSection {
        kind: SectionKind::Table,
        entries,
        prev: direct_offset(&trailer, b"Prev")?,
        xref_stm: direct_offset(&trailer, b"XRefStm")?,
        after: lx.pos(),
    })
}

/// An optional offset entry: absent is fine, present must be a whole number.
fn direct_offset(d: &Dictionary, key: &[u8]) -> Option<Option<usize>> {
    match d.get(key) {
        Err(_) => Some(None),
        Ok(Object::Integer(n)) => Some(Some(usize::try_from(*n).ok()?)),
        Ok(_) => None,
    }
}

fn read_xref_stream(bytes: &[u8], mut lx: Lexer) -> Option<ReadSection> {
    let _: u32 = word_num(lx.next())?;
    let _: u16 = word_num(lx.next())?;
    if !matches!(lx.next()?, (_, Tok::Word(b"obj"), _)) {
        return None;
    }
    let dict = match read_object(&mut lx, 0)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    let (_, Tok::Word(b"stream"), mut start) = lx.next()? else {
        return None;
    };
    start += match bytes.get(start..start + 2)? {
        b"\r\n" => 2,
        [b'\n', _] => 1,
        _ => return None,
    };
    let len = usize::try_from(dict.get(b"Length").ok()?.as_i64().ok()?).ok()?;
    let data = bytes.get(start..start.checked_add(len)?)?;
    let mut tail = Lexer::new(bytes, start + len);
    if !matches!(tail.next()?, (_, Tok::Word(b"endstream"), _))
        || !matches!(tail.next()?, (_, Tok::Word(b"endobj"), _))
    {
        return None;
    }
    if dict.get(b"Type").ok()?.as_name().ok()? != b"XRef" {
        return None;
    }
    let decoded = Stream::new(dict.clone(), data.to_vec())
        .decompressed_content_with_limit(MAX_XREF_STREAM)
        .ok()?;
    let ints = |key: &[u8]| -> Option<Vec<i64>> {
        dict.get(key)
            .ok()?
            .as_array()
            .ok()?
            .iter()
            .map(|o| o.as_i64().ok())
            .collect()
    };
    let w: Vec<usize> = ints(b"W")?
        .into_iter()
        .map(|x| usize::try_from(x).ok().filter(|&x| x <= 8))
        .collect::<Option<_>>()?;
    let [w0, w1, w2] = w[..] else {
        return None;
    };
    let row = w0 + w1 + w2;
    if row == 0 {
        return None;
    }
    let size = dict.get(b"Size").ok()?.as_i64().ok()?;
    let index = match dict.get(b"Index") {
        Ok(_) => ints(b"Index")?,
        Err(_) => vec![0, size],
    };
    if index.len() % 2 != 0 {
        return None;
    }
    let field = |b: &[u8]| b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut entries = Vec::new();
    let mut pos = 0;
    for pair in index.chunks(2) {
        let first = u32::try_from(pair[0]).ok()?;
        let count = usize::try_from(pair[1]).ok()?;
        if count > decoded.len() / row {
            return None;
        }
        for i in 0..count {
            let r = decoded.get(pos..pos + row)?;
            pos += row;
            let kind = if w0 == 0 { 1 } else { field(&r[..w0]) };
            let (f1, f2) = (field(&r[w0..w0 + w1]), field(&r[w0 + w1..]));
            let num = first.checked_add(u32::try_from(i).ok()?)?;
            let e = match kind {
                0 => Entry::Free,
                1 => Entry::InUse {
                    offset: usize::try_from(f1).ok()?,
                    gen: u16::try_from(f2).ok()?,
                },
                2 => Entry::Compressed {
                    container: u32::try_from(f1).ok()?,
                    index: u32::try_from(f2).ok()?,
                },
                _ => return None,
            };
            entries.push((num, e));
        }
    }
    Some(ReadSection {
        kind: SectionKind::Stream,
        entries,
        prev: direct_offset(&dict, b"Prev")?,
        xref_stm: None,
        after: tail.pos(),
    })
}

/// Where the revision whose section starts at `at` ends: after the section (ending at
/// `after`) come `startxref`, `at` and `%%EOF`.
fn revision_end(bytes: &[u8], after: usize, at: usize) -> Option<usize> {
    let mut lx = Lexer::new(bytes, after);
    if !matches!(lx.next()?, (_, Tok::Word(b"startxref"), _)) || word_num::<usize>(lx.next())? != at
    {
        return None;
    }
    let mut p = lx.pos();
    while bytes.get(p).is_some_and(|&c| is_white(c)) {
        p += 1;
    }
    let mut end = p + bytes.get(p..)?.strip_prefix(b"%%EOF").map(|_| 5)?;
    if bytes.get(end..end + 2) == Some(b"\r\n") {
        end += 2;
    } else if matches!(bytes.get(end), Some(b'\n' | b'\r')) {
        end += 1;
    }
    Some(end)
}

/// One direct object, enough for cross-reference dictionaries: numbers, names (with
/// `#xx` escapes), references, arrays, dictionaries. Strings are kept empty.
fn read_object(lx: &mut Lexer, depth: usize) -> Option<Object> {
    if depth > 32 {
        return None;
    }
    let (_, tok, _) = lx.next()?;
    Some(match tok {
        Tok::DictOpen => {
            let mut d = Dictionary::new();
            loop {
                match lx.next()? {
                    (_, Tok::DictClose, _) => break,
                    (_, Tok::Name(k), _) => {
                        let v = read_object(lx, depth + 1)?;
                        d.set(decode_name(k)?, v);
                    }
                    _ => return None,
                }
            }
            Object::Dictionary(d)
        }
        Tok::ArrayOpen => {
            let mut a = Vec::new();
            loop {
                let mut look = lx.clone();
                if let (_, Tok::ArrayClose, _) = look.next()? {
                    *lx = look;
                    break;
                }
                a.push(read_object(lx, depth + 1)?);
            }
            Object::Array(a)
        }
        Tok::Name(n) => Object::Name(decode_name(n)?),
        Tok::Hex | Tok::Literal => Object::String(Vec::new(), StringFormat::Literal),
        Tok::Word(b"true") => Object::Boolean(true),
        Tok::Word(b"false") => Object::Boolean(false),
        Tok::Word(b"null") => Object::Null,
        Tok::Word(w) => {
            let s = std::str::from_utf8(w).ok()?;
            match s.parse::<i64>() {
                Ok(n) => {
                    // Perhaps `N G R`.
                    let mut look = lx.clone();
                    let gen: Option<u16> = word_num(look.next());
                    let r = matches!(look.next(), Some((_, Tok::Word(b"R"), _)));
                    match (gen, r, u32::try_from(n)) {
                        (Some(g), true, Ok(num)) => {
                            *lx = look;
                            Object::Reference((num, g))
                        }
                        _ => Object::Integer(n),
                    }
                }
                Err(_) => Object::Real(s.parse().ok()?),
            }
        }
        Tok::DictClose | Tok::ArrayClose => return None,
    })
}

fn decode_name(n: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(n.len());
    let mut i = 0;
    while i < n.len() {
        if n[i] == b'#' {
            let h = std::str::from_utf8(n.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(n[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Whether object `id` starts at `offset`: `N G obj`.
fn header_at(bytes: &[u8], offset: usize, id: ObjectId) -> bool {
    header_id(bytes, offset) == Some(id)
}

/// The object whose header (`N G obj`) starts at `offset`, perhaps after white space.
fn header_id(bytes: &[u8], offset: usize) -> Option<ObjectId> {
    let mut lx = Lexer::new(bytes, offset);
    let first = lx.next();
    if !first.is_some_and(|(s, _, _)| bytes[offset..s].iter().all(|&c| is_white(c))) {
        return None;
    }
    let id = (word_num(first)?, word_num(lx.next())?);
    matches!(lx.next(), Some((_, Tok::Word(b"obj"), _))).then_some(id)
}

/// Whether the newest cross-reference section of `bytes` is a hybrid one (a table whose
/// trailer names a cross-reference stream too, `/XRefStm`). lopdf before 0.46 read such a
/// section's stream only while it was the newest, so a revision appended after it hid the
/// objects the stream lists; the read-back after appending still names the layout.
pub(crate) fn newest_is_hybrid(bytes: &[u8]) -> bool {
    last_startxref(bytes)
        .and_then(|at| read_section(bytes, at).ok())
        .is_some_and(|s| s.xref_stm.is_some())
}

/// Checks a revision LimarePDF appended to the version ending at `base_end`, with this module's
/// strict reader: the file must end with exactly one new revision building on that
/// version, whose cross-reference section lists `written` and nothing else (besides the
/// head of the free list and a cross-reference stream's own entry), each where its object
/// starts in the new revision. Returns those positions.
pub(crate) fn check_appended(
    bytes: &[u8],
    base_end: usize,
    written: &[ObjectId],
) -> Result<HashMap<ObjectId, usize>, String> {
    let chain = read_chain(bytes, base_end)?;
    let [section] = &chain[..] else {
        return Err(format!("{} revisions were appended, not one", chain.len()));
    };
    let mut found = HashMap::new();
    for &(num, e) in &section.entries {
        match e {
            Entry::Free if num == 0 => {}
            // The cross-reference stream itself.
            Entry::InUse { offset, .. } if offset == section.offset => {}
            Entry::InUse { offset, gen } => {
                let id = (num, gen);
                if !(base_end..section.offset).contains(&offset) || !header_at(bytes, offset, id) {
                    return Err(format!("object {num} isn't where its entry says"));
                }
                if found.insert(id, offset).is_some() {
                    return Err(format!("object {num} is listed twice"));
                }
            }
            _ => return Err(format!("unexpected entry for object {num}")),
        }
    }
    let want: HashSet<ObjectId> = written.iter().copied().collect();
    if found.len() != want.len() || !found.keys().all(|id| want.contains(id)) {
        return Err("the new revision doesn't list exactly the objects written".into());
    }
    Ok(found)
}

// ---------------------------------------------------------------- the whole file

/// The largest decoded object stream read when comparing readings (bytes).
const MAX_OBJECT_STREAM: usize = 256 << 20;

/// How lopdf's reading of a file differs from that of a reader following the PDF
/// specification (Acrobat, pdfium, poppler). lopdf takes every object an object stream
/// holds that has no entry, and it repairs or misreads some damage. What LimarePDF shows,
/// edits and signs must be what other apps show.
pub(crate) struct Reading {
    /// Objects the file holds that such a reader doesn't see: deleted by a later revision,
    /// never listed, listed under another generation, or a stray copy in an object stream.
    /// lopdf holds some of them, and dropping those makes the two readings agree. A file
    /// that uses one reads differently in other apps: some find it by scanning the file.
    pub(crate) hidden: BTreeSet<ObjectId>,
    /// Object numbers the two readings may disagree on in a way dropping objects doesn't
    /// fix: lopdf misread or repaired them, or couldn't read them at all.
    pub(crate) unsure: HashSet<u32>,
    /// Whether the file ends with its cross-reference pointer. Readers find a pointer
    /// followed by other data in different ways.
    pub(crate) ends_cleanly: bool,
}

/// Compares lopdf's reading `doc` of `bytes` (the bytes it read) with the
/// specification's. Fails when the cross-reference information can't be read as written,
/// so the specification's reading isn't known.
pub(crate) fn compare_reading(bytes: &[u8], doc: &Document) -> Result<Reading, String> {
    // lopdf reads from the header on, and its offsets count from there.
    let start = bytes.windows(5).position(|w| w == b"%PDF-").unwrap_or(0);
    let bytes = &bytes[start..];
    let pointer = last_startxref(bytes);
    let (spec, deleted) = whole_xref(bytes, pointer.unwrap_or(doc.xref_start))?;
    let table = &doc.reference_table.entries;
    let mut unsure: HashSet<u32> = HashSet::new();
    let mut hidden = BTreeSet::new();

    // The entries must agree. Where the newest is free, lopdf may keep an older entry,
    // whose object is hidden below.
    for num in spec.keys().chain(table.keys()) {
        let agree = match (spec.get(num), table.get(num)) {
            (Some(Entry::Free), _) => true,
            (None, None | Some(XrefEntry::Free | XrefEntry::UnusableFree)) => true,
            (
                Some(Entry::InUse { offset, gen }),
                Some(XrefEntry::Normal {
                    offset: o,
                    generation: g,
                }),
            ) => *o as usize == *offset && g == gen,
            (
                Some(Entry::Compressed { container, index }),
                Some(XrefEntry::Compressed {
                    container: c,
                    index: i,
                }),
            ) => c == container && u32::from(*i) == *index,
            _ => false,
        };
        if !agree {
            unsure.insert(*num);
        }
    }
    // lopdf keeps an object under the number its header gives, whichever entry led to it.
    for (&num, e) in table {
        if let XrefEntry::Normal { offset, generation } = *e {
            let found = header_id(bytes, offset as usize);
            if found != Some((num, generation)) {
                unsure.insert(num);
                if let Some((other, _)) = found {
                    unsure.insert(other);
                }
            }
        }
    }

    // Object streams: each holds the objects its index lists, and a reader takes an object
    // from the stream at the place its entry gives. lopdf takes any object a stream holds
    // that has no entry of its own, and one whose own object it couldn't read.
    let mut copies: Vec<(u32, ObjectId)> = Vec::new();
    for (&(c, g), o) in &doc.objects {
        let Object::Stream(s) = o else { continue };
        if !s.dict.has_type(b"ObjStm") {
            continue;
        }
        let members =
            objstm_members(s).ok_or_else(|| format!("its object stream {c} can't be read"))?;
        let mut seen = HashSet::new();
        for (i, &n) in members.iter().enumerate() {
            if !seen.insert(n) {
                unsure.insert(n);
            }
            match spec.get(&n) {
                Some(Entry::Compressed { container, index }) if *container == c => {
                    if usize::try_from(*index).ok() != Some(i) {
                        unsure.insert(n);
                    }
                }
                Some(Entry::InUse { gen: 0, .. }) if doc.objects.contains_key(&(n, 0)) => {
                    copies.push((n, (c, g)));
                }
                // Deleted, or never listed.
                None | Some(Entry::Free) => {
                    hidden.insert((n, 0));
                }
                _ => {}
            }
        }
    }
    // lopdf's object equals the stray copy: either the two are the same, or lopdf couldn't
    // read the object itself and took the copy. Reading the file again without object
    // streams tells which.
    if doc.encryption_state.is_none() {
        let mut parsed: HashMap<ObjectId, lopdf::ObjectStream> = HashMap::new();
        let mut took = Vec::new();
        for (n, c) in copies {
            let os = match parsed.entry(c) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let Some(Object::Stream(s)) = doc.objects.get(&c) else {
                        continue;
                    };
                    e.insert(
                        lopdf::ObjectStream::new_with_limit(s, Some(MAX_OBJECT_STREAM))
                            .map_err(|_| format!("its object stream {} can't be read", c.0))?,
                    )
                }
            };
            let copy = os.objects.get(&(n, 0));
            if copy.is_some_and(|x| doc.objects.get(&(n, 0)).is_some_and(|o| same_object(x, o))) {
                took.push(n);
            }
        }
        if !took.is_empty() {
            let direct = Document::load_from_with_options(
                std::io::Cursor::new(bytes),
                lopdf::LoadOptions::with_filter(skip_object_streams),
            )
            .map_err(|_| "LimarePDF can't read it again without its object streams".to_string())?;
            unsure.extend(
                took.into_iter()
                    .filter(|n| !direct.objects.contains_key(&(*n, 0))),
            );
        }
    }

    for &(n, g) in doc.objects.keys() {
        let seen = match spec.get(&n) {
            None | Some(Entry::Free) => false,
            Some(Entry::InUse { gen, .. }) => g == *gen,
            Some(Entry::Compressed { container, .. }) => {
                g == 0 && matches!(spec.get(container), Some(Entry::InUse { .. }))
            }
        };
        if !seen {
            hidden.insert((n, g));
        }
    }
    // Objects a later revision deleted, which lopdf drops too.
    hidden.extend(deleted.iter().map(|(&n, e)| match *e {
        Entry::InUse { gen, .. } => (n, gen),
        _ => (n, 0),
    }));
    // Objects a reader finds that lopdf doesn't hold.
    for (&n, &e) in &spec {
        let id = match e {
            Entry::Free => continue,
            Entry::InUse { gen, .. } => (n, gen),
            Entry::Compressed { container, .. } => {
                if !matches!(spec.get(&container), Some(Entry::InUse { .. })) {
                    continue;
                }
                (n, 0)
            }
        };
        if !doc.objects.contains_key(&id) {
            unsure.insert(n);
        }
    }
    // A stream whose own entry gives a generation other than 0 isn't one readers agree on.
    for (&n, &e) in &spec {
        if let Entry::Compressed { container, .. } = e {
            if matches!(spec.get(&container), Some(Entry::InUse { gen, .. }) if *gen != 0) {
                unsure.insert(n);
            }
        }
    }
    Ok(Reading {
        hidden,
        unsure,
        ends_cleanly: pointer.is_some(),
    })
}

/// The cross-reference entry each object number has for a reader following the
/// specification: every section from the one at `at` along the `/Prev` chain (a hybrid
/// section's stream ranking after its table), the newest entry counting, free ones too.
/// Also, for each number that entry frees, the newest older entry placing an object: the
/// object a revision deleted.
#[allow(clippy::type_complexity)]
fn whole_xref(
    bytes: &[u8],
    mut at: usize,
) -> Result<(HashMap<u32, Entry>, HashMap<u32, Entry>), String> {
    let mut spec = HashMap::new();
    let mut deleted = HashMap::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(at) || seen.len() > MAX_SECTIONS {
            return Err("its chain of revisions loops or is too long".into());
        }
        let read = read_section(bytes, at)?;
        let mut entries = read.entries;
        if let Some(stm) = read.xref_stm {
            let extra = read_section(bytes, stm)?;
            if extra.kind != SectionKind::Stream {
                return Err("a hybrid revision's stream isn't a cross-reference stream".into());
            }
            entries.extend(extra.entries);
        }
        for (num, e) in entries {
            if *spec.entry(num).or_insert(e) == Entry::Free && e != Entry::Free {
                deleted.entry(num).or_insert(e);
            }
        }
        match read.prev {
            Some(p) => at = p,
            None => return Ok((spec, deleted)),
        }
    }
}

/// The object numbers an object stream holds, in order, when its index reads cleanly:
/// `/N` pairs of whole numbers before `/First`. lopdf reads every pair it finds, whatever
/// `/N` says, and other readers stop at `/N`.
fn objstm_members(s: &Stream) -> Option<Vec<u32>> {
    let content = s.get_plain_content_with_limit(MAX_OBJECT_STREAM).ok()?;
    if content.is_empty() {
        return Some(Vec::new());
    }
    let int = |key: &[u8]| usize::try_from(s.dict.get(key).ok()?.as_i64().ok()?).ok();
    let (first, n) = (int(b"First")?, int(b"N")?);
    let words: Vec<&str> = std::str::from_utf8(content.get(..first)?)
        .ok()?
        .split_whitespace()
        .collect();
    if words.len() != n.checked_mul(2)? {
        return None;
    }
    words
        .chunks(2)
        .map(|p| p[1].parse::<u32>().ok().and(p[0].parse().ok()))
        .collect()
}

/// A lopdf load filter that leaves object streams out, so lopdf neither keeps nor opens
/// them. lopdf uses the object returned only for objects taken from object streams (for
/// the others only `None` counts), and with this filter there are none.
fn skip_object_streams(id: ObjectId, o: &mut Object) -> Option<(ObjectId, Object)> {
    let objstm = matches!(o, Object::Stream(s) if s.dict.has_type(b"ObjStm"));
    (!objstm).then_some((id, Object::Null))
}

/// Every reference in `doc`, in its trailer and its objects, however deeply nested, but the
/// encryption dictionary's. lopdf drops that dictionary once it has decrypted the file,
/// while a cross-reference stream still names it; it holds no content, and the file
/// decrypted with it reads as other apps read it.
pub(crate) fn references(doc: &Document) -> HashSet<ObjectId> {
    fn content(d: &Dictionary) -> impl Iterator<Item = (&Vec<u8>, &Object)> {
        d.iter().filter(|(k, _)| k.as_slice() != b"Encrypt")
    }
    let mut out = HashSet::new();
    let mut stack: Vec<&Object> = content(&doc.trailer).map(|(_, o)| o).collect();
    stack.extend(doc.objects.values());
    while let Some(o) = stack.pop() {
        match o {
            Object::Reference(id) => {
                out.insert(*id);
            }
            Object::Array(a) => stack.extend(a),
            Object::Dictionary(d) => stack.extend(d.iter().map(|(_, o)| o)),
            Object::Stream(s) if s.dict.has_type(b"XRef") => {
                stack.extend(content(&s.dict).map(|(_, o)| o))
            }
            Object::Stream(s) => stack.extend(s.dict.iter().map(|(_, o)| o)),
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------- one step

/// A version of the document: lopdf's reading, with the objects LimarePDF's reader found freed
/// hidden. lopdf drops them itself since 0.47 (before, it ignored free entries); the check
/// doesn't rest on that.
struct Version<'a> {
    pdf: &'a Pdf,
    freed: HashSet<u32>,
}

impl Version<'_> {
    fn get(&self, id: ObjectId) -> Option<&Object> {
        if self.freed.contains(&id.0) {
            return None;
        }
        self.pdf.doc.objects.get(&id)
    }

    /// `o`, following references (a few steps at most).
    fn resolve<'b>(&'b self, mut o: &'b Object) -> Option<&'b Object> {
        for _ in 0..8 {
            match o {
                Object::Reference(id) => o = self.get(*id)?,
                o => return Some(o),
            }
        }
        None
    }

    fn dict<'b>(&'b self, o: &'b Object) -> Option<&'b Dictionary> {
        match self.resolve(o)? {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    fn dict_of(&self, id: ObjectId) -> Option<&Dictionary> {
        match self.get(id)? {
            Object::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    fn array<'b>(&'b self, o: &'b Object) -> Option<&'b Vec<Object>> {
        self.resolve(o)?.as_array().ok()
    }

    /// The object holding the array `o` refers to (as [`Version::resolve`] follows it);
    /// `None` for an array written in place, or for anything else.
    fn array_holder<'b>(&'b self, mut o: &'b Object) -> Option<ObjectId> {
        let mut at = None;
        for _ in 0..8 {
            match o {
                Object::Reference(id) => {
                    at = Some(*id);
                    o = self.get(*id)?;
                }
                Object::Array(_) => return at,
                _ => return None,
            }
        }
        None
    }

    fn name<'b>(&'b self, d: &'b Dictionary, key: &[u8]) -> Option<&'b [u8]> {
        self.resolve(d.get(key).ok()?)?.as_name().ok()
    }

    /// The ids lopdf holds for object number `num`.
    fn ids(&self, num: u32) -> Vec<ObjectId> {
        if self.freed.contains(&num) {
            return Vec::new();
        }
        self.pdf
            .doc
            .objects
            .range((num, 0)..=(num, u16::MAX))
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Compares the version ending at `a` with the one ending at `b`. `before` are the
/// sections between the signature's own version (ending at `sig_end`) and `a`; `between`
/// those between `a` and `b`; both newest first. `listed` as for [`analyse`].
fn compare_versions(
    versions: &mut Versions,
    sig_end: usize,
    a: usize,
    b: usize,
    before: &[&Section],
    between: &[&Section],
    listed: &HashSet<ObjectId>,
) -> Vec<Seen> {
    let malformed = |why: String| vec![never(ChangeKind::Malformed(why), None)];
    let bytes = versions.bytes;
    // Which objects the sections change, and which they free, newest entry first. Objects
    // are checked in number order, so a revision with several faults always gives the same
    // reason (a reason naming another object would read as a new change when saving).
    let effective = |secs: &[&Section]| {
        let mut m: BTreeMap<u32, Entry> = BTreeMap::new();
        for s in secs {
            for &(num, e) in &s.entries {
                if num != 0 {
                    m.entry(num).or_insert(e);
                }
            }
        }
        m
    };
    let freed = |m: &BTreeMap<u32, Entry>| -> HashSet<u32> {
        m.iter()
            .filter(|(_, e)| **e == Entry::Free)
            .map(|(n, _)| *n)
            .collect()
    };
    let newest = effective(between);
    // Frees before `a`, unless `between` reuses the number.
    let old_freed = freed(&effective(before));
    let new_freed: HashSet<u32> = {
        let mut all: Vec<&Section> = between.to_vec();
        all.extend(before.iter().copied());
        freed(&effective(&all))
    };
    versions.load(a);
    versions.load(b);
    let (Some(old_pdf), Some(new_pdf)) = (versions.peek(a), versions.peek(b)) else {
        return malformed(if a == sig_end {
            "LimarePDF can't read the document as it is after signing".into()
        } else {
            "LimarePDF can't read a later signed version".into()
        });
    };
    let old = Version {
        pdf: old_pdf,
        freed: old_freed,
    };
    let new = Version {
        pdf: new_pdf,
        freed: new_freed,
    };

    // lopdf must read the same objects LimarePDF's reader finds.
    let old_table = &old.pdf.doc.reference_table.entries;
    let new_table = &new.pdf.doc.reference_table.entries;
    // Cross-reference streams are objects too, which lopdf may not keep.
    let section_starts: HashSet<usize> = between
        .iter()
        .flat_map(|s| [Some(s.offset), s.stream_at])
        .flatten()
        .collect();
    let mut changed: HashSet<u32> = HashSet::new();
    for (&num, &e) in &newest {
        changed.insert(num);
        let ok = match e {
            Entry::Free => true,
            Entry::InUse { offset, gen } => {
                if offset < a || offset >= b {
                    return malformed(format!(
                        "object {num} points outside the revision that changes it"
                    ));
                }
                if !header_at(bytes, offset, (num, gen)) {
                    return malformed(format!(
                        "object {num} isn't where its cross-reference entry says"
                    ));
                }
                matches!(new_table.get(&num), Some(XrefEntry::Normal { offset: o, generation: g })
                    if *o as usize == offset && *g == gen)
                    && (section_starts.contains(&offset)
                        || new.pdf.doc.objects.contains_key(&(num, gen)))
            }
            Entry::Compressed { container, index } => {
                let fresh = matches!(newest.get(&container), Some(Entry::InUse { .. }));
                if !fresh {
                    return malformed(format!(
                        "object {num} is stored in an object stream from before"
                    ));
                }
                matches!(new_table.get(&num), Some(XrefEntry::Compressed { container: c, index: i })
                    if *c == container && u32::from(*i) == index)
                    && new.pdf.doc.objects.contains_key(&(num, 0))
            }
        };
        if !ok {
            return malformed(format!("LimarePDF can't read object {num} reliably"));
        }
    }
    // Everything else reads as before, except objects held in a rewritten object stream, and
    // object 0, which lopdf lists as free after reading a table but not a stream (an object
    // 0 it reads is still compared below).
    let nums: BTreeSet<u32> = old_table.keys().chain(new_table.keys()).copied().collect();
    for num in nums {
        if num == 0 || newest.contains_key(&num) {
            continue;
        }
        let (o, n) = (old_table.get(&num), new_table.get(&num));
        if let Some(XrefEntry::Compressed { container, .. }) = o {
            if newest.contains_key(container) {
                changed.insert(num);
                continue;
            }
        }
        let same = match (o, n) {
            (None, None) => true,
            (Some(x), Some(y)) => same_entry(x, y),
            _ => false,
        };
        if !same {
            return malformed(format!("LimarePDF can't read object {num} reliably"));
        }
    }
    let ids = |v: &Version| -> BTreeSet<ObjectId> { v.pdf.doc.objects.keys().copied().collect() };
    for id in ids(&old).union(&ids(&new)) {
        if changed.contains(&id.0) {
            continue;
        }
        let same = match (old.pdf.doc.objects.get(id), new.pdf.doc.objects.get(id)) {
            (Some(x), Some(y)) => same_object(x, y),
            (None, None) => true,
            _ => false,
        };
        if !same {
            return malformed(format!("LimarePDF can't read object {} reliably", id.0));
        }
    }

    let (old_roles, new_roles) = match (Roles::build(&old), Roles::build(&new)) {
        (Ok(o), Ok(n)) => (o, n),
        (Err(why), _) | (_, Err(why)) => return malformed(why),
    };
    let mut j = Judge {
        old: &old,
        new: &new,
        or: &old_roles,
        nr: &new_roles,
        listed,
        out: Vec::new(),
        pushed: HashSet::new(),
    };
    j.trailer();
    j.pages();
    j.annotations();
    j.fields();
    let mut changed: Vec<u32> = changed.into_iter().collect();
    changed.sort_unstable();
    for num in changed {
        let mut ids: Vec<ObjectId> = old.ids(num);
        ids.extend(new.ids(num));
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            j.object(id);
        }
    }
    j.out
}

fn same_entry(a: &XrefEntry, b: &XrefEntry) -> bool {
    match (a, b) {
        (
            XrefEntry::Normal {
                offset: o1,
                generation: g1,
            },
            XrefEntry::Normal {
                offset: o2,
                generation: g2,
            },
        ) => o1 == o2 && g1 == g2,
        (
            XrefEntry::Compressed {
                container: c1,
                index: i1,
            },
            XrefEntry::Compressed {
                container: c2,
                index: i2,
            },
        ) => c1 == c2 && i1 == i2,
        (XrefEntry::Free, XrefEntry::Free) | (XrefEntry::UnusableFree, XrefEntry::UnusableFree) => {
            true
        }
        _ => false,
    }
}

/// Objects equal in value: how a string is written (literal or hex) and where a stream
/// sits in the file don't count. Acrobat rewrites strings in its own way when saving.
fn same_object(a: &Object, b: &Object) -> bool {
    #[cfg(test)]
    tests::COMPARED.set(tests::COMPARED.get() + 1);
    same_at(a, b, 0)
}

fn same_at(a: &Object, b: &Object, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match (a, b) {
        (Object::String(x, _), Object::String(y, _)) => x == y,
        (Object::Array(x), Object::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_at(p, q, depth + 1))
        }
        (Object::Dictionary(x), Object::Dictionary(y)) => same_dict(x, y, depth),
        (Object::Stream(x), Object::Stream(y)) => {
            x.content == y.content && same_dict(&x.dict, &y.dict, depth)
        }
        // A whole number is the same written as `612` or `612.0` (writers, lopdf among
        // them, drop the `.0`).
        (Object::Real(r), Object::Integer(i)) | (Object::Integer(i), Object::Real(r)) => {
            r.fract() == 0.0 && *r as i64 == *i
        }
        _ => a == b,
    }
}

fn same_dict(x: &Dictionary, y: &Dictionary, depth: usize) -> bool {
    x.len() == y.len()
        && x.iter()
            .all(|(k, v)| y.get(k).is_ok_and(|w| same_at(v, w, depth + 1)))
}

fn same_value(a: Option<&Object>, b: Option<&Object>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => same_object(x, y),
        (None, None) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------- roles

/// The roles an object plays in a version of the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Catalog,
    Info,
    Encrypt,
    Perms,
    Metadata,
    Dss,
    Extensions,
    /// The document's name trees (`/Names`), and the comment icon appearances in it.
    Names,
    NamedAppearance,
    /// Any other document-level structure.
    Other,
    /// An action or script.
    Action,
    /// A page or a node of the page tree.
    PageNode,
    /// An indirect `/Kids` array of the page tree.
    PagesArray,
    /// An indirect `/Annots` array.
    AnnotsArray,
    /// Anything a page draws or uses: contents, resources, fonts, images.
    PageContent,
    /// A comment (a markup annotation or a popup), and anything under it.
    Comment,
    CommentPart,
    /// A link or another annotation that isn't a comment, and anything under it.
    OtherAnnot,
    OtherAnnotPart,
    /// A widget annotation that is also a form field.
    WidgetAnnot,
    /// A form field other than a signature field, and anything under it (appearances).
    Field,
    FieldPart,
    SigField,
    SigFieldPart,
    /// A signature field's lock and seed value.
    FieldMeta,
    /// An indirect `/Fields` or `/Kids` array of the form.
    FieldsArray,
    /// A signature dictionary, and anything under it.
    SigDict,
    SigPart,
    AcroForm,
    /// Form-wide settings: default resources.
    AcroFormPart,
}

/// A form field node.
#[derive(Clone, Debug)]
struct FieldInfo {
    name: String,
    parent: Option<ObjectId>,
    /// The top of its field tree.
    root: ObjectId,
    /// The field it is part of: itself when titled, else its parent's (a widget kid's field).
    field: ObjectId,
    /// It has a kind, by its own or an inherited `/FT` ([`crate::forms::of_a_kind`]).
    typed: bool,
    sig: bool,
    /// For a signature field: it holds a signature.
    signed: bool,
    /// The signature it holds is a document timestamp.
    timestamp: bool,
    /// It has a widget with an area that isn't hidden.
    visible: bool,
}

impl FieldInfo {
    /// Its name, copied for a change found.
    fn copied_name(&self) -> String {
        #[cfg(test)]
        tests::NAMES_COPIED.set(tests::NAMES_COPIED.get() + 1);
        self.name.clone()
    }
}

/// The most nodes walked in the page tree or the form, and the most steps walking them (a
/// kid listed, or 64 bytes of a field's name), assigning roles or comparing a version's
/// annotation lists with the next's (and showing their changes on each page); beyond that
/// the document is refused as too complex to check.
const MAX_NODES: usize = 500_000;
const MAX_STEPS: usize = 4_000_000;

/// [`MAX_STEPS`], or a test's limit ([`budget::limit`]).
fn max_steps() -> usize {
    budget::limit(MAX_STEPS as u64) as usize
}

/// Keys that link to an annotation or field elsewhere without containing it.
const LINK_KEYS: [&[u8]; 12] = [
    b"P", b"Parent", b"IRT", b"Popup", b"Obj", b"Pg", b"T", b"AN", b"Dest", b"D", b"Fields", b"CO",
];

struct Roles {
    of: HashMap<ObjectId, Vec<(Kind, ObjectId)>>,
    catalog: ObjectId,
    /// Leaf pages in order, every page tree node, and each leaf's index.
    pages: Vec<ObjectId>,
    page_nodes: HashSet<ObjectId>,
    page_index: HashMap<ObjectId, usize>,
    /// Each `/Annots` list once (one several pages share is kept once), and each leaf
    /// page's list in it.
    annot_lists: Vec<Vec<Object>>,
    page_annots: HashMap<ObjectId, usize>,
    /// Indirect annotations and the page listing them.
    annots: HashMap<ObjectId, usize>,
    fields: BTreeMap<ObjectId, FieldInfo>,
    /// Each listing of a field by another than the one it's named by: the field and the field
    /// listing it, or none for `/Fields`.
    again: BTreeSet<(ObjectId, Option<ObjectId>)>,
}

impl Roles {
    fn build(v: &Version) -> Result<Self, String> {
        let too_complex = || "the document is too complex to check".to_string();
        let catalog = v
            .pdf
            .doc
            .trailer
            .get(b"Root")
            .ok()
            .and_then(|o| o.as_reference().ok())
            .filter(|&id| v.dict_of(id).is_some())
            .ok_or("a version has no document catalog")?;
        let cat = v
            .dict_of(catalog)
            .ok_or("a version has no document catalog")?;
        let mut r = Roles {
            of: HashMap::new(),
            catalog,
            pages: Vec::new(),
            page_nodes: HashSet::new(),
            page_index: HashMap::new(),
            annot_lists: Vec::new(),
            page_annots: HashMap::new(),
            annots: HashMap::new(),
            fields: BTreeMap::new(),
            again: BTreeSet::new(),
        };

        // Each kid the page tree or the form lists is a step, so a list many nodes share costs
        // its length each time, and so is each 64 bytes of a field's name; nesting is not
        // limited.
        let limit = max_steps();
        let mut steps = 0;

        // The page tree.
        let mut stack: Vec<ObjectId> = cat
            .get(b"Pages")
            .ok()
            .and_then(|o| o.as_reference().ok())
            .map(|id| vec![id])
            .unwrap_or_default();
        while let Some(id) = stack.pop() {
            if !r.page_nodes.insert(id) {
                continue;
            }
            if r.page_nodes.len() > MAX_NODES {
                return Err(too_complex());
            }
            let Some(d) = v.dict_of(id) else {
                continue;
            };
            let kids = d.get(b"Kids").ok().and_then(|k| v.array(k));
            match kids {
                Some(kids) if v.name(d, b"Type") != Some(b"Page") => {
                    steps += kids.len();
                    if steps > limit {
                        return Err(too_complex());
                    }
                    for k in kids.iter().rev() {
                        if let Ok(k) = k.as_reference() {
                            stack.push(k);
                        }
                    }
                }
                _ => {
                    r.page_index.entry(id).or_insert(r.pages.len());
                    r.pages.push(id);
                }
            }
        }
        // Each list once, at the first page that has it: one written into the page is the
        // page's own.
        let mut lists: HashMap<ObjectId, usize> = HashMap::new();
        for (i, &page) in r.pages.iter().enumerate() {
            let annots = v.dict_of(page).and_then(|d| d.get(b"Annots").ok());
            let key = annots.and_then(|a| v.array_holder(a)).unwrap_or(page);
            let at = *lists.entry(key).or_insert_with(|| {
                let entries = annots.and_then(|a| v.array(a)).cloned().unwrap_or_default();
                for e in &entries {
                    if let Ok(id) = e.as_reference() {
                        r.annots.entry(id).or_insert(i);
                    }
                }
                r.annot_lists.push(entries);
                r.annot_lists.len() - 1
            });
            r.page_annots.insert(page, at);
        }

        // The form's fields.
        let form = cat.get(b"AcroForm").ok().and_then(|o| v.dict(o));
        let roots = form
            .and_then(|f| f.get(b"Fields").ok())
            .and_then(|o| v.array(o))
            .cloned()
            .unwrap_or_default();
        // (field, parent); a parent is recorded before its kids. A node is named and typed
        // through the first node listing it, unless that gave it no kind: then through the
        // first with a kind listing it after, as the form's reading ([`Pdf::form_nodes`])
        // does, it and its kids recorded again, each at most once more.
        let mut stack: Vec<(ObjectId, Option<ObjectId>)> = roots
            .iter()
            .rev()
            .filter_map(|o| o.as_reference().ok())
            .map(|id| (id, None))
            .collect();
        // Whether a list of kids, which fields may share, holds a widget that shows.
        let mut shown = HashMap::new();
        while let Some((id, parent)) = stack.pop() {
            let Some(d) = v.dict_of(id) else {
                continue;
            };
            let up = parent.and_then(|p| r.fields.get(&p));
            let ft = v.name(d, b"FT");
            let typed = match ft {
                Some(_) => forms::of_a_kind(ft),
                None => up.is_some_and(|p| p.typed),
            };
            if let Some(f) = r.fields.get(&id) {
                let renamed = typed && !f.typed;
                if f.parent != parent {
                    r.again
                        .insert((id, if renamed { f.parent } else { parent }));
                }
                if !renamed {
                    continue;
                }
            } else if r.fields.len() > MAX_NODES {
                return Err(too_complex());
            }
            let partial = d.get(b"T").ok().and_then(|t| v.pdf.text_value(t));
            let field = match (&partial, up) {
                (None, Some(p)) => p.field,
                _ => id,
            };
            let name = match (partial, up) {
                (Some(t), Some(p)) if !p.name.is_empty() => format!("{}.{t}", p.name),
                (Some(t), _) => t,
                (None, p) => p.map(|p| p.name.clone()).unwrap_or_default(),
            };
            steps += name.len() / 64;
            if steps > limit {
                return Err(too_complex());
            }
            let sig = match ft {
                Some(ft) => ft == b"Sig",
                None => up.is_some_and(|p| p.sig),
            };
            let root = up.map_or(id, |p| p.root);
            let value = d.get(b"V").ok().and_then(|o| v.dict(o));
            let timestamp = value.is_some_and(|s| {
                v.name(s, b"Type") == Some(b"DocTimeStamp")
                    || v.name(s, b"SubFilter") == Some(b"ETSI.RFC3161")
            });
            r.fields.insert(
                id,
                FieldInfo {
                    name,
                    parent,
                    root,
                    field,
                    typed,
                    sig,
                    signed: sig && value.is_some(),
                    timestamp: sig && timestamp,
                    visible: widget_visible(v, d, &mut shown),
                },
            );
            if let Some(kids) = d.get(b"Kids").ok().and_then(|k| v.array(k)) {
                steps += kids.len();
                if steps > limit {
                    return Err(too_complex());
                }
                for k in kids.iter().rev() {
                    if let Ok(k) = k.as_reference() {
                        stack.push((k, Some(id)));
                    }
                }
            }
        }

        // Roles.
        let mut w = Walker {
            v,
            r: &mut r,
            seen: HashSet::new(),
            todo: Vec::new(),
            steps: 0,
            lists: HashMap::new(),
            found: HashMap::new(),
            done: HashSet::new(),
        };
        w.push(catalog, Kind::Catalog, catalog);
        for (key, kind) in [(&b"Info"[..], Kind::Info), (b"Encrypt", Kind::Encrypt)] {
            if let Ok(id) = v.pdf.doc.trailer.get(key).and_then(|o| o.as_reference()) {
                w.push(id, kind, id);
            }
        }
        if let Some(Ok(id)) = cat.get(b"AcroForm").ok().map(|o| o.as_reference()) {
            w.push(id, Kind::AcroForm, id);
        }
        let nodes: Vec<ObjectId> = w.r.page_nodes.iter().copied().collect();
        for id in nodes {
            w.push(id, Kind::PageNode, id);
        }
        let fields: Vec<(ObjectId, bool)> = w.r.fields.iter().map(|(id, f)| (*id, f.sig)).collect();
        for (id, sig) in fields {
            w.push(id, if sig { Kind::SigField } else { Kind::Field }, id);
        }
        let annots: Vec<ObjectId> = w.r.annots.keys().copied().collect();
        for id in annots {
            let kind = if w.r.fields.contains_key(&id) {
                Kind::WidgetAnnot
            } else {
                match annot_class(v, v.get(id)) {
                    AnnotClass::Comment => Kind::Comment,
                    _ => Kind::OtherAnnot,
                }
            };
            w.push(id, kind, id);
        }
        w.run()?;
        Ok(r)
    }

    fn kinds(&self, id: ObjectId) -> &[(Kind, ObjectId)] {
        self.of.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    fn page_of(&self, node: ObjectId) -> Option<usize> {
        self.page_index.get(&node).copied()
    }
}

/// Whether a field's widget (the field itself, or any of its kids) shows on the page: a
/// rectangle with an area, not hidden. `shown` keeps the answer for each list of kids looked
/// through, which fields may share; it holds for `v` only.
fn widget_visible(v: &Version, d: &Dictionary, shown: &mut HashMap<ObjectId, bool>) -> bool {
    let one = |d: &Dictionary| {
        let rect = d.get(b"Rect").ok().and_then(|r| v.array(r));
        let rect: Option<Vec<f32>> = rect.filter(|a| a.len() == 4).and_then(|a| {
            a.iter()
                .map(|x| {
                    #[cfg(test)]
                    tests::RECT_READ.set(tests::RECT_READ.get() + 1);
                    match v.resolve(x)? {
                        Object::Integer(i) => Some(*i as f32),
                        Object::Real(f) => Some(*f),
                        _ => None,
                    }
                })
                .collect()
        });
        let area = matches!(rect.as_deref(), Some(&[x0, y0, x1, y1])
            if (x1 - x0).abs() > 0.0 && (y1 - y0).abs() > 0.0);
        let flags = d
            .get(b"F")
            .ok()
            .and_then(|f| v.resolve(f)?.as_i64().ok())
            .unwrap_or(0);
        // Hidden (2) or NoView (32).
        area && flags & (2 | 32) == 0
    };
    if one(d) {
        return true;
    }
    let Ok(kids) = d.get(b"Kids") else {
        return false;
    };
    let any = || {
        v.array(kids)
            .is_some_and(|kids| kids.iter().filter_map(|k| v.dict(k)).any(one))
    };
    match v.array_holder(kids) {
        Some(list) => *shown.entry(list).or_insert_with(any),
        None => any(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AnnotClass {
    /// A markup annotation or a popup.
    Comment,
    Widget,
    /// A link or another annotation that isn't a comment, or not an annotation at all.
    Other,
}

const COMMENT_SUBTYPES: [&[u8]; 18] = [
    b"Text",
    b"FreeText",
    b"Line",
    b"Square",
    b"Circle",
    b"Polygon",
    b"PolyLine",
    b"Highlight",
    b"Underline",
    b"Squiggly",
    b"StrikeOut",
    b"Stamp",
    b"Caret",
    b"Ink",
    b"FileAttachment",
    b"Sound",
    b"Redact",
    b"Popup",
];

fn annot_class(v: &Version, o: Option<&Object>) -> AnnotClass {
    let Some(Object::Dictionary(d)) = o.and_then(|o| v.resolve(o)) else {
        return AnnotClass::Other;
    };
    match v.name(d, b"Subtype") {
        Some(b"Widget") => AnnotClass::Widget,
        Some(s) if COMMENT_SUBTYPES.contains(&s) => AnnotClass::Comment,
        _ => AnnotClass::Other,
    }
}

/// Assigns roles: each object reached gets the kind of the structure reaching it.
struct Walker<'v, 'r> {
    v: &'v Version<'v>,
    r: &'r mut Roles,
    seen: HashSet<(ObjectId, Kind, ObjectId)>,
    todo: Vec<(ObjectId, Kind, ObjectId)>,
    steps: usize,
    /// The annotations written inside each `/Annots` array held in an object, as
    /// [`Walker::written_in`] found them.
    lists: HashMap<ObjectId, (Vec<(usize, Kind)>, usize)>,
    /// The references in each object walked as a kind, and the kinds they get, as
    /// [`Walker::refs`] found them.
    found: HashMap<(ObjectId, Kind), Vec<(ObjectId, Kind)>>,
    /// The objects whose entries were given their parts, by kind.
    done: HashSet<(ObjectId, Kind)>,
}

impl Walker<'_, '_> {
    fn push(&mut self, id: ObjectId, kind: Kind, owner: ObjectId) {
        if self.seen.insert((id, kind, owner)) {
            self.r.of.entry(id).or_default().push((kind, owner));
            self.todo.push((id, kind, owner));
        }
    }

    fn run(&mut self) -> Result<(), String> {
        let limit = max_steps();
        while let Some((id, kind, owner)) = self.todo.pop() {
            self.steps += 1;
            if self.steps > limit {
                return Err("the document is too complex to check".into());
            }
            let v = self.v;
            let Some(obj) = v.get(id) else {
                continue;
            };
            let dict = match obj {
                Object::Dictionary(d) => Some(d),
                Object::Stream(s) => Some(&s.dict),
                _ => None,
            };
            // These give an object's entries their parts with the object as owner, so
            // another owner reaching it as the same kind adds nothing.
            let owns = matches!(
                kind,
                Kind::PageNode
                    | Kind::Comment
                    | Kind::OtherAnnot
                    | Kind::Field
                    | Kind::SigField
                    | Kind::AcroForm
                    | Kind::Names
            );
            if owns && dict.is_some() && !self.done.insert((id, kind)) {
                continue;
            }
            match (kind, dict) {
                (Kind::Catalog, Some(d)) => {
                    for (k, val) in d.iter() {
                        let nk = match k.as_slice() {
                            b"Pages" => continue,
                            b"Names" => {
                                match val {
                                    Object::Reference(r) => self.push(*r, Kind::Names, *r),
                                    Object::Dictionary(n) => self.names(n, owner),
                                    _ => {}
                                }
                                continue;
                            }
                            b"AcroForm" => Kind::AcroForm,
                            b"DSS" => Kind::Dss,
                            b"Metadata" => Kind::Metadata,
                            b"Extensions" => Kind::Extensions,
                            b"Perms" => Kind::Perms,
                            _ => Kind::Other,
                        };
                        self.walk_entry(val, nk, owner, k);
                    }
                }
                (Kind::PageNode, Some(d)) => {
                    for (k, val) in d.iter() {
                        match k.as_slice() {
                            b"Parent" => {}
                            b"Kids" => {
                                if let Ok(r) = val.as_reference() {
                                    self.push(r, Kind::PagesArray, id);
                                }
                            }
                            b"Annots" => {
                                if let Ok(r) = val.as_reference() {
                                    self.push(r, Kind::AnnotsArray, id);
                                }
                                // Annotations written inside the array, a step for each
                                // object in them; the others are pushed as annotations
                                // already.
                                let list = v.array(val).map(Vec::as_slice).unwrap_or_default();
                                let (inside, size) = self.written_in(list, v.array_holder(val));
                                self.steps += size;
                                if self.steps > limit {
                                    return Err("the document is too complex to check".into());
                                }
                                for (i, nk) in inside {
                                    self.walk(&list[i], nk, id, Some(k.as_slice()));
                                }
                            }
                            _ => self.walk_entry(val, Kind::PageContent, id, k),
                        }
                    }
                }
                (Kind::Comment | Kind::OtherAnnot, Some(d)) => {
                    let part = if kind == Kind::Comment {
                        Kind::CommentPart
                    } else {
                        Kind::OtherAnnotPart
                    };
                    for (k, val) in d.iter() {
                        match k.as_slice() {
                            b"P" | b"IRT" => {}
                            // A parent recorded nowhere names a widget for readers following
                            // `/Parent`, and gives it a type, value and actions.
                            b"Parent" => {
                                let up = val.as_reference().ok().filter(|r| {
                                    !self.r.fields.contains_key(r)
                                        && !self.r.annots.contains_key(r)
                                        && v.dict_of(*r).is_some()
                                });
                                if let Some(r) = up {
                                    self.push(r, part, id);
                                }
                            }
                            b"Popup" => {
                                if let Ok(r) = val.as_reference() {
                                    if !self.r.fields.contains_key(&r) {
                                        self.push(r, kind, r);
                                    }
                                }
                            }
                            _ => self.walk_entry(val, part, id, k),
                        }
                    }
                }
                (Kind::Field | Kind::SigField, Some(d)) => {
                    let part = if kind == Kind::Field {
                        Kind::FieldPart
                    } else {
                        Kind::SigFieldPart
                    };
                    for (k, val) in d.iter() {
                        match k.as_slice() {
                            b"P" => {}
                            // Readers following `/Parent` name the field, and take its type,
                            // value and actions, from what it names: one other than the field
                            // listing it makes the field all a change to it, and walked so, a
                            // parent recorded nowhere (and its own) part of it.
                            b"Parent" => {
                                let up =
                                    val.as_reference().ok().filter(|r| v.dict_of(*r).is_some());
                                let listing = self.r.fields.get(&id).and_then(|f| f.parent);
                                if up.is_some_and(|r| Some(r) != listing) {
                                    self.push(id, Kind::FieldMeta, id);
                                }
                            }
                            b"Kids" => {
                                if let Ok(r) = val.as_reference() {
                                    self.push(r, Kind::FieldsArray, id);
                                }
                            }
                            b"V" if kind == Kind::SigField => match val {
                                Object::Reference(r) => self.push(*r, Kind::SigDict, id),
                                _ => self.walk(val, Kind::SigPart, id, Some(k.as_slice())),
                            },
                            b"Lock" | b"SV" => self.walk_entry(val, Kind::FieldMeta, id, k),
                            _ => self.walk_entry(val, part, id, k),
                        }
                    }
                }
                (Kind::AcroForm, Some(d)) => {
                    for (k, val) in d.iter() {
                        match k.as_slice() {
                            b"Fields" => {
                                if let Ok(r) = val.as_reference() {
                                    self.push(r, Kind::FieldsArray, id);
                                }
                            }
                            b"CO" => {}
                            b"XFA" => self.walk_entry(val, Kind::Other, id, k),
                            _ => self.walk_entry(val, Kind::AcroFormPart, id, k),
                        }
                    }
                }
                (Kind::Names, Some(d)) => self.names(d, id),
                (
                    Kind::WidgetAnnot | Kind::PagesArray | Kind::AnnotsArray | Kind::FieldsArray,
                    _,
                ) => {}
                // An object reached from many owners is walked once a kind, a step; what it
                // refers to is pushed again for each further owner, a step, or a step for
                // each reference in it that owner reached already, if more.
                _ => {
                    let (found, again_for) = match self.found.remove(&(id, kind)) {
                        Some(found) => (found, true),
                        None => {
                            let mut found = Vec::new();
                            self.refs(obj, kind, None, &mut found);
                            (found, false)
                        }
                    };
                    let pushed = self.todo.len();
                    for &(r, kind) in &found {
                        self.push(r, kind, owner);
                    }
                    let again = found.len() - (self.todo.len() - pushed);
                    self.found.insert((id, kind), found);
                    if again_for {
                        self.steps += again.saturating_sub(1);
                        if self.steps > limit {
                            return Err("the document is too complex to check".into());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The annotations written inside the `/Annots` array `list` (their positions and
    /// kinds), and the objects in them ([`nodes`]). A list held in an object (`holder`),
    /// which pages may share, is looked through once.
    fn written_in(
        &mut self,
        list: &[Object],
        holder: Option<ObjectId>,
    ) -> (Vec<(usize, Kind)>, usize) {
        if let Some(known) = holder.and_then(|h| self.lists.get(&h)) {
            #[cfg(test)]
            tests::LOOKED.set(tests::LOOKED.get() + known.0.len());
            return known.clone();
        }
        let mut found = (Vec::new(), 0);
        for (i, e) in list.iter().enumerate() {
            #[cfg(test)]
            tests::LOOKED.set(tests::LOOKED.get() + 1);
            if let Object::Dictionary(_) = e {
                let kind = match annot_class(self.v, Some(e)) {
                    AnnotClass::Comment => Kind::CommentPart,
                    _ => Kind::OtherAnnotPart,
                };
                found.0.push((i, kind));
                found.1 += nodes(e);
            }
        }
        if let Some(h) = holder {
            self.lists.insert(h, found.clone());
        }
        found
    }

    /// The name trees: comment icon appearances, and the rest (destinations, scripts,
    /// embedded files) as document structure.
    fn names(&mut self, d: &Dictionary, owner: ObjectId) {
        for (k, val) in d.iter() {
            let kind = if k == b"AP" {
                Kind::NamedAppearance
            } else {
                Kind::Other
            };
            self.walk_entry(val, kind, owner, k);
        }
    }

    /// One dictionary entry: actions and scripts get their own kind.
    fn walk_entry(&mut self, val: &Object, kind: Kind, owner: ObjectId, key: &[u8]) {
        self.walk(val, child_kind(kind, key), owner, Some(key));
    }

    /// The references in `val` (a value of `kind`, under dictionary key `key`), pushed for
    /// `owner`.
    fn walk(&mut self, val: &Object, kind: Kind, owner: ObjectId, key: Option<&[u8]>) {
        let mut found = Vec::new();
        self.refs(val, kind, key, &mut found);
        for (r, kind) in found {
            self.push(r, kind, owner);
        }
    }

    /// The references in `val` (a value of `kind`, under dictionary key `key`) and the
    /// kinds they get, added to `out`.
    fn refs(&self, val: &Object, kind: Kind, key: Option<&[u8]>, out: &mut Vec<(ObjectId, Kind)>) {
        #[cfg(test)]
        tests::WALKED.set(tests::WALKED.get() + 1);
        match val {
            Object::Reference(r) => {
                let r = *r;
                if self.r.page_nodes.contains(&r) {
                    return;
                }
                // A signature's reference to what it covers (the catalog, the form).
                if matches!(kind, Kind::SigDict | Kind::SigPart | Kind::Perms)
                    && key == Some(b"Data")
                {
                    return;
                }
                if key.is_some_and(|k| LINK_KEYS.contains(&k))
                    && (self.r.annots.contains_key(&r) || self.r.fields.contains_key(&r))
                {
                    return;
                }
                let kind = if kind == Kind::SigDict {
                    Kind::SigPart
                } else {
                    kind
                };
                out.push((r, kind));
            }
            Object::Array(a) => {
                for e in a {
                    self.refs(e, kind, key, out);
                }
            }
            Object::Dictionary(d) => {
                for (k, v) in d.iter() {
                    self.refs(v, child_kind(kind, k), Some(k), out);
                }
            }
            Object::Stream(s) => {
                for (k, v) in s.dict.iter() {
                    self.refs(v, child_kind(kind, k), Some(k), out);
                }
            }
            _ => {}
        }
    }
}

/// The objects written in place in `o`, `o` included: those [`Walker::refs`] goes through.
fn nodes(o: &Object) -> usize {
    1 + match o {
        Object::Array(a) => a.iter().map(nodes).sum(),
        Object::Dictionary(d) => d.iter().map(|(_, v)| nodes(v)).sum(),
        Object::Stream(s) => s.dict.iter().map(|(_, v)| nodes(v)).sum(),
        _ => 0,
    }
}

fn child_kind(kind: Kind, key: &[u8]) -> Kind {
    match key {
        b"A" | b"AA" | b"JS" | b"OpenAction" => Kind::Action,
        _ if kind == Kind::SigDict => Kind::SigPart,
        _ => kind,
    }
}

// ---------------------------------------------------------------- judging

struct Judge<'a> {
    old: &'a Version<'a>,
    new: &'a Version<'a>,
    or: &'a Roles,
    nr: &'a Roles,
    /// The fields whose signatures the report lists.
    listed: &'a HashSet<ObjectId>,
    out: Vec<Seen>,
    /// The fields' changes pushed (field, kind of change, page), each once.
    pushed: HashSet<(ObjectId, FieldChange, Option<usize>)>,
}

/// A kind of change to a field, pushed once a page for each field: its name may be long, and
/// many of its keys or parts may change.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FieldChange {
    Changed,
    Filled,
    MadeReadOnly,
    SignatureChanged,
}

/// Field dictionary entries filling in may change: the value, its appearance, the
/// appearance state, the rich-text value, the selected options, the modification date.
const FILL_KEYS: [&[u8]; 6] = [b"V", b"AP", b"AS", b"RV", b"I", b"M"];
/// Signature field entries signing may change.
const SIGN_KEYS: [&[u8]; 4] = [b"V", b"AP", b"AS", b"M"];

/// Whether the field node `id` holds a signature in `roles`, itself or, for a widget kid,
/// the field it is part of (signing sets the field's `/V` and locks and draws its widgets).
fn signed_field(roles: &Roles, id: ObjectId) -> bool {
    let signed = |id: &ObjectId| roles.fields.get(id).is_some_and(|f| f.signed);
    signed(&id) || roles.fields.get(&id).is_some_and(|f| signed(&f.field))
}

impl<'a> Judge<'a> {
    fn push(&mut self, s: Seen) {
        self.out.push(s);
    }

    /// Field `owner`'s `change` on `page`, pushed once: its name is copied only then.
    fn push_field(&mut self, owner: ObjectId, change: FieldChange, page: Option<usize>) {
        if !self.pushed.insert((owner, change, page)) {
            return;
        }
        let name = self.field_name(owner);
        let fill = |kind| seen(kind, page, Need::Fill(Some(name.clone())));
        let s = match change {
            FieldChange::Changed => never(ChangeKind::FieldChanged(name), page),
            FieldChange::SignatureChanged => never(ChangeKind::SignatureChanged(name), page),
            FieldChange::Filled => fill(ChangeKind::FieldFilled(name.clone())),
            FieldChange::MadeReadOnly => fill(ChangeKind::FieldMadeReadOnly(name.clone())),
        };
        self.push(s);
    }

    /// The keys whose values differ between two dictionaries.
    fn differing(a: &Dictionary, b: &Dictionary) -> Vec<Vec<u8>> {
        let mut keys: Vec<Vec<u8>> = a
            .iter()
            .map(|(k, _)| k.clone())
            .chain(b.iter().map(|(k, _)| k.clone()))
            .collect();
        keys.sort();
        keys.dedup();
        keys.into_iter()
            .filter(|k| !same_value(a.get(k).ok(), b.get(k).ok()))
            .collect()
    }

    fn trailer(&mut self) {
        let (o, n) = (&self.old.pdf.doc.trailer, &self.new.pdf.doc.trailer);
        if self.or.catalog != self.nr.catalog {
            self.push(never(
                ChangeKind::DocumentChanged("the document catalog was replaced".into()),
                None,
            ));
        }
        if !same_value(o.get(b"Encrypt").ok(), n.get(b"Encrypt").ok()) {
            self.push(never(
                ChangeKind::DocumentChanged("encryption".into()),
                None,
            ));
        }
        if !same_value(o.get(b"Info").ok(), n.get(b"Info").ok()) {
            self.push(seen(ChangeKind::Metadata, None, Need::Nothing));
        }
    }

    fn pages(&mut self) {
        if self.or.pages != self.nr.pages {
            self.push(never(ChangeKind::PagesChanged, None));
        }
    }

    /// Annotations added to, removed from or reordered on each page. Each pair of lists
    /// (before and after) is compared once, however many pages have it, and its changes
    /// cost a step for each page they show on, within [`MAX_STEPS`]; past that the document
    /// is too complex to check, and no list's changes are reported.
    fn annotations(&mut self) {
        let (or, nr) = (self.or, self.nr);
        let limit = max_steps();
        let mut steps = 0;
        let mut compared: HashMap<(usize, usize), Vec<Seen>> = HashMap::new();
        // Each page with its pair.
        let mut pages: Vec<(usize, (usize, usize))> = Vec::new();
        let mut within = true;
        for (i, page) in nr.pages.iter().enumerate() {
            let Some(&before) = or.page_annots.get(page) else {
                continue;
            };
            let pair = (before, nr.page_annots[page]);
            if let std::collections::hash_map::Entry::Vacant(e) = compared.entry(pair) {
                let (b, a) = (&or.annot_lists[pair.0], &nr.annot_lists[pair.1]);
                let Some(found) = self.list_changes(b, a, &mut steps, limit) else {
                    within = false;
                    break;
                };
                e.insert(found);
            }
            steps += compared[&pair].len();
            if steps > limit {
                within = false;
                break;
            }
            pages.push((i, pair));
        }
        if !within {
            let why = "the document is too complex to check".to_string();
            self.push(never(ChangeKind::Malformed(why), None));
            return;
        }
        for (i, pair) in pages {
            for s in &compared[&pair] {
                self.push(Seen {
                    page: Some(i),
                    ..s.clone()
                });
            }
        }
    }

    /// What changed between a page's annotations `before` and `after`, each change once and
    /// without the page; `None` past `limit` steps. Each entry costs a step; one referred to
    /// is looked for by its reference, and one written in place (which the format doesn't
    /// allow) is compared with those in place in the other list, a step each.
    fn list_changes(
        &self,
        before: &[Object],
        after: &[Object],
        steps: &mut usize,
        limit: usize,
    ) -> Option<Vec<Seen>> {
        let (old, new) = (self.old, self.new);
        *steps += before.len() + after.len();
        if *steps > limit {
            return None;
        }
        // For each entry of `list`, whether `other` has it too.
        let in_other = |list: &[Object], other: &[Object], steps: &mut usize| {
            let refs: HashSet<ObjectId> = (other.iter())
                .filter_map(|e| e.as_reference().ok())
                .collect();
            let in_place: Vec<&Object> = (other.iter())
                .filter(|e| e.as_reference().is_err())
                .collect();
            list.iter()
                .map(|e| match e {
                    Object::Reference(id) => Some(refs.contains(id)),
                    e => {
                        for x in &in_place {
                            *steps += 1;
                            if *steps > limit {
                                return None;
                            }
                            if same_object(x, e) {
                                return Some(true);
                            }
                        }
                        Some(false)
                    }
                })
                .collect::<Option<Vec<bool>>>()
        };
        let in_after = in_other(before, after, steps)?;
        let in_before = in_other(after, before, steps)?;
        // An entry referring again to what one before it did changes nothing more: judged
        // once, a field's name isn't copied for each.
        let (mut gone, mut new_ids) = (HashSet::new(), HashSet::new());
        let removed = (before.iter().zip(&in_after))
            .filter_map(|(e, &k)| (!k).then_some(e))
            .filter(|e| e.as_reference().ok().is_none_or(|id| gone.insert(id)));
        let added = (after.iter().zip(&in_before))
            .filter_map(|(e, &k)| (!k).then_some(e))
            .filter(|e| e.as_reference().ok().is_none_or(|id| new_ids.insert(id)));

        let mut out: Vec<Seen> = Vec::new();
        let mut once: HashSet<(ChangeKind, Need)> = HashSet::new();
        let mut push = |s: Seen| {
            if once.insert((s.kind.clone(), s.need.clone())) {
                out.push(s);
            }
        };
        for e in removed {
            match annot_class(old, Some(e)) {
                AnnotClass::Comment => push(seen(ChangeKind::CommentRemoved, None, Need::Comment)),
                AnnotClass::Widget => {
                    let id = e.as_reference().ok();
                    let field = id.and_then(|id| self.or.fields.get(&id));
                    let kept = id.is_some_and(|id| self.nr.fields.contains_key(&id));
                    match field {
                        // Taken off the page but still a field.
                        Some(f) if kept && f.signed => {
                            push(never(ChangeKind::SignatureChanged(f.copied_name()), None))
                        }
                        Some(f) if kept => {
                            push(never(ChangeKind::FieldChanged(f.copied_name()), None))
                        }
                        // A field removed is reported with the fields.
                        Some(_) => {}
                        None => push(never(ChangeKind::AnnotationChanged, None)),
                    }
                }
                AnnotClass::Other => push(never(ChangeKind::AnnotationChanged, None)),
            }
        }
        for e in added {
            match annot_class(new, Some(e)) {
                AnnotClass::Comment => {
                    let d = new.dict(e);
                    if d.is_some_and(|d| d.has(b"A") || d.has(b"AA")) {
                        push(never(ChangeKind::Actions, None));
                    } else {
                        push(seen(ChangeKind::CommentAdded, None, Need::Comment));
                    }
                }
                AnnotClass::Widget => {
                    let id = e.as_reference().ok();
                    match id.and_then(|id| self.nr.fields.get(&id).map(|f| (id, f))) {
                        // A widget of a field added in this step: reported with the
                        // fields. A widget added to a field from before isn't allowed.
                        Some((id, f)) => {
                            let root = self.field_root(id);
                            if self.or.fields.contains_key(&root) {
                                push(never(ChangeKind::FieldChanged(f.copied_name()), None));
                            }
                        }
                        None => push(never(ChangeKind::AnnotationChanged, None)),
                    }
                }
                AnnotClass::Other => push(never(ChangeKind::AnnotationChanged, None)),
            }
        }
        // Entries kept must keep their order (it decides what covers what).
        let kept_before: Vec<&Object> = (before.iter().zip(&in_after))
            .filter_map(|(e, &k)| k.then_some(e))
            .collect();
        let kept_after: Vec<&Object> = (after.iter().zip(&in_before))
            .filter_map(|(e, &k)| k.then_some(e))
            .collect();
        let same_order = kept_before.len() == kept_after.len()
            && kept_before
                .iter()
                .zip(&kept_after)
                .all(|(x, y)| same_object(x, y));
        if !same_order {
            if kept_after
                .iter()
                .all(|e| annot_class(new, Some(e)) == AnnotClass::Comment)
            {
                push(seen(ChangeKind::CommentChanged, None, Need::Comment));
            } else {
                push(never(ChangeKind::AnnotationChanged, None));
            }
        }
        Some(out)
    }

    /// Whether a field's flags only gained read-only: the newer dictionary's own `/Ff` is
    /// the older flags, its own or inherited, plus read-only.
    fn only_read_only(&self, a: &Dictionary, b: &Dictionary) -> bool {
        let Ok(Object::Integer(new)) = b.get(b"Ff") else {
            return false;
        };
        let mut d = a;
        for _ in 0..64 {
            match d.get(b"Ff") {
                Ok(Object::Integer(old)) => return *new == (old | 1) && old & 1 == 0,
                Ok(_) => return false,
                Err(_) => {}
            }
            match d.get(b"Parent").ok().and_then(|p| self.old.dict(p)) {
                Some(p) => d = p,
                None => return *new == 1,
            }
        }
        false
    }

    /// The top of the field tree `id` is in, in the newer version.
    fn field_root(&self, id: ObjectId) -> ObjectId {
        self.nr.fields.get(&id).map_or(id, |f| f.root)
    }

    /// Whether the newer version's field or widget `id` has an action (`/A` or `/AA`, not null).
    fn acts(&self, id: ObjectId) -> bool {
        let d = self.new.dict_of(id);
        [&b"A"[..], b"AA"].into_iter().any(|k| {
            (d.and_then(|d| d.get(k).ok()))
                .and_then(|o| self.new.resolve(o))
                .is_some_and(|o| !matches!(o, Object::Null))
        })
    }

    /// The newer version's fields. [`Self::fields`] reads them only through this, so the
    /// tests can count how many it looks at.
    fn new_fields(&self) -> impl Iterator<Item = (&'a ObjectId, &'a FieldInfo)> + 'a {
        let nr: &'a Roles = self.nr;
        nr.fields.iter().inspect(|_| {
            #[cfg(test)]
            tests::FIELDS_LOOKED.set(tests::FIELDS_LOOKED.get() + 1);
        })
    }

    /// Field `id`, signed in this step (`new_visible` as for [`sign_seen`]): signing only when
    /// the report lists its signature, as nothing else checks it, and the signature's
    /// dictionary is new in this step: an earlier signature put in it signs nothing here.
    fn signing(&self, id: ObjectId, f: &FieldInfo, new_visible: Option<bool>) -> Seen {
        let earlier = match self.new.dict_of(id).and_then(|d| d.get(b"V").ok()) {
            Some(Object::Reference(v)) => self.old.get(*v).is_some(),
            _ => false,
        };
        if self.listed.contains(&id) && !earlier {
            return sign_seen(f, new_visible);
        }
        let what = format!("a signature in field \"{}\" it can't check", f.name);
        never(ChangeKind::Unrecognised(what), None)
    }

    /// Fields added, removed or signed.
    fn fields(&mut self) {
        for (id, f) in &self.or.fields {
            if !self.nr.fields.contains_key(id) {
                let kind = if f.signed {
                    ChangeKind::SignatureChanged(f.name.clone())
                } else {
                    ChangeKind::FieldRemoved(f.name.clone())
                };
                self.push(never(kind, None));
            }
        }
        // Listed by another field than the one it's named by, or no longer: only that one is
        // compared below, but a reader going by another would see the field there.
        let (or, nr) = (self.or, self.nr);
        let kept = |p: &ObjectId| or.fields.contains_key(p) && nr.fields.contains_key(p);
        // Each field added outside its tree once, however many list it.
        let mut outside = HashSet::new();
        for (id, by) in or.again.symmetric_difference(&nr.again) {
            match (or.fields.get(id), nr.fields.get(id), by.filter(kept)) {
                (Some(o), Some(_), _) => {
                    let change = if o.signed {
                        FieldChange::SignatureChanged
                    } else {
                        FieldChange::Changed
                    };
                    self.push_field(*id, change, None);
                }
                // Added in this step, and listed by a field kept too: that one changed.
                (None, Some(_), Some(p)) => self.push_field(p, FieldChange::Changed, None),
                // Or by `/Fields` or another field added: a field added outside its tree.
                (None, Some(f), None) if outside.insert(*id) => {
                    self.push(never(ChangeKind::FieldAdded(f.copied_name()), None));
                }
                // Removed: refused as that above; or such a field listed again.
                _ => {}
            }
        }
        // The nodes of each field tree added in this step, in number order.
        let mut added: HashMap<ObjectId, Vec<(&ObjectId, &FieldInfo)>> = HashMap::new();
        for (id, f) in self.new_fields() {
            if !self.or.fields.contains_key(&f.root) {
                added.entry(f.root).or_default().push((id, f));
            }
        }
        for (id, f) in self.new_fields() {
            match self.or.fields.get(id) {
                Some(o) => {
                    if o.signed && (!f.signed || o.name != f.name) {
                        self.push_field(*id, FieldChange::SignatureChanged, None);
                    } else if o.parent != f.parent || o.name != f.name {
                        // Moved, or renamed by a change to a field above it: a lock naming it
                        // would no longer, or what it takes from those above it would change.
                        self.push_field(*id, FieldChange::Changed, None);
                    } else if o.sig != f.sig {
                        // Made part of a signature field, or no longer, by a list of kids or
                        // fields changing: its signing would go unjudged, or its changes be
                        // judged as filling in another field.
                        self.push_field(*id, FieldChange::Changed, None);
                    } else if !o.signed && f.signed {
                        self.push(self.signing(*id, f, None));
                    }
                }
                None => match f.parent {
                    // Part of a field added in this step.
                    Some(p) if !self.or.fields.contains_key(&p) => {}
                    Some(p) => self.push_field(p, FieldChange::Changed, None),
                    None if f.sig => {
                        // The whole new field: whether anything in it is signed, shows or acts.
                        let tree = added.get(id).map(Vec::as_slice).unwrap_or_default();
                        let nr = self.nr;
                        let sig = |p: Option<ObjectId>| {
                            p.and_then(|p| nr.fields.get(&p)).is_some_and(|p| p.sig)
                        };
                        for (_, n) in tree.iter().filter(|(_, n)| !n.sig && sig(n.parent)) {
                            // A field of another kind added inside it: never allowed, as when
                            // added on its own.
                            self.push(never(ChangeKind::FieldAdded(n.name.clone()), None));
                        }
                        let visible = tree.iter().any(|(_, f)| f.visible);
                        if let Some((i, _)) = tree.iter().find(|(i, _)| self.acts(**i)) {
                            let page = self.nr.annots.get(*i).copied();
                            self.push(never(ChangeKind::Actions, page));
                        }
                        // Signed in this step: one signed before and moved into it is judged
                        // by its parent changing, not taken for this field's signing.
                        let old = |i: &ObjectId| self.or.fields.contains_key(i);
                        let mut signed = false;
                        for (i, s) in tree.iter().filter(|(i, f)| f.signed && !old(i)) {
                            self.push(self.signing(**i, s, Some(visible)));
                            signed = true;
                        }
                        if !signed {
                            self.push(seen(
                                ChangeKind::SignatureFieldAdded(f.name.clone()),
                                None,
                                Need::Sign {
                                    field: f.name.clone(),
                                    new_visible: Some(visible),
                                    timestamp: false,
                                },
                            ));
                        }
                    }
                    None => self.push(never(ChangeKind::FieldAdded(f.name.clone()), None)),
                },
            }
        }
    }

    /// One object that differs between the versions, judged by every role it plays in the
    /// newer one.
    fn object(&mut self, id: ObjectId) {
        let (o, n) = (self.old.get(id), self.new.get(id));
        if same_value(o, n) {
            return;
        }
        let kinds = self.nr.kinds(id).to_vec();
        let what = || format!("object {}", id.0);
        let (o, n) = match (o, n) {
            (None, Some(_)) => {
                // New: judged where it is used, unless the earlier version already used it.
                if !self.or.kinds(id).is_empty() {
                    self.push(never(
                        ChangeKind::Unrecognised(format!(
                            "{}, missing from the signed version but used by it, was added",
                            what()
                        )),
                        None,
                    ));
                }
                return;
            }
            (Some(_), None) => {
                // Deleted: fine when nothing uses it any more.
                if !kinds.is_empty() {
                    self.push(never(
                        ChangeKind::Unrecognised(format!(
                            "{} was deleted but is still used",
                            what()
                        )),
                        None,
                    ));
                }
                return;
            }
            (Some(o), Some(n)) => (o, n),
            (None, None) => return,
        };
        for (kind, owner) in kinds {
            self.judge(kind, owner, id, o, n);
        }
    }

    /// Field `owner`'s name before this step (what a lock names), or its new name if it's new.
    fn field_name(&self, owner: ObjectId) -> String {
        self.or
            .fields
            .get(&owner)
            .or_else(|| self.nr.fields.get(&owner))
            .map(FieldInfo::copied_name)
            .unwrap_or_default()
    }

    fn judge(&mut self, kind: Kind, owner: ObjectId, id: ObjectId, o: &Object, n: &Object) {
        let page = (self.nr.annots.get(&owner).copied()).or(self.nr.page_of(owner));
        let dicts = match (o, n) {
            (Object::Dictionary(a), Object::Dictionary(b)) => Some((a, b)),
            _ => None,
        };
        match kind {
            Kind::Catalog => match dicts {
                Some((a, b)) => self.catalog(a, b),
                None => self.push(never(ChangeKind::Unrecognised("the catalog".into()), None)),
            },
            Kind::AcroForm => match dicts {
                Some((a, b)) => self.acroform(a, b),
                None => self.push(never(ChangeKind::Unrecognised("the form".into()), None)),
            },
            Kind::Info | Kind::Metadata => {
                self.push(seen(ChangeKind::Metadata, None, Need::Nothing))
            }
            Kind::Dss | Kind::Extensions => {
                self.push(seen(ChangeKind::ValidationData, None, Need::Nothing))
            }
            Kind::AcroFormPart => self.push(seen(ChangeKind::FormSettings, None, Need::Fill(None))),
            Kind::PageNode => {
                let keys = match dicts {
                    Some((a, b)) => Self::differing(a, b),
                    None => vec![b"Type".to_vec()],
                };
                for k in keys {
                    match k.as_slice() {
                        // Compared annotation by annotation.
                        b"Annots" => {}
                        // iText marks the pages it saves with its version; no reader uses it.
                        b"ITXT"
                            if dicts.is_some_and(|(_, b)| {
                                matches!(b.get(b"ITXT"), Ok(Object::String(..)) | Err(_))
                            }) =>
                        {
                            self.push(seen(ChangeKind::Metadata, None, Need::Nothing))
                        }
                        b"Kids" | b"Count" | b"Parent" => {
                            self.push(never(ChangeKind::PagesChanged, None))
                        }
                        _ => self.push(never(ChangeKind::PageContent, self.nr.page_of(id))),
                    }
                }
            }
            Kind::PagesArray => self.push(never(ChangeKind::PagesChanged, None)),
            // Compared entry by entry.
            Kind::AnnotsArray | Kind::FieldsArray | Kind::WidgetAnnot => {}
            Kind::PageContent => self.push(never(ChangeKind::PageContent, page)),
            Kind::Comment => {
                let comments = annot_class(self.old, Some(o)) == AnnotClass::Comment
                    && annot_class(self.new, Some(n)) == AnnotClass::Comment;
                let actions = dicts.is_some_and(|(a, b)| {
                    !same_value(a.get(b"A").ok(), b.get(b"A").ok())
                        || !same_value(a.get(b"AA").ok(), b.get(b"AA").ok())
                });
                if !comments {
                    self.push(never(ChangeKind::AnnotationChanged, page));
                } else if actions {
                    self.push(never(ChangeKind::Actions, page));
                } else {
                    self.push(seen(ChangeKind::CommentChanged, page, Need::Comment));
                }
            }
            Kind::CommentPart => self.push(seen(ChangeKind::CommentChanged, page, Need::Comment)),
            Kind::OtherAnnot | Kind::OtherAnnotPart => {
                self.push(never(ChangeKind::AnnotationChanged, page))
            }
            Kind::Field => {
                let keys = match dicts {
                    Some((a, b)) => Self::differing(a, b),
                    None => vec![b"Type".to_vec()],
                };
                let mut filled = false;
                for k in keys {
                    if FILL_KEYS.contains(&k.as_slice()) {
                        filled = true;
                    } else if k == b"Ff" && dicts.is_some_and(|(a, b)| self.only_read_only(a, b)) {
                        // Signing a field that locks others makes them read-only (Acrobat).
                        self.push_field(owner, FieldChange::MadeReadOnly, page);
                    } else if k != b"Kids" {
                        self.push_field(owner, FieldChange::Changed, page);
                    }
                }
                if filled {
                    self.push_field(owner, FieldChange::Filled, page);
                }
            }
            Kind::FieldPart => self.push_field(owner, FieldChange::Filled, page),
            Kind::SigField => {
                let was_signed = signed_field(self.or, owner);
                let keys = match dicts {
                    Some((a, b)) => Self::differing(a, b),
                    None => vec![b"Type".to_vec()],
                };
                let is_signed = signed_field(self.nr, owner);
                for k in keys {
                    if was_signed {
                        self.push_field(owner, FieldChange::SignatureChanged, page);
                    } else if k == b"F"
                        && is_signed
                        && dicts.is_some_and(|(a, b)| only_locked(a, b))
                    {
                        // Acrobat locks the widget it signs.
                    } else if !SIGN_KEYS.contains(&k.as_slice()) && k != b"Kids" {
                        self.push_field(owner, FieldChange::Changed, page);
                    } else if !is_signed {
                        // Changed, but not signed.
                        self.push_field(owner, FieldChange::Changed, page);
                    }
                }
            }
            Kind::SigFieldPart => {
                let was_signed = signed_field(self.or, owner);
                let is_signed = signed_field(self.nr, owner);
                if was_signed {
                    self.push_field(owner, FieldChange::SignatureChanged, page);
                } else if !is_signed {
                    self.push_field(owner, FieldChange::Changed, page);
                }
                // Otherwise part of signing the field, reported with the fields.
            }
            Kind::SigDict | Kind::SigPart => {
                self.push_field(owner, FieldChange::SignatureChanged, page)
            }
            Kind::FieldMeta => self.push_field(owner, FieldChange::Changed, page),
            Kind::Action => self.push(never(ChangeKind::Actions, page)),
            Kind::Perms => match dicts {
                Some((a, b)) => self.perms(a, b),
                None => self.push(never(
                    ChangeKind::DocumentChanged("the document's permissions".into()),
                    None,
                )),
            },
            Kind::Names => match dicts {
                Some((a, b)) => self.names(a, b),
                None => self.push(never(ChangeKind::DocumentChanged("/Names".into()), None)),
            },
            Kind::NamedAppearance => {
                self.push(seen(ChangeKind::CommentAppearances, None, Need::Comment))
            }
            Kind::Encrypt => self.push(never(
                ChangeKind::DocumentChanged("encryption".into()),
                None,
            )),
            Kind::Other => self.push(never(
                ChangeKind::DocumentChanged(format!("object {}", id.0)),
                None,
            )),
        }
    }

    fn catalog(&mut self, a: &Dictionary, b: &Dictionary) {
        for k in Self::differing(a, b) {
            match k.as_slice() {
                b"AcroForm" => {
                    let empty = Dictionary::new();
                    let fa = a.get(b"AcroForm").ok().and_then(|o| self.old.dict(o));
                    let fb = b.get(b"AcroForm").ok().and_then(|o| self.new.dict(o));
                    match (fa, fb) {
                        (_, None) => self.push(never(
                            ChangeKind::DocumentChanged("the form was removed".into()),
                            None,
                        )),
                        (fa, Some(fb)) => self.acroform(fa.unwrap_or(&empty), fb),
                    }
                }
                b"DSS" | b"Extensions" => {
                    self.push(seen(ChangeKind::ValidationData, None, Need::Nothing))
                }
                b"Metadata" | b"Version" => {
                    self.push(seen(ChangeKind::Metadata, None, Need::Nothing))
                }
                b"Pages" => self.push(never(ChangeKind::PagesChanged, None)),
                b"OpenAction" | b"AA" => self.push(never(ChangeKind::Actions, None)),
                b"Names" | b"Perms" => {
                    let empty = Dictionary::new();
                    let da = a.get(&k).ok().and_then(|o| self.old.dict(o));
                    let db = b.get(&k).ok().and_then(|o| self.new.dict(o));
                    let (da, db) = (da.unwrap_or(&empty), db.unwrap_or(&empty));
                    if k == b"Names" {
                        self.names(da, db);
                    } else {
                        self.perms(da, db);
                    }
                }
                other => self.push(never(
                    ChangeKind::DocumentChanged(format!("/{}", String::from_utf8_lossy(other))),
                    None,
                )),
            }
        }
    }

    /// The name trees: only the comment icon appearances may change.
    fn names(&mut self, a: &Dictionary, b: &Dictionary) {
        for k in Self::differing(a, b) {
            if k == b"AP" {
                self.push(seen(ChangeKind::CommentAppearances, None, Need::Comment));
            } else {
                self.push(never(
                    ChangeKind::DocumentChanged(format!("/Names /{}", String::from_utf8_lossy(&k))),
                    None,
                ));
            }
        }
    }

    /// The document's permissions: Reader usage rights may be removed; nothing else may
    /// change.
    fn perms(&mut self, a: &Dictionary, b: &Dictionary) {
        for k in Self::differing(a, b) {
            if matches!(k.as_slice(), b"UR3" | b"UR") && !b.has(&k) {
                self.push(seen(ChangeKind::UsageRightsRemoved, None, Need::Nothing));
            } else {
                self.push(never(
                    ChangeKind::DocumentChanged("the document's permissions".into()),
                    None,
                ));
            }
        }
    }

    /// The form dictionary: fields are compared one by one; signature flags change with
    /// signing; fonts and defaults for filling in may change with form filling.
    fn acroform(&mut self, a: &Dictionary, b: &Dictionary) {
        for k in Self::differing(a, b) {
            match k.as_slice() {
                b"Fields" | b"SigFlags" => {}
                b"DR" | b"DA" | b"Q" => {
                    self.push(seen(ChangeKind::FormSettings, None, Need::Fill(None)))
                }
                // Turned off, it asks nothing; turned on, every field would be redrawn
                // from its value, which can change what the page shows.
                b"NeedAppearances"
                    if !b
                        .get(b"NeedAppearances")
                        .ok()
                        .and_then(|o| self.new.resolve(o))
                        .is_some_and(|o| o.as_bool().unwrap_or(true)) =>
                {
                    self.push(seen(ChangeKind::FormSettings, None, Need::Fill(None)))
                }
                b"CO" | b"NeedAppearances" => self.push(never(
                    ChangeKind::DocumentChanged(format!("form /{}", String::from_utf8_lossy(&k))),
                    None,
                )),
                other => self.push(never(
                    ChangeKind::DocumentChanged(format!(
                        "form /{}",
                        String::from_utf8_lossy(other)
                    )),
                    None,
                )),
            }
        }
    }
}

/// Whether the annotation flags only gained Locked (128) or LockedContents (512).
fn only_locked(a: &Dictionary, b: &Dictionary) -> bool {
    let flags = |d: &Dictionary| match d.get(b"F") {
        Ok(Object::Integer(f)) => Some(*f),
        Err(_) => Some(0),
        Ok(_) => None,
    };
    match (flags(a), flags(b)) {
        (Some(x), Some(y)) => x & !y == 0 && (y & !x) & !(128 | 512) == 0,
        _ => false,
    }
}

/// A field signed (`new_visible` set when the field was added in the same step).
fn sign_seen(f: &FieldInfo, new_visible: Option<bool>) -> Seen {
    let kind = if f.timestamp {
        ChangeKind::DocumentTimestamp(f.name.clone())
    } else {
        ChangeKind::Signed(f.name.clone())
    };
    seen(
        kind,
        None,
        Need::Sign {
            field: f.name.clone(),
            new_visible,
            timestamp: f.timestamp,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::budget_seam;
    use crate::forms::FieldKind;
    use crate::incremental::append_revision;
    use lopdf::dictionary;
    use std::cell::Cell;

    thread_local! {
        /// Objects compared (`same_object`) on this thread.
        pub(super) static COMPARED: Cell<usize> = const { Cell::new(0) };
        /// `/Annots` entries role assignment looked at on this thread.
        pub(super) static LOOKED: Cell<usize> = const { Cell::new(0) };
        /// Objects role assignment walked through on this thread.
        pub(super) static WALKED: Cell<usize> = const { Cell::new(0) };
        /// Numbers of widgets' `/Rect` read on this thread.
        pub(super) static RECT_READ: Cell<usize> = const { Cell::new(0) };
        /// Fields of the newer version `Judge::fields` looked at, on this thread.
        pub(super) static FIELDS_LOOKED: Cell<usize> = const { Cell::new(0) };
        /// Field names copied for changes found (`FieldInfo::copied_name`), on this thread.
        pub(super) static NAMES_COPIED: Cell<usize> = const { Cell::new(0) };
        /// Bytes looked at telling whether a revision ends at a version's end, on this thread.
        pub(super) static SCANNED: Cell<usize> = const { Cell::new(0) };
    }

    fn square(n: usize) -> Dictionary {
        dictionary! {
            "NM" => Object::string_literal(format!("square {n}")),
            "Type" => "Annot",
            "Subtype" => "Square",
            "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
        }
    }

    /// Changes found: (kind, page, allowed).
    type Found = Vec<(ChangeKind, Option<usize>, bool)>;

    /// `pages` pages sharing one `/Annots` array of `n` entries made by `entry`, then a
    /// revision adding one more: the changes after the first version, the objects compared
    /// finding them, and the entries role assignment looked at.
    fn shared_list_grown(
        pages: usize,
        n: usize,
        entry: impl Fn(&mut Document, usize) -> Object,
    ) -> (Found, usize, usize) {
        let (signed, p) = shared_list(pages, n, entry);
        COMPARED.set(0);
        LOOKED.set(0);
        let found = changes_since(&signed, &p);
        (found, COMPARED.get(), LOOKED.get())
    }

    /// `pages` pages sharing one `/Annots` array of `n` entries made by `entry`, saved (to be
    /// signed), and a revision of it adding one more.
    fn shared_list(
        pages: usize,
        n: usize,
        entry: impl Fn(&mut Document, usize) -> Object,
    ) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        for i in 0..pages {
            p.insert_blank(i, 300.0, 200.0).unwrap();
        }
        let list: Vec<Object> = (0..n).map(|i| entry(&mut p.doc, i)).collect();
        let list = p.doc.add_object(list);
        for page in p.page_ids() {
            p.doc.get_dictionary_mut(page).unwrap().set("Annots", list);
        }
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let added = entry(&mut p.doc, n);
        (p.doc.get_object_mut(list).and_then(Object::as_array_mut))
            .unwrap()
            .push(added);
        (signed, p)
    }

    /// The fields whose signatures `verify_signatures` lists in `p`: signature fields with a
    /// value.
    fn listed(p: &Pdf) -> HashSet<ObjectId> {
        let value = |id| p.doc.get_dictionary(id).ok().and_then(|d| d.get(b"V").ok());
        (p.form_nodes().into_iter())
            .filter(|(f, n)| {
                f.kind == FieldKind::Signature
                    && value(n.id).is_some_and(|v| !matches!(v, Object::Null))
            })
            .map(|(_, n)| n.id)
            .collect()
    }

    /// The changes after `signed` that `p`, a revision of it, makes.
    fn changes_since(signed: &[u8], p: &Pdf) -> Found {
        changes_certified(signed, p, None)
    }

    /// The changes after `signed` that `p`, a revision of it, makes, when `signed` is
    /// certified with `certified`.
    fn changes_certified(signed: &[u8], p: &Pdf, certified: Option<Permissions>) -> Found {
        let bytes = append_revision(signed, &p.doc).unwrap().bytes;
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let sig = Signed {
            end: signed.len(),
            locks: None,
        };
        let found = analyse(&mut versions, &[sig], &listed(&whole), certified);
        found[0]
            .iter()
            .map(|c| (c.kind.clone(), c.page, c.allowed()))
            .collect()
    }

    /// Two pages sharing a list of 2,000 annotations, one more added after signing: the list
    /// is compared with the one before once, by reference, and the change shows on each page.
    #[test]
    fn signature_changes_compare_each_annots_list_once() {
        let refer = |d: &mut Document, i| d.add_object(square(i)).into();
        let (found, compared, _) = shared_list_grown(2, 2_000, refer);
        let added = |page| (ChangeKind::CommentAdded, Some(page), true);
        assert_eq!(found, [added(0), added(1)]);
        assert!(compared <= 5_000, "{compared} objects compared");
    }

    /// Annotations written into the list directly (which the format doesn't allow) are
    /// compared among themselves within a step count, past which the document is too complex
    /// to check.
    #[test]
    fn direct_annotations_past_the_step_count_are_too_complex_to_check() {
        let (found, _, _) = shared_list_grown(2, 3_000, |_, i| square(i).into());
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// A thousand pages sharing a list of 1,000 annotations, one more added after signing:
    /// assigning roles looks through the list once a version, not once a page, and the
    /// change shows on each page.
    #[test]
    fn roles_look_through_a_list_pages_share_once() {
        let refer = |d: &mut Document, i| d.add_object(square(i)).into();
        let (found, _, looked) = shared_list_grown(1_000, 1_000, refer);
        let added: Vec<_> = (0..1_000)
            .map(|page| (ChangeKind::CommentAdded, Some(page), true))
            .collect();
        assert_eq!(found, added);
        assert!(looked <= 5_000, "{looked} entries looked at");
    }

    /// A hundred pages sharing a list of 100 annotations written into it directly, one more
    /// added after signing: each page's roles walk them again, at a step for each of their
    /// objects, so at 50,000 steps the document is too complex to check.
    #[test]
    fn annotations_in_a_shared_list_cost_steps_on_each_page() {
        let direct = |_: &mut Document, i| square(i).into();
        let (found, _, _) = shared_list_grown(100, 100, direct);
        let added: Vec<_> = (0..100)
            .map(|page| (ChangeKind::CommentAdded, Some(page), true))
            .collect();
        assert_eq!(found, added);
        let (signed, p) = shared_list(100, 100, direct);
        let (found, _) = budget_seam::with_limit(50_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// 100 pages sharing a list of 100 fields' widgets, emptied after signing with the fields
    /// kept: each field changed shows on each page, 10,000 changes. Each costs a step, so
    /// with 5,000 steps the document is too complex to check.
    #[test]
    fn annotation_changes_on_each_page_count_against_the_steps() {
        let mut p = Pdf::new();
        for i in 0..100 {
            p.insert_blank(i, 300.0, 200.0).unwrap();
        }
        let widgets: Vec<Object> = (0..100)
            .map(|i| {
                let w = dictionary! {
                    "Type" => "Annot",
                    "Subtype" => "Widget",
                    "FT" => "Tx",
                    "T" => Object::string_literal(format!("f{i}")),
                    "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
                };
                p.doc.add_object(w).into()
            })
            .collect();
        let list = p.doc.add_object(widgets.clone());
        for page in p.page_ids() {
            p.doc.get_dictionary_mut(page).unwrap().set("Annots", list);
        }
        let form = p.doc.add_object(dictionary! { "Fields" => widgets });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        p.doc.objects.insert(list, Object::Array(Vec::new()));

        let found = changes_since(&signed, &p);
        let first = (ChangeKind::FieldChanged("f0".into()), Some(0), false);
        assert_eq!((found.len(), &found[0]), (10_000, &first));
        let (found, _) = budget_seam::with_limit(5_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        let refused = (ChangeKind::Malformed(why), None, false);
        assert_eq!((found.len(), &found[0]), (1, &refused));
    }

    /// `pages` pages sharing the resources `shared` makes, saved (to be signed), and a
    /// revision of it changing the dictionary `shared` names after them.
    fn shared_resources(
        pages: usize,
        shared: impl Fn(&mut Document) -> (ObjectId, ObjectId),
    ) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        for i in 0..pages {
            p.insert_blank(i, 300.0, 200.0).unwrap();
        }
        let (res, changed) = shared(&mut p.doc);
        for page in p.page_ids() {
            p.doc
                .get_dictionary_mut(page)
                .unwrap()
                .set("Resources", res);
        }
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(changed).unwrap()).set("Changed", true);
        (signed, p)
    }

    /// A thousand pages sharing resources that hold a list of 1,000 numbers, changed after
    /// signing: the change shows on each page, and assigning roles walks the list once a
    /// version, not once a page.
    #[test]
    fn roles_walk_what_pages_share_once() {
        let shared = |d: &mut Document| {
            let junk: Vec<Object> = (0..1_000i64).map(Object::from).collect();
            let res = d.add_object(dictionary! { "Junk" => junk });
            (res, res)
        };
        let (signed, p) = shared_resources(1_000, shared);
        WALKED.set(0);
        let found = changes_since(&signed, &p);
        let walked = WALKED.get();
        let changed: Found = (0..1_000)
            .map(|page| (ChangeKind::PageContent, Some(page), false))
            .collect();
        assert_eq!(found, changed);
        assert!(walked <= 50_000, "{walked} objects walked");
    }

    /// A hundred pages sharing resources of 100 objects that each refer to the same 100
    /// others, one of those changed after signing: each page reaches each of the 100 again
    /// through each of the 100, a step each time, so at 100,000 steps the document is too
    /// complex to check.
    #[test]
    fn references_reached_again_cost_steps() {
        let shared = |d: &mut Document| {
            let ends: Vec<ObjectId> = (0..100i64)
                .map(|j| d.add_object(dictionary! { "N" => j }))
                .collect();
            let list: Vec<Object> = ends.iter().map(|&end| end.into()).collect();
            let mut res = Dictionary::new();
            for i in 0..100 {
                let middle = d.add_object(dictionary! { "Junk" => list.clone() });
                res.set(format!("R{i}"), middle);
            }
            (d.add_object(res), ends[0])
        };
        let (signed, p) = shared_resources(100, shared);
        let found = changes_since(&signed, &p);
        let changed: Found = (0..100)
            .map(|page| (ChangeKind::PageContent, Some(page), false))
            .collect();
        assert_eq!(found, changed);
        let (found, _) = budget_seam::with_limit(100_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// The last object assigning roles reaches, reached from the form first, refers 5,000
    /// times to one the catalog reached already: a step each, so at 2,000 steps the document
    /// is too complex to check.
    #[test]
    fn references_reached_again_last_cost_steps() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let x = p.doc.new_object_id();
        let y = p.doc.add_object(vec![Object::from(x); 5_000]);
        p.doc.objects.insert(x, dictionary! { "Y" => y }.into());
        let form = p.doc.add_object(dictionary! { "XFA" => x });
        let root = p.doc.trailer.get(b"Root").and_then(Object::as_reference);
        let catalog = p.doc.get_dictionary_mut(root.unwrap()).unwrap();
        catalog.set("Foo", x);
        catalog.set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(x).unwrap()).set("Changed", true);
        let found = changes_since(&signed, &p);
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.0, ChangeKind::Malformed(_))),
            "{found:?}"
        );
        let (found, _) = budget_seam::with_limit(2_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// A structure element holding 5,000 marked pieces of a page, which the structure tree's
    /// parent tree lists once for each, changed after signing: the catalog reaches it the
    /// first time only, so the list is a step, and the check comes out the same within 1,000.
    #[test]
    fn a_parent_tree_listing_an_element_again_costs_a_step() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let page = p.page_ids()[0];
        let tree = p.doc.new_object_id();
        let marks: Vec<Object> = (0..5_000i64).map(Object::from).collect();
        let element = p.doc.add_object(dictionary! {
            "S" => "P",
            "P" => tree,
            "Pg" => page,
            "K" => marks,
        });
        let parents = p.doc.add_object(vec![Object::from(element); 5_000]);
        let nums = dictionary! { "Nums" => vec![Object::from(0i64), parents.into()] };
        let root = dictionary! { "K" => element, "ParentTree" => nums };
        p.doc.objects.insert(tree, root.into());
        let catalog = p.doc.trailer.get(b"Root").and_then(Object::as_reference);
        (p.doc.get_dictionary_mut(catalog.unwrap()).unwrap()).set("StructTreeRoot", tree);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(element).unwrap()).set("Changed", true);
        let found = changes_since(&signed, &p);
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.0, ChangeKind::Malformed(_))),
            "{found:?}"
        );
        let (limited, _) = budget_seam::with_limit(1_000, || changes_since(&signed, &p));
        assert_eq!(limited, found);
    }

    /// A page listing 1,000 annotations that are each an array holding the same dictionary of
    /// 1,000 numbers, changed after signing: assigning roles walks the dictionary once a
    /// version, not once for each array reaching it.
    #[test]
    fn parts_reached_through_many_arrays_are_walked_once() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let junk: Vec<Object> = (0..1_000i64).map(Object::from).collect();
        let shared = p.doc.add_object(dictionary! { "Junk" => junk });
        let list: Vec<Object> = (0..1_000)
            .map(|_| p.doc.add_object(vec![Object::from(shared)]).into())
            .collect();
        let page = p.page_ids()[0];
        p.doc.get_dictionary_mut(page).unwrap().set("Annots", list);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(shared).unwrap()).set("Changed", true);
        WALKED.set(0);
        let found = changes_since(&signed, &p);
        let walked = WALKED.get();
        assert_eq!(found, [(ChangeKind::AnnotationChanged, Some(0), false)]);
        assert!(walked <= 50_000, "{walked} objects walked");
    }

    /// Three hundred pages on one article thread, a bead each: each page reaches every bead
    /// through the thread's links, a step each, and reaching a bead's neighbour again adds
    /// nothing to that, so the check comes out the same within 150,000 steps.
    #[test]
    fn a_thread_through_every_page_costs_a_step_a_bead() {
        let mut p = Pdf::new();
        for i in 0..300 {
            p.insert_blank(i, 300.0, 200.0).unwrap();
        }
        let pages = p.page_ids();
        let d = &mut p.doc;
        let beads: Vec<ObjectId> = pages.iter().map(|_| d.new_object_id()).collect();
        let thread = d.add_object(dictionary! { "F" => beads[0] });
        for (i, (&bead, &page)) in beads.iter().zip(&pages).enumerate() {
            let mut b = dictionary! {
                "P" => page,
                "N" => beads[(i + 1) % beads.len()],
                "V" => beads[(i + beads.len() - 1) % beads.len()],
            };
            if i == 0 {
                b.set("T", thread);
            }
            d.objects.insert(bead, b.into());
            (d.get_dictionary_mut(page).unwrap()).set("B", vec![Object::from(bead)]);
        }
        let root = d.trailer.get(b"Root").and_then(Object::as_reference);
        (d.get_dictionary_mut(root.unwrap()).unwrap()).set("Threads", vec![thread.into()]);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(thread).unwrap()).set("Changed", true);
        let found = changes_since(&signed, &p);
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.0, ChangeKind::Malformed(_))),
            "{found:?}"
        );
        let (limited, _) = budget_seam::with_limit(150_000, || changes_since(&signed, &p));
        assert_eq!(limited, found);
    }

    /// A one-page document whose page tree `shape` reshapes (given the document, the tree's
    /// root and the page), saved (to be signed), and a revision of it drawing on the page.
    fn page_drawn_on(shape: impl FnOnce(&mut Document, ObjectId, ObjectId)) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let page = p.page_ids()[0];
        let root = p.doc.catalog().unwrap().get(b"Pages");
        let root = root.and_then(Object::as_reference).unwrap();
        shape(&mut p.doc, root, page);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let contents = p.doc.get_dictionary(page).unwrap().get(b"Contents");
        let contents = contents.and_then(Object::as_reference).unwrap();
        let drawn = Stream::new(Dictionary::new(), b"0 0 m 10 10 l S".to_vec());
        p.doc.objects.insert(contents, drawn.into());
        (signed, p)
    }

    /// `n` page-tree nodes, each the only kid of the next, the first holding `kids`: the
    /// last of them.
    fn chain(d: &mut Document, n: usize, mut kids: Vec<Object>) -> ObjectId {
        let mut top = None;
        for _ in 0..n {
            let id = d.add_object(dictionary! { "Type" => "Pages", "Kids" => kids });
            kids = vec![id.into()];
            top = Some(id);
        }
        top.unwrap()
    }

    /// A page 70 levels down its page tree, and one 2 levels down that a chain 64 levels deep
    /// reaches first, drawn on after signing: the drawing is found as on a plain document.
    #[test]
    fn pages_deep_in_the_tree_are_checked() {
        let (signed, p) = page_drawn_on(|_, _, _| {});
        let plain = changes_since(&signed, &p);
        assert!(!plain.is_empty());
        let (signed, p) = page_drawn_on(|d, root, page| {
            let top = chain(d, 69, vec![page.into()]);
            (d.get_dictionary_mut(root).unwrap()).set("Kids", vec![Object::from(top)]);
        });
        assert_eq!(changes_since(&signed, &p), plain);
        let (signed, p) = page_drawn_on(|d, root, page| {
            let near = chain(d, 1, vec![page.into()]);
            let top = chain(d, 63, vec![near.into()]);
            let kids = vec![Object::from(top), near.into()];
            (d.get_dictionary_mut(root).unwrap()).set("Kids", kids);
        });
        assert_eq!(changes_since(&signed, &p), plain);
    }

    /// A thousand page-tree nodes each listing the same 1,001 kids, a page and themselves, the
    /// page drawn on after signing: each kid listed is a step, about a million, so the drawing
    /// is found as on a plain document, and at 100,000 steps the document is too complex to
    /// check.
    #[test]
    fn page_tree_kids_cost_a_step_each() {
        let (signed, p) = page_drawn_on(|_, _, _| {});
        let plain = changes_since(&signed, &p);
        let (signed, p) = page_drawn_on(|d, root, page| {
            let list = d.new_object_id();
            let mut kids = vec![Object::from(page)];
            for _ in 0..1_000 {
                let node = d.add_object(dictionary! { "Type" => "Pages", "Kids" => list });
                kids.push(node.into());
            }
            d.objects.insert(list, kids.into());
            (d.get_dictionary_mut(root).unwrap()).set("Kids", list);
        });
        assert_eq!(changes_since(&signed, &p), plain);
        let (found, _) = budget_seam::with_limit(100_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// A one-page document with a form whose fields `make` makes, giving the form's list and
    /// a field, saved (to be signed), and a revision of it filling in that field.
    fn form_filled(make: impl FnOnce(&mut Document) -> (Vec<Object>, ObjectId)) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let (fields, filled) = make(&mut p.doc);
        let form = p.doc.add_object(dictionary! { "Fields" => fields });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        (p.doc.get_dictionary_mut(filled).unwrap()).set("V", Object::string_literal("x"));
        (signed, p)
    }

    /// A field 40 levels down the form, filled after signing: it's found as a field named
    /// with all 40 names is when it's the form's only one.
    #[test]
    fn fields_deep_in_the_form_are_checked() {
        let names: Vec<String> = (0..40).map(|i| format!("f{i}")).collect();
        let (signed, p) = form_filled(|d| {
            let named = Object::string_literal(names.join("."));
            let f = d.add_object(dictionary! { "FT" => "Tx", "T" => named });
            (vec![f.into()], f)
        });
        let plain = changes_since(&signed, &p);
        assert!(!plain.is_empty());
        let (signed, p) = form_filled(|d| {
            let last = Object::string_literal(names[39].as_str());
            let last = d.add_object(dictionary! { "FT" => "Tx", "T" => last });
            let mut top = last;
            for name in names[..39].iter().rev() {
                let kids = vec![Object::from(top)];
                let name = Object::string_literal(name.as_str());
                top = d.add_object(dictionary! { "T" => name, "Kids" => kids });
            }
            (vec![top.into()], last)
        });
        assert_eq!(changes_since(&signed, &p), plain);
    }

    /// Fields named with 64 KB each, whose 1,000 other entries or 1,000 parts change after
    /// signing: a text field's entries and parts; an unsigned signature field's entries, parts
    /// and seed value parts; a signed one's entries and its signature's parts. Each field's
    /// change is found once, its name copied once, not once a key or a part (1,000 times each
    /// before, 64 MB a field and twice that with what it needs).
    #[test]
    fn a_fields_change_is_found_once_however_many_keys_or_parts_change() {
        fn keyed(mut d: Dictionary) -> Dictionary {
            for i in 0..1_000 {
                d.set(format!("K{i}"), 0);
            }
            d
        }
        fn parts(doc: &mut lopdf::Document, all: &mut Vec<ObjectId>) -> Object {
            let list: Vec<Object> = (0..1_000)
                .map(|_| {
                    let r = doc.add_object(dictionary! { "N" => 0 });
                    all.push(r);
                    r.into()
                })
                .collect();
            list.into()
        }
        let name = |c: char| c.to_string().repeat(65_536);
        let t = |c: char| Object::string_literal(name(c));
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let (doc, mut all) = (&mut p.doc, Vec::new());
        let text_parts = parts(doc, &mut all);
        let sig_parts = parts(doc, &mut all);
        let seed_parts = parts(doc, &mut all);
        let value = doc.add_object(dictionary! { "Type" => "Sig" });
        let value_parts = parts(doc, &mut all);
        let value_parts = doc.add_object(dictionary! { "Type" => "Sig", "X" => value_parts });
        let ids: Vec<ObjectId> = [
            keyed(dictionary! { "FT" => "Tx", "T" => t('a') }),
            dictionary! { "FT" => "Tx", "T" => t('b'), "X" => text_parts },
            keyed(dictionary! { "FT" => "Sig", "T" => t('c') }),
            dictionary! { "FT" => "Sig", "T" => t('d'), "X" => sig_parts },
            dictionary! { "FT" => "Sig", "T" => t('e'), "SV" => seed_parts },
            keyed(dictionary! { "FT" => "Sig", "T" => t('f'), "V" => value }),
            dictionary! { "FT" => "Sig", "T" => t('g'), "V" => value_parts },
        ]
        .into_iter()
        .map(|f| doc.add_object(f))
        .collect();
        let fields: Vec<Object> = ids.iter().map(|&f| f.into()).collect();
        let form = doc.add_object(dictionary! { "Fields" => fields });
        doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        for f in [ids[0], ids[2], ids[5]] {
            let d = p.doc.get_dictionary_mut(f).unwrap();
            for i in 0..1_000 {
                d.set(format!("K{i}"), 1);
            }
        }
        for &r in &all {
            p.doc.get_dictionary_mut(r).unwrap().set("N", 1);
        }
        let bytes = append_revision(&signed, &p.doc).unwrap().bytes;
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let end = signed.len();
        let (listed, mut cache) = (listed(&whole), HashMap::new());
        NAMES_COPIED.set(0);
        let raw = changes_after(&mut versions, &bytes, end, &[end], &listed, &mut cache);
        let copied = NAMES_COPIED.get();
        let count = |kind: ChangeKind| raw.iter().filter(|s| s.kind == kind).count();
        let found = [
            count(ChangeKind::FieldChanged(name('a'))),
            count(ChangeKind::FieldFilled(name('b'))),
            count(ChangeKind::FieldChanged(name('c'))),
            count(ChangeKind::FieldChanged(name('d'))),
            count(ChangeKind::FieldChanged(name('e'))),
            count(ChangeKind::SignatureChanged(name('f'))),
            count(ChangeKind::SignatureChanged(name('g'))),
        ];
        assert_eq!(found, [1; 7]);
        assert_eq!(copied, 7, "names copied");
    }

    /// A page listing a text field's and a signed signature field's widgets 1,000 times each,
    /// fields named with 64 KB, taken off it after signing with the fields kept, and another
    /// text field's widget from before put on it 1,000 times. Each change is found once, its
    /// name copied once, not once an entry (1,000 times each before, 64 MB a field).
    #[test]
    fn a_widget_listed_again_and_again_is_judged_once() {
        let name = |c: char| c.to_string().repeat(65_536);
        let widget = |c: char| {
            dictionary! {
                "Type" => "Annot", "Subtype" => "Widget", "T" => Object::string_literal(name(c)),
                "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
            }
        };
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let doc = &mut p.doc;
        let value = doc.add_object(dictionary! { "Type" => "Sig" });
        let (mut a, mut b, mut c) = (widget('a'), widget('b'), widget('c'));
        a.set("FT", "Tx");
        b.extend(&dictionary! { "FT" => "Sig", "V" => value });
        c.set("FT", "Tx");
        let [a, b, c] = [a, b, c].map(|w| doc.add_object(w));
        let fields: Vec<Object> = [a, b, c].iter().map(|&f| f.into()).collect();
        let form = doc.add_object(dictionary! { "Fields" => fields });
        doc.catalog_mut().unwrap().set("AcroForm", form);
        let times = |w: ObjectId| vec![Object::from(w); 1_000];
        let list = doc.add_object([times(a), times(b)].concat());
        let page = p.page_ids()[0];
        p.doc.get_dictionary_mut(page).unwrap().set("Annots", list);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        p.doc.objects.insert(list, Object::Array(times(c)));

        NAMES_COPIED.set(0);
        let found = changes_since(&signed, &p);
        let copied = NAMES_COPIED.get();
        // Each change, its name cut to its first letter and length.
        let brief = |found: &[(ChangeKind, Option<usize>, bool)]| -> Vec<String> {
            let cut = |n: &String| format!("{}.. {}", &n[..n.len().min(1)], n.len());
            let brief = |k: &ChangeKind| match k {
                ChangeKind::FieldChanged(n) => format!("FieldChanged({})", cut(n)),
                ChangeKind::SignatureChanged(n) => format!("SignatureChanged({})", cut(n)),
                k => format!("{k:?}").chars().take(80).collect(),
            };
            (found.iter())
                .map(|(k, page, ok)| format!("{}, {page:?}, {ok}", brief(k)))
                .collect()
        };
        let refused = |kind| (kind, Some(0), false);
        let want = [
            refused(ChangeKind::FieldChanged(name('a'))),
            refused(ChangeKind::FieldChanged(name('c'))),
            refused(ChangeKind::SignatureChanged(name('b'))),
        ];
        assert_eq!(brief(&found), brief(&want));
        assert_eq!(found, want);
        assert_eq!(copied, 3, "names copied");
    }

    /// A field named with 64 KB, added after signing with 1,000 fields listing it: it is
    /// found added once, its name copied once, not once for each field listing it but the
    /// first (999 times before, 64 MB).
    #[test]
    fn a_field_added_listed_by_many_is_found_once() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let form = p
            .doc
            .add_object(dictionary! { "Fields" => Vec::<Object>::new() });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let doc = &mut p.doc;
        let name = Object::string_literal("a".repeat(65_536));
        let field = doc.add_object(dictionary! { "FT" => "Tx", "T" => name });
        let fields: Vec<Object> = (0..1_000)
            .map(|i| {
                let t = Object::string_literal(format!("{i}"));
                doc.add_object(dictionary! { "T" => t, "Kids" => vec![field.into()] })
                    .into()
            })
            .collect();
        doc.get_dictionary_mut(form).unwrap().set("Fields", fields);
        let bytes = append_revision(&signed, &p.doc).unwrap().bytes;
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let end = signed.len();
        let (listed, mut cache) = (listed(&whole), HashMap::new());
        NAMES_COPIED.set(0);
        let raw = changes_after(&mut versions, &bytes, end, &[end], &listed, &mut cache);
        let copied = NAMES_COPIED.get();
        let long = |s: &&Seen| matches!(&s.kind, ChangeKind::FieldAdded(n) if n.len() > 1_000);
        assert_eq!(raw.iter().filter(long).count(), 1);
        assert_eq!(copied, 1, "names copied");
    }

    /// A thousand fields each listing the same 1,000 kids, themselves, with no area on the
    /// page: whether a field shows is worked out from the list once, not for each field, and
    /// each kid listed is a step, so at 100,000 steps the document is too complex to check.
    #[test]
    fn form_kids_cost_a_step_each() {
        let (signed, p) = form_filled(|d| {
            let list = d.new_object_id();
            let fields: Vec<Object> = (0..1_000)
                .map(|i| {
                    let f = dictionary! {
                        "T" => Object::string_literal(format!("{i}")),
                        "Rect" => vec![Object::from(0); 4],
                        "Kids" => list,
                    };
                    d.add_object(f).into()
                })
                .collect();
            d.objects.insert(list, fields.clone().into());
            let first = fields[0].as_reference().unwrap();
            (vec![first.into()], first)
        });
        RECT_READ.set(0);
        let found = changes_since(&signed, &p);
        let read = RECT_READ.get();
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.0, ChangeKind::Malformed(_))),
            "{found:?}"
        );
        assert!(read <= 50_000, "{read} numbers read");
        let (found, _) = budget_seam::with_limit(100_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// A field whose rectangle lists 10,000 numbers instead of 4: it has no area, found
    /// without reading them.
    #[test]
    fn a_rectangle_of_too_many_numbers_is_not_read() {
        let (signed, p) = form_filled(|d| {
            let rect: Vec<Object> = (0..10_000i64).map(Object::from).collect();
            let named = Object::string_literal("f");
            let f = d.add_object(dictionary! { "FT" => "Tx", "T" => named, "Rect" => rect });
            (vec![f.into()], f)
        });
        RECT_READ.set(0);
        let found = changes_since(&signed, &p);
        assert_eq!(found, [(ChangeKind::FieldFilled("f".into()), None, true)]);
        assert_eq!(RECT_READ.get(), 0);
    }

    /// A field named with 6,400 bytes over 1,000 kids: each kid's name holds it again, a step
    /// for each 64 bytes, so at 50,000 steps the document is too complex to check.
    #[test]
    fn long_field_names_cost_steps() {
        let (signed, p) = form_filled(|d| {
            let kids: Vec<Object> = (0..1_000)
                .map(|i| {
                    let named = Object::string_literal(format!("{i}"));
                    let kid = d.add_object(dictionary! { "FT" => "Tx", "T" => named });
                    kid.into()
                })
                .collect();
            let named = Object::string_literal("x".repeat(6_400));
            let first = kids[0].as_reference().unwrap();
            let root = d.add_object(dictionary! { "T" => named, "Kids" => kids });
            (vec![root.into()], first)
        });
        let found = changes_since(&signed, &p);
        assert!(
            !found
                .iter()
                .any(|f| matches!(f.0, ChangeKind::Malformed(_))),
            "{found:?}"
        );
        let (found, _) = budget_seam::with_limit(50_000, || changes_since(&signed, &p));
        let why = "the document is too complex to check".to_string();
        assert_eq!(found, [(ChangeKind::Malformed(why), None, false)]);
    }

    /// A form whose fields loop: F1 lists F2 and G, F2 lists Y, and Y lists F1's list again.
    /// Role assignment and the form's reading both name G through Y, F1.F2.Y.G, so a lock on
    /// F1.F2 reaches it.
    #[test]
    fn a_field_reached_again_through_a_loop_keeps_its_name() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let d = &mut p.doc;
        let list = d.new_object_id();
        let g = d.add_object(dictionary! { "FT" => "Tx", "T" => Object::string_literal("G") });
        let y = d.add_object(dictionary! { "T" => Object::string_literal("Y"), "Kids" => list });
        let y = vec![Object::from(y)];
        let f2 = d.add_object(dictionary! { "T" => Object::string_literal("F2"), "Kids" => y });
        let kids = vec![Object::from(f2), g.into()];
        d.objects.insert(list, kids.into());
        let f1 = d.add_object(dictionary! { "T" => Object::string_literal("F1"), "Kids" => list });
        let form = d.add_object(dictionary! { "Fields" => vec![Object::from(f1)] });
        d.catalog_mut().unwrap().set("AcroForm", form);
        let v = Version {
            pdf: &p,
            freed: HashSet::new(),
        };
        let roles = Roles::build(&v).unwrap();
        assert_eq!(roles.fields[&g].name, "F1.F2.Y.G");
        let read = p.form_nodes().into_iter().find(|(_, n)| n.id == g);
        assert_eq!(read.map(|(f, _)| f.name).as_deref(), Some("F1.F2.Y.G"));
    }

    /// Each field the form's reading finds is named and typed alike by role assignment.
    #[track_caller]
    fn roles_read_the_form_as_it_is_shown(p: &Pdf) {
        let v = Version {
            pdf: p,
            freed: HashSet::new(),
        };
        let roles = Roles::build(&v).unwrap();
        let read = p.form_nodes();
        assert!(!read.is_empty());
        for (f, n) in read {
            let r = &roles.fields[&n.id];
            let sig = matches!(f.kind, FieldKind::Signature);
            assert_eq!((r.name.as_str(), r.sig), (f.name.as_str(), sig));
        }
    }

    /// Field `K` of no kind of its own, below `chain` untitled nodes, listed through them by
    /// nodes `X1` and `X2` of no kind and by field `T` of kind `ft`, `T` first or last: role
    /// assignment names and types it as the form's reading does, through `T`. Before, it took
    /// `K` as named by the first node listing it, `X1.K`, of no kind, where the form showed
    /// `T.K`.
    #[test]
    fn a_field_a_node_of_no_kind_lists_first_is_named_through_one_with_a_kind() {
        for (ft, t_first, chain) in [
            ("Sig", false, 0),
            ("Sig", true, 0),
            ("Tx", false, 0),
            ("Sig", false, 3),
            ("Ch", false, 3),
        ] {
            let mut p = Pdf::new();
            p.insert_blank(0, 300.0, 200.0).unwrap();
            let d = &mut p.doc;
            let rect = vec![Object::from(20), 20.into(), 120.into(), 40.into()];
            let mut top =
                d.add_object(dictionary! { "T" => Object::string_literal("K"), "Rect" => rect });
            for _ in 0..chain {
                top = d.add_object(dictionary! { "Kids" => vec![Object::from(top)] });
            }
            let node = |d: &mut Document, t: &str, ft: Option<&str>| {
                let mut n = dictionary! { "T" => Object::string_literal(t), "Kids" => vec![Object::from(top)] };
                if let Some(ft) = ft {
                    n.set("FT", Object::Name(ft.into()));
                }
                Object::from(d.add_object(n))
            };
            let mut fields = vec![node(d, "X1", None), node(d, "X2", None)];
            let t = node(d, "T", Some(ft));
            if t_first {
                fields.insert(0, t);
            } else {
                fields.push(t);
            }
            let form = d.add_object(dictionary! { "Fields" => fields });
            d.catalog_mut().unwrap().set("AcroForm", form);
            assert_eq!(p.form_nodes()[0].0.name, "T.K");
            roles_read_the_form_as_it_is_shown(&p);
        }
    }

    /// A field whose `/FT` is a reference to its kind, alone or listing with a node of no kind
    /// listed before it the same field `K`: the form's reading gives it its kind, as role
    /// assignment does. Before, it took the field as of no kind.
    #[test]
    fn a_kind_given_through_a_reference_is_read_alike() {
        for shared in [false, true] {
            let mut p = Pdf::new();
            p.insert_blank(0, 300.0, 200.0).unwrap();
            let d = &mut p.doc;
            let rect = vec![Object::from(20), 20.into(), 120.into(), 40.into()];
            let sig = d.add_object(Object::Name(b"Sig".to_vec()));
            let k =
                d.add_object(dictionary! { "T" => Object::string_literal("K"), "Rect" => rect });
            let t = d.add_object(dictionary! {
                "T" => Object::string_literal("T"),
                "FT" => sig,
                "Kids" => vec![Object::from(k)],
            });
            let mut fields = vec![Object::from(t)];
            if shared {
                let x =
                    dictionary! { "T" => Object::string_literal("X"), "Kids" => vec![k.into()] };
                fields.insert(0, d.add_object(x).into());
            }
            let form = d.add_object(dictionary! { "Fields" => fields });
            d.catalog_mut().unwrap().set("AcroForm", form);
            let read = p.form_nodes();
            assert_eq!(read[0].0.name, "T.K");
            assert!(matches!(read[0].0.kind, FieldKind::Signature));
            roles_read_the_form_as_it_is_shown(&p);
        }
    }

    /// 49 nodes of no kind, then a text field, listing the same 50 kid fields of no kind of
    /// their own (forms' `nodes_of_no_kind_sharing_kid_fields_walk_them_once`): each kid is
    /// the text field's, for role assignment as for the form's reading.
    #[test]
    fn kid_fields_nodes_of_no_kind_share_are_named_through_the_field() {
        let n = 50;
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let d = &mut p.doc;
        let name = |i: usize| Object::string_literal(format!("f{i}"));
        let kids: Vec<Object> = (0..n)
            .map(|i| d.add_object(dictionary! { "T" => name(n + i) }).into())
            .collect();
        let list = d.add_object(kids);
        let fields: Vec<Object> = (0..n)
            .map(|i| {
                let mut f = dictionary! { "T" => name(i), "Kids" => list };
                if i == n - 1 {
                    f.set("FT", "Tx");
                }
                d.add_object(f).into()
            })
            .collect();
        let form = d.add_object(dictionary! { "Fields" => fields });
        d.catalog_mut().unwrap().set("AcroForm", form);
        assert_eq!(p.form_nodes().len(), n);
        roles_read_the_form_as_it_is_shown(&p);
    }

    /// Fields A and B listing the same kids, a widget that shows, and C listing a widget with
    /// no area: A and B show, C doesn't, though B's kid is A's and its answer is the list's.
    #[test]
    fn fields_sharing_a_list_of_kids_show_as_it_does() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let d = &mut p.doc;
        let rect = |n: i64| vec![Object::from(20), 20.into(), n.into(), n.into()];
        let w = d.add_object(dictionary! { "Subtype" => "Widget", "Rect" => rect(120) });
        let list = d.add_object(vec![Object::from(w)]);
        let z = d.add_object(dictionary! { "Subtype" => "Widget", "Rect" => rect(20) });
        let none = d.add_object(vec![Object::from(z)]);
        let field = |d: &mut Document, t: &str, kids: ObjectId| {
            let t = Object::string_literal(t);
            d.add_object(dictionary! { "FT" => "Sig", "T" => t, "Kids" => kids })
        };
        let a = field(d, "A", list);
        let b = field(d, "B", list);
        let c = field(d, "C", none);
        let fields = vec![Object::from(a), b.into(), c.into()];
        let form = d.add_object(dictionary! { "Fields" => fields });
        d.catalog_mut().unwrap().set("AcroForm", form);
        let v = Version {
            pdf: &p,
            freed: HashSet::new(),
        };
        let roles = Roles::build(&v).unwrap();
        let shows = [a, b, c].map(|id| roles.fields[&id].visible);
        assert_eq!(shows, [true, true, false]);
    }

    /// A signed one-page document with an empty form, and a revision adding signature field S
    /// with `depth` nodes below it, the last listing a widget on the page that acts if `act`.
    fn signature_field_added(depth: usize, act: bool) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let page = p.page_ids()[0];
        let empty: Vec<Object> = Vec::new();
        let form = p.doc.add_object(dictionary! { "Fields" => empty });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let d = &mut p.doc;
        let rect = vec![Object::from(10), 10.into(), 110.into(), 60.into()];
        let mut w = dictionary! { "Subtype" => "Widget", "Rect" => rect, "P" => page };
        if act {
            let js = Object::string_literal("app.alert(1)");
            w.set("A", dictionary! { "S" => "JavaScript", "JS" => js });
        }
        let mut top = d.add_object(w);
        (d.get_dictionary_mut(page).unwrap()).set("Annots", vec![Object::from(top)]);
        for _ in 0..depth {
            top = d.add_object(dictionary! { "Kids" => vec![Object::from(top)] });
        }
        let s = Object::string_literal("S");
        let kids = vec![Object::from(top)];
        let s = d.add_object(dictionary! { "FT" => "Sig", "T" => s, "Kids" => kids });
        (d.get_dictionary_mut(form).unwrap()).set("Fields", vec![Object::from(s)]);
        (signed, p)
    }

    /// A signed one-page document with an empty form, and a revision adding signature field S
    /// with a kid for each of `depths`, that many nodes above field `X{i}` holding a document
    /// timestamp.
    fn timestamp_field_added(depths: &[usize]) -> (Vec<u8>, Pdf) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let empty: Vec<Object> = Vec::new();
        let form = p.doc.add_object(dictionary! { "Fields" => empty });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let d = &mut p.doc;
        let mut kids = Vec::new();
        for (i, &depth) in depths.iter().enumerate() {
            let stamp = dictionary! { "Type" => "DocTimeStamp", "SubFilter" => "ETSI.RFC3161" };
            let x = Object::string_literal(format!("X{i}"));
            let mut top = d.add_object(dictionary! { "T" => x, "V" => stamp });
            for _ in 0..depth {
                top = d.add_object(dictionary! { "Kids" => vec![Object::from(top)] });
            }
            kids.push(Object::from(top));
        }
        let s = Object::string_literal("S");
        let s = d.add_object(dictionary! { "FT" => "Sig", "T" => s, "Kids" => kids });
        (d.get_dictionary_mut(form).unwrap()).set("Fields", vec![Object::from(s)]);
        (signed, p)
    }

    /// A signature field added after a certification allowing no changes, a document
    /// timestamp in a field below it: allowed when the report lists that timestamp; 40 levels
    /// down, past what it lists, nothing would check it, so it's refused, also beside one the
    /// report lists (which was all that was judged).
    #[test]
    fn a_new_signature_the_report_doesnt_list_is_refused() {
        let certified = Some(Permissions::NoChanges);
        let (signed, p) = timestamp_field_added(&[0]);
        let stamped = (ChangeKind::DocumentTimestamp("S.X0".into()), None, true);
        let found = changes_certified(&signed, &p, certified);
        assert_eq!(found, std::slice::from_ref(&stamped));
        let (signed, p) = timestamp_field_added(&[40]);
        let found = changes_certified(&signed, &p, certified);
        assert!(!found.is_empty() && found.iter().all(|f| !f.2), "{found:?}");
        let (signed, p) = timestamp_field_added(&[0, 40]);
        let found = changes_certified(&signed, &p, certified);
        let refused = found.iter().any(|f| !f.2);
        assert!(found.contains(&stamped) && refused, "{found:?}");
    }

    /// A signature field added after signing with its widget 70 levels down is judged as one
    /// with the widget right under it: its action is refused, and so, when the document is
    /// certified for filling in forms, is its showing on the page.
    #[test]
    fn a_new_signature_fields_deep_widget_is_judged() {
        for act in [true, false] {
            let certified = (!act).then_some(Permissions::FormFilling);
            let (signed, p) = signature_field_added(0, act);
            let plain = changes_certified(&signed, &p, certified);
            assert!(plain.iter().any(|f| !f.2), "{plain:?}");
            let (signed, p) = signature_field_added(70, act);
            assert_eq!(changes_certified(&signed, &p, certified), plain);
        }
    }

    /// 2,000 signature fields added after signing: judging them looks at each field a couple
    /// of times (4,000 looks), not at every field for each one (4,000,000).
    #[test]
    fn new_signature_fields_are_looked_at_a_couple_of_times_each() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let empty: Vec<Object> = Vec::new();
        let form = p.doc.add_object(dictionary! { "Fields" => empty });
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let fields: Vec<Object> = (0..2_000)
            .map(|i| {
                let t = Object::string_literal(format!("s{i}"));
                let field = p.doc.add_object(dictionary! { "FT" => "Sig", "T" => t });
                field.into()
            })
            .collect();
        (p.doc.get_dictionary_mut(form).unwrap()).set("Fields", fields);
        FIELDS_LOOKED.set(0);
        let found = changes_since(&signed, &p);
        assert_eq!(found.len(), 2_000);
        let looked = FIELDS_LOOKED.get();
        assert!(looked <= 10_000, "{looked} fields looked at");
    }

    /// A revision after signing, a later signature ending in the 64 KB of spaces after it, and
    /// 500 empty revisions after the spaces: telling which revisions end at each version's
    /// end looks at each byte a few times, not at the spaces once a revision (96 MB before),
    /// and the changes found are those without the spaces and empty revisions.
    #[test]
    fn white_space_after_a_signature_end_is_looked_at_once() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let signed = p.snapshot().unwrap();
        let mut p = Pdf::from_bytes(&signed, None).unwrap();
        let page = p.page_ids()[0];
        p.doc.get_dictionary_mut(page).unwrap().set("Rotate", 90);
        let plain = append_revision(&signed, &p.doc).unwrap().bytes;
        let mut bytes = plain.clone();
        let later = bytes.len() + 1;
        bytes.resize(bytes.len() + 65_536, b' ');
        let trailer = Pdf::from_bytes(&plain, None).unwrap().doc.trailer;
        let (num, gen) = trailer.get(b"Root").unwrap().as_reference().unwrap();
        let size = trailer.get(b"Size").unwrap().as_i64().unwrap();
        let mut prev = last_startxref(&plain).unwrap();
        // Each a cross-reference stream listing only itself, as the revision before.
        for n in size..size + 500 {
            let at = bytes.len();
            let dict = format!(
                "<< /Type /XRef /Size {} /Root {num} {gen} R /Prev {prev} /W [1 4 2] \
                 /Index [{n} 1] /Length 7 >>",
                n + 1
            );
            let head = format!("{n} 0 obj\n{dict}\nstream\n");
            bytes.extend_from_slice(head.as_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&(at as u32).to_be_bytes());
            bytes.extend_from_slice(&[0, 0]);
            let tail = format!("\nendstream\nendobj\nstartxref\n{at}\n%%EOF\n");
            bytes.extend_from_slice(tail.as_bytes());
            prev = at;
        }
        let end = signed.len();
        let changes = |bytes: &[u8], sig_ends: &[usize]| {
            let whole = Pdf::from_bytes(bytes, None).unwrap();
            let mut versions = Versions::new(bytes, None, &whole);
            let (listed, mut cache) = (listed(&whole), HashMap::new());
            SCANNED.set(0);
            let found = changes_after(&mut versions, bytes, end, sig_ends, &listed, &mut cache);
            let found: Vec<_> = found.into_iter().map(|s| (s.kind, s.need)).collect();
            (found, SCANNED.get())
        };
        let (found, scanned) = changes(&bytes, &[end, later]);
        assert!(scanned <= 4 * bytes.len(), "{scanned} bytes looked at");
        assert!(!found.is_empty());
        assert_eq!(found, changes(&plain, &[end]).0);
    }
}
