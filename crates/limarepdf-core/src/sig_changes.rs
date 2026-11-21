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
use crate::sig_verify::{
    is_delim, is_white, too_many_versions, FieldLock, Lexer, Permissions, Tok, Versions,
};
use crate::Pdf;
use lopdf::xref::XrefEntry;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::ops::Range;

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
/// only when it's one of them, as nothing else checks its signature. `unchecked` are where
/// the versions signed by the signatures that couldn't be checked end, in order.
pub(crate) fn analyse(
    versions: &mut Versions,
    sigs: &[Signed],
    unchecked: &[usize],
    listed: &HashSet<ObjectId>,
    certified: Option<Permissions>,
) -> Vec<Vec<Change>> {
    let bytes = versions.bytes;
    // A version a signature LimarePDF couldn't check signed is compared too, as other apps
    // may show it as signed: one LimarePDF doesn't open, past its limits, is refused there.
    let ends = signed_ends(
        bytes,
        (sigs.iter().map(|s| s.end)).chain(unchecked.iter().copied()),
    );
    let mut cache: HashMap<(usize, usize), Vec<Seen>> = HashMap::new();
    sigs.iter()
        .map(|s| {
            let mut seen = changes_after(versions, bytes, s.end, &ends, listed, &mut cache);
            // A later version other apps may read differently is compared as lopdf reads it,
            // as its signature can't be checked: what they show there was never seen.
            let later = (unchecked.iter().filter(|&&e| e > s.end))
                .find_map(|&e| versions.peek(e)?.differs.as_ref());
            if let Some(why) = later {
                if !seen.iter().any(|x| x.need == Need::Never) {
                    seen.push(never(
                        ChangeKind::Malformed(format!(
                            "other PDF apps may read a later signed version differently from \
                             LimarePDF ({why})"
                        )),
                        None,
                    ));
                }
            }
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

/// Where signed versions end, in order, each with where the white space just before it
/// starts: a version ends where a revision does when only white space lies between. Ends
/// past the file sign no version of it. Each byte is looked at once, however many end in
/// one run of white space.
fn signed_ends(bytes: &[u8], ends: impl IntoIterator<Item = usize>) -> Vec<(usize, usize)> {
    let mut ends: Vec<usize> = (ends.into_iter()).filter(|&e| e <= bytes.len()).collect();
    ends.sort_unstable();
    ends.dedup();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(ends.len());
    for e in ends {
        let from = out.last().map_or(0, |&(p, _)| p);
        let white = (bytes[from..e].iter().rev())
            .take_while(|&&c| is_white(c))
            .count();
        #[cfg(test)]
        tests::SCANNED.set(tests::SCANNED.get() + (white + 1).min(e - from));
        let start = match out.last() {
            Some(&(p, start)) if white == e - p => start,
            _ => e - white,
        };
        out.push((e, start));
    }
    out
}

/// The changes after the version ending at `end` (see [`changes_between`]). A document
/// other PDF apps may read differently from LimarePDF has a change that is never allowed.
fn changes_after(
    versions: &mut Versions,
    bytes: &[u8],
    end: usize,
    sig_ends: &[(usize, usize)],
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
    sig_ends: &[(usize, usize)],
    listed: &HashSet<ObjectId>,
    cache: &mut HashMap<(usize, usize), Vec<Seen>>,
) -> Vec<Seen> {
    let malformed = |why: String| vec![never(ChangeKind::Malformed(why), None)];
    let sections = match read_chain(bytes, end) {
        Ok(s) => s,
        Err(why) => return malformed(why),
    };
    // The sections a version ending at `at` has, from the first: sections come newest first,
    // their ends falling, so they're the last ones. Only the one before them can end past
    // `at`, at "%%EOF" before the end of line a revision's end takes in, at most 2 bytes
    // (`revision_end`).
    let ending_by = |at: usize| {
        let k = sections.partition_point(|s| s.end > at);
        match k.checked_sub(1) {
            Some(i) if sections[i].end <= at + 2 => {
                let gap = &bytes[at..sections[i].end];
                #[cfg(test)]
                tests::SCANNED.set(tests::SCANNED.get() + gap.len());
                if gap.iter().all(|&c| is_white(c)) {
                    i
                } else {
                    k
                }
            }
            _ => k,
        }
    };
    // A version ends where a revision does when only white space lies between, either way;
    // past every revision read, it's this signature's own version.
    let at_revision = |(at, white): (usize, usize)| match sections.get(ending_by(at)) {
        Some(s) => s.end > at || s.end >= white,
        None => white <= end,
    };
    let from = sig_ends.partition_point(|&(e, _)| e <= end);
    let to = sig_ends.partition_point(|&(e, _)| e < bytes.len());
    let later = sig_ends.get(from..to).unwrap_or_default();
    // A later version signed where no revision read ends is one other apps may show as
    // signed, but that can't be compared: a revision off the chain, or part of one.
    if !later.iter().all(|&e| at_revision(e)) {
        return malformed(
            "a later signature signs a part of the file that isn't one of the document's \
             versions, which PDF apps may show as signed"
                .into(),
        );
    }
    // The versions to compare, each with where its sections start: this one, each later
    // signed version, and the whole file.
    let anchors: Vec<(usize, usize)> = (std::iter::once(end))
        .chain(later.iter().map(|&(e, _)| e))
        .chain(std::iter::once(bytes.len()))
        .map(|at| (at, ending_by(at)))
        .collect();

    let mut out = Vec::new();
    // The numbers the sections from `freed_by` on free, brought up to `a` only for a window
    // compared, as a cached one doesn't need them.
    let (mut freed, mut freed_by) = (HashSet::new(), sections.len());
    for w in anchors.windows(2) {
        let ((a, by_a), (b, by_b)) = (w[0], w[1]);
        // Newest first, as read.
        let between: Vec<&Section> = match sections.get(by_b..by_a) {
            Some(s) if !s.is_empty() => s.iter().collect(),
            _ => continue,
        };
        // Shared by every signature: `freed` differs, but only in the numbers freed since,
        // all of which the version at `a` has freed, so none hides a change.
        let found = match cache.get(&(a, b)) {
            Some(found) => found.clone(),
            None => {
                let since: Vec<&Section> = (sections.get(by_a..freed_by).unwrap_or_default())
                    .iter()
                    .collect();
                for (num, e) in effective(&since) {
                    if e == Entry::Free {
                        freed.insert(num);
                    } else {
                        freed.remove(&num);
                    }
                }
                freed_by = by_a;
                let found = compare_versions(versions, a, b, &freed, &between, listed);
                cache.insert((a, b), found.clone());
                found
            }
        };
        let stop = found
            .iter()
            .any(|s| matches!(s.kind, ChangeKind::Malformed(_)));
        out.extend(found);
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
            // lopdf must find the signed version's section where it does in that version.
            if lopdf_moves(bytes, at) != lopdf_moves(&bytes[..signed_end], at) {
                return Err(moved(at));
            }
            return Ok(sections);
        }
        if !seen.insert(at) || sections.len() >= MAX_SECTIONS {
            return Err("the chain of revisions loops or is too long".into());
        }
        let read = read_section(bytes, at)?;
        if sections.is_empty() {
            newest_has_room(&read, at)?;
        }
        if read.stray_xref_stm {
            return Err(
                "a later revision's cross-reference stream names another one (/XRefStm), \
                 which PDF apps read differently"
                    .into(),
            );
        }
        wide_enough(&read)?;
        decoded_alike(&read, at)?;
        listed_once(&read.entries)?;
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
            wide_enough(&extra)?;
            decoded_alike(&extra, stm)?;
            listed_once(&extra.entries)?;
            // lopdf lets the stream's entry replace a free one in the table, Poppler doesn't.
            let freed: HashSet<u32> = (entries.iter())
                .filter(|(_, e)| *e == Entry::Free)
                .map(|&(num, _)| num)
                .collect();
            if let Some((num, _)) =
                (extra.entries.iter()).find(|(num, e)| *e != Entry::Free && freed.contains(num))
            {
                return Err(format!(
                    "a later revision lists object {num} as free in its cross-reference table \
                     but in use in its cross-reference stream, which PDF apps read differently"
                ));
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

/// Refuses a section listing a number twice with different entries: LimarePDF's reader
/// takes the first, lopdf the last.
fn listed_once(entries: &[(u32, Entry)]) -> Result<(), String> {
    let mut first: HashMap<u32, Entry> = HashMap::new();
    match (entries.iter()).find(|&&(num, e)| *first.entry(num).or_insert(e) != e) {
        Some((num, _)) => Err(format!(
            "a later revision gives object {num} two different cross-reference entries, which \
             PDF apps read differently"
        )),
        None => Ok(()),
    }
}

/// Refuses a cross-reference stream whose rows are under 3 bytes wide: lopdf can't read one
/// unless its data is padded, and drops it from a hybrid revision, where other apps read it.
fn wide_enough(read: &ReadSection) -> Result<(), String> {
    if read.narrow {
        return Err(
            "a later revision's cross-reference stream has entries under 3 bytes wide, which \
             some PDF apps can't read"
                .into(),
        );
    }
    Ok(())
}

/// Refuses a cross-reference stream, its section starting at `at`, whose data other apps
/// may decode differently from lopdf ([`decodes_alike`]).
fn decoded_alike(read: &ReadSection, at: usize) -> Result<(), String> {
    if read.lenient {
        return Err(format!(
            "the cross-reference stream at byte {at} holds data PDF apps may decode \
             differently: damaged, or not plain Flate data"
        ));
    }
    Ok(())
}

/// Whether other PDF apps decode stream `s` (at most `limit` bytes of it) as lopdf does:
/// unfiltered, or whole Flate data with predictor parameters they all take alike. lopdf
/// decodes damaged Flate data as far as it can, where some apps fail, and some then
/// rebuild the cross-reference information by scanning the file, finding objects no
/// section lists. lopdf reads neither indirect parameters nor the abbreviated keys some
/// apps take for `/Filter` and `/DecodeParms`. Other filters aren't relied on.
fn decodes_alike(s: &Stream, limit: usize) -> bool {
    let d = &s.dict;
    if [&b"F"[..], b"DP", b"FFilter", b"FDecodeParms"]
        .into_iter()
        .any(|k| d.has(k))
    {
        return false;
    }
    let none = |o: Option<&Object>| matches!(o, None | Some(Object::Null));
    let flate = |o: &Object| matches!(o, Object::Name(n) if n == b"FlateDecode");
    let (filter, parms) = (d.get(b"Filter").ok(), d.get(b"DecodeParms").ok());
    // Apps take parameters in an array only for filters in an array, and lopdf takes
    // parameters for one filter for all of them. lopdf decodes data with an empty list of
    // filters as nothing.
    let parms = match filter {
        _ if none(filter) => return none(parms),
        Some(f) if flate(f) => match parms {
            Some(Object::Dictionary(p)) => Some(p),
            p if none(p) => None,
            _ => return false,
        },
        Some(Object::Array(f)) if matches!(f.as_slice(), [f] if flate(f)) => match parms {
            Some(Object::Array(p)) => match p.as_slice() {
                [Object::Dictionary(p)] => Some(p),
                [Object::Null] => None,
                _ => return false,
            },
            p if none(p) => None,
            _ => return false,
        },
        _ => return false,
    };
    parms.is_none_or(predicted_alike)
        && matches!(
            crate::sanitise::inflate(&s.content, limit),
            Ok(crate::sanitise::Inflated::Whole)
        )
}

/// Whether other PDF apps take predictor parameters `p` as lopdf does: each value a direct
/// integer in the range the spec allows, and no TIFF predictor (2), which Poppler and pdf.js
/// decode differently from lopdf at 16 bits or with rows padded out to a byte. lopdf takes
/// 0 for 1, where Poppler drops the predictor, and ignores predictors 3 to 9, as Poppler
/// does, where pdf.js fails.
fn predicted_alike(p: &Dictionary) -> bool {
    let int = |k: &[u8], default: i64| match p.get(k) {
        Err(_) | Ok(Object::Null) => Some(default),
        Ok(Object::Integer(i)) => Some(*i),
        Ok(_) => None,
    };
    let (Some(predictor), Some(columns), Some(colors), Some(bits)) = (
        int(b"Predictor", 1),
        int(b"Columns", 1),
        int(b"Colors", 1),
        int(b"BitsPerComponent", 8),
    ) else {
        return false;
    };
    matches!(predictor, 1 | 10..=15)
        && (1..=32).contains(&colors)
        && matches!(bits, 1 | 2 | 4 | 8 | 16)
        && columns >= 1
        && columns < i64::from(i32::MAX) / colors / bits
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
    /// Whether a cross-reference stream names another with `/XRefStm`, which the
    /// specification gives a table's trailer only: lopdf adds that stream's entries, other
    /// apps don't.
    stray_xref_stm: bool,
    /// Whether a cross-reference stream's rows are under 3 bytes wide (`/W`), which lopdf
    /// can't read unless the data is padded.
    narrow: bool,
    /// Whether a cross-reference stream's data may decode differently in other apps
    /// ([`decodes_alike`]).
    lenient: bool,
    /// Where the section (with its trailer, or its object) ends.
    after: usize,
    /// A table's trailer, or the stream's dictionary.
    trailer: Dictionary,
}

fn read_section(bytes: &[u8], at: usize) -> Result<ReadSection, String> {
    let bad = || malformed(at);
    let mut lx = Lexer::new(bytes, at);
    let (start, tok, _) = lx.next().ok_or_else(bad)?;
    if !bytes[at..start].iter().all(|&c| is_white(c)) {
        return Err(bad());
    }
    if lopdf_moves(bytes, at).iter().any(|&to| to != start) {
        return Err(moved(at));
    }
    match tok {
        Tok::Word(b"xref") => read_table(bytes, lx).ok_or_else(bad),
        Tok::Word(_) => read_xref_stream(bytes, Lexer::new(bytes, at)).ok_or_else(bad),
        _ => Err(bad()),
    }
}

fn malformed(at: usize) -> String {
    format!("the cross-reference section at byte {at} is malformed")
}

/// Refuses the newest section, the one at `at`, when its `/Size` reaches past
/// [`MAX_ENTRIES`]: Poppler makes room for as many objects as the newest trailer gives (and
/// as every cross-reference stream's gives, which [`read_xref_stream`] checks).
fn newest_has_room(read: &ReadSection, at: usize) -> Result<(), String> {
    match read.trailer.get(b"Size") {
        Ok(Object::Integer(n)) if *n > MAX_ENTRIES => Err(malformed(at)),
        _ => Ok(()),
    }
}

fn moved(at: usize) -> String {
    format!(
        "PDF apps may take different cross-reference sections near byte {at}: the pointer to \
         it doesn't lead straight to one"
    )
}

/// Where lopdf may read the cross-reference section a pointer to `at` names, instead of
/// after the white space there. A pointer that doesn't lead straight to `xref` or an object
/// header moves to the nearest `xref` within 64 bytes (not the one in `startxref`, the
/// earlier on a tie), or, failing that and unless a header follows the white space, to the
/// nearest header within 64 bytes that starts a cross-reference stream. lopdf keeps a move
/// when the section there reads: an `xref` counts when a line ends after it, as a table
/// starts, and every header counts, so no move lopdf makes is missed.
fn lopdf_moves(bytes: &[u8], at: usize) -> Vec<usize> {
    const WINDOW: usize = 64;
    let rest = bytes.get(at..).unwrap_or_default();
    if rest.is_empty() || rest.starts_with(b"xref") || lopdf_header(rest) {
        return Vec::new();
    }
    let (lo, hi) = (at.saturating_sub(WINDOW), bytes.len().min(at + WINDOW));
    let xref = (lo..hi.saturating_sub(4))
        .filter(|&p| bytes[p..].starts_with(b"xref") && !bytes[..p].ends_with(b"start"))
        .min_by_key(|p| p.abs_diff(at));
    // lopdf tries only the nearest `xref`, and reads at `at` when no table starts there.
    if let Some(p) = xref {
        let after = &bytes[p + 4..];
        let after = after.strip_prefix(b" ").unwrap_or(after);
        let table = after.starts_with(b"\n") || after.starts_with(b"\r");
        return if table { vec![p] } else { Vec::new() };
    }
    let white = rest.iter().take_while(|c| c.is_ascii_whitespace()).count();
    if lopdf_header(&rest[white..]) {
        return Vec::new();
    }
    (lo..hi)
        .filter(|&p| p == 0 || !bytes[p - 1].is_ascii_alphanumeric())
        .filter(|&p| lopdf_header(&bytes[p..]))
        .collect()
}

/// Whether `b` starts with an object header as lopdf finds one: a number up to 10 digits,
/// spaces, a generation up to 5 digits, spaces, then `obj` not followed by a letter or digit.
fn lopdf_header(b: &[u8]) -> bool {
    fn digits<T: std::str::FromStr>(b: &[u8], cap: usize) -> Option<&[u8]> {
        let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > cap {
            return None;
        }
        std::str::from_utf8(&b[..n]).ok()?.parse::<T>().ok()?;
        Some(&b[n..])
    }
    fn spaces(b: &[u8]) -> Option<&[u8]> {
        let n = (b.iter())
            .take_while(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
            .count();
        (n > 0).then_some(&b[n..])
    }
    fn header(b: &[u8]) -> Option<()> {
        let b = spaces(digits::<u32>(b, 10)?)?;
        let b = spaces(digits::<u16>(b, 5)?)?.strip_prefix(b"obj")?;
        b.first()
            .is_none_or(|c| !c.is_ascii_alphanumeric())
            .then_some(())
    }
    header(b).is_some()
}

fn word_num<T: std::str::FromStr>(t: Option<(usize, Tok, usize)>) -> Option<T> {
    match t? {
        (_, Tok::Word(w), _) if w.iter().all(u8::is_ascii_digit) => {
            std::str::from_utf8(w).ok()?.parse().ok()
        }
        _ => None,
    }
}

/// The most objects a cross-reference section may make room for: its `/Size`, or a
/// subsection's first number and count. Poppler 26 can't make room for more than 2^24, older
/// versions for 2^25, and a machine short of memory for fewer: it then takes the section as
/// damaged, and scans the whole file for objects instead.
const MAX_ENTRIES: i64 = 1 << 23;

/// Whether the `count` object numbers from `first` fit in [`MAX_ENTRIES`].
fn has_room(first: i64, count: i64) -> bool {
    first >= 0 && count >= 0 && first.saturating_add(count) <= MAX_ENTRIES
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
        if count > bytes.len() / 18 || !has_room(first.into(), i64::try_from(count).ok()?) {
            return None;
        }
        for i in 0..count {
            let num = first.checked_add(u32::try_from(i).ok()?)?;
            // Poppler takes an offset past 2^63 - 1, or a generation past 2^31 - 1, as damage.
            let offset: i64 = word_num(lx.next())?;
            let gen: i32 = word_num(lx.next())?;
            let e = match lx.next()? {
                (_, Tok::Word(b"n"), _) => Entry::InUse {
                    offset: usize::try_from(offset).ok()?,
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
        stray_xref_stm: false,
        narrow: false,
        lenient: false,
        after: lx.pos(),
        trailer,
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
    // Poppler takes an object number past 2^31 - 1 as damage.
    let _: i32 = word_num(lx.next())?;
    let _: u16 = word_num(lx.next())?;
    if !matches!(lx.next()?, (_, Tok::Word(b"obj"), _)) {
        return None;
    }
    let dict = match read_object(&mut lx, 0)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    let (_, Tok::Word(b"stream"), keyword) = lx.next()? else {
        return None;
    };
    let start = data_start(bytes, keyword)?;
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
    let stream = Stream::new(dict.clone(), data.to_vec());
    let decoded = stream
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
    // Poppler takes a type wider than 4 bytes as damage.
    if row == 0 || w0 > 4 {
        return None;
    }
    let size = dict.get(b"Size").ok()?.as_i64().ok()?;
    if !has_room(0, size) {
        return None;
    }
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
        if count > decoded.len() / row || !has_room(pair[0], pair[1]) {
            return None;
        }
        for i in 0..count {
            let r = decoded.get(pos..pos + row)?;
            pos += row;
            let kind = if w0 == 0 { 1 } else { field(&r[..w0]) };
            let (f1, f2) = (field(&r[w0..w0 + w1]), field(&r[w0 + w1..]));
            let num = first.checked_add(u32::try_from(i).ok()?)?;
            // Poppler takes an offset past 2^63 - 1, or a generation or index past 2^31 - 1, as
            // damage, whatever the type, but for 0xFFFFFFFF in object 0's, which it reads as
            // 65535 (in a free entry; in another, LimarePDF couldn't read it alike).
            let wrapped = kind == 0 && num == 0 && f2 == u64::from(u32::MAX);
            if i64::try_from(f1).is_err() || (i32::try_from(f2).is_err() && !wrapped) {
                return None;
            }
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
        stray_xref_stm: dict.has(b"XRefStm"),
        narrow: row < 3,
        lenient: !decodes_alike(&stream, MAX_XREF_STREAM),
        after: tail.pos(),
        trailer: dict,
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
    object(lx, depth, Read::Keep)
}

/// Whether one direct object of the file's body reads as [`read_object`] reads it, without
/// building it; `decrypted` when readers decrypt it, as one outside object streams in an
/// encrypted file.
fn skip_object(lx: &mut Lexer, decrypted: bool) -> bool {
    object(lx, 0, Read::Check { decrypted }).is_some()
}

/// How [`object`] reads.
#[derive(Clone, Copy)]
enum Read {
    /// Keeping what arrays and dictionaries hold, as cross-reference information is read.
    Keep,
    /// Only whether an object of the file's body reads alike: arrays and dictionaries read as
    /// null.
    Check { decrypted: bool },
}

/// [`read_object`], or only checking, as `read` says. lopdf and pdf.js take the last value of
/// a key given twice, and so does Poppler's lookup below 32 entries; but from 32 Poppler sorts
/// them and may take another, and of a font resource dictionary it takes the first, at any
/// size. So a dictionary giving a key twice with values written differently doesn't read: in
/// cross-reference information from 32 entries, in an object at any size. Nor does one giving
/// `/Contents` twice in an object readers decrypt: Poppler decrypts the last value twice.
fn object(lx: &mut Lexer, depth: usize, read: Read) -> Option<Object> {
    if depth > 32 {
        return None;
    }
    let keep = matches!(read, Read::Keep);
    let (_, tok, _) = lx.next()?;
    Some(match tok {
        Tok::DictOpen => {
            let mut d = Dictionary::new();
            // Each key, and its value as written.
            let mut keys = Vec::new();
            loop {
                match lx.next()? {
                    (_, Tok::DictClose, _) => break,
                    (_, Tok::Name(k), _) => {
                        let mut from = lx.pos();
                        let v = object(lx, depth + 1, read)?;
                        let k = decode_name(k)?;
                        if keep {
                            d.set(k.clone(), v);
                        }
                        let bytes = lx.bytes();
                        while is_white(bytes[from]) {
                            from += 1;
                        }
                        keys.push((k, &bytes[from..lx.pos()]));
                    }
                    _ => return None,
                }
            }
            keys.sort_unstable();
            let twice = keys.windows(2).any(|w| {
                w[0].0 == w[1].0
                    && match read {
                        Read::Keep => keys.len() >= 32 && w[0].1 != w[1].1,
                        Read::Check { decrypted } => {
                            w[0].1 != w[1].1 || (decrypted && w[0].0 == b"Contents")
                        }
                    }
            });
            if twice {
                return None;
            }
            if keep {
                Object::Dictionary(d)
            } else {
                Object::Null
            }
        }
        Tok::ArrayOpen => {
            let mut a = Vec::new();
            loop {
                let mut look = lx.clone();
                if let (_, Tok::ArrayClose, _) = look.next()? {
                    *lx = look;
                    break;
                }
                let o = object(lx, depth + 1, read)?;
                if keep {
                    a.push(o);
                }
            }
            if keep {
                Object::Array(a)
            } else {
                Object::Null
            }
        }
        Tok::Name(n) => Object::Name(decode_name(n)?),
        Tok::Hex | Tok::Literal => Object::String(Vec::new(), StringFormat::Literal),
        Tok::Word(b"true") => Object::Boolean(true),
        Tok::Word(b"false") => Object::Boolean(false),
        Tok::Word(b"null") => Object::Null,
        Tok::Word(w) => match number(w)? {
            Object::Integer(n) if w.iter().all(u8::is_ascii_digit) => {
                // Perhaps `N G R`; lopdf takes one only after digits alone, where
                // other readers take `+1 0 R` too.
                let mut look = lx.clone();
                let gen: Option<u16> = word_num(look.next_word());
                let r = matches!(look.next_word(), Some((_, Tok::Word(b"R"), _)));
                match (gen, r, u32::try_from(n)) {
                    (Some(g), true, Ok(num)) => {
                        *lx = look;
                        Object::Reference((num, g))
                    }
                    _ => Object::Integer(n),
                }
            }
            n => n,
        },
        Tok::DictClose | Tok::ArrayClose => return None,
    })
}

/// A number as lopdf reads it: an integer, a sign and digits, or a real, a sign, digits, a
/// point and digits, with a digit on one side of the point. lopdf, Poppler and pdf.js skip
/// minus signs after the point (`0.00-4142502`). Not a minus inside the whole part, which
/// pdf.js skips and the others start a number at, nor what Rust reads besides (`1e5`,
/// `inf`), which PDF readers take as other tokens.
fn number(w: &[u8]) -> Option<Object> {
    let s = std::str::from_utf8(w).ok()?;
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    if !unsigned.is_empty() && unsigned.bytes().all(|c| c.is_ascii_digit()) {
        return s.parse().ok().map(Object::Integer);
    }
    let (whole, part) = unsigned.split_once('.')?;
    let digit = |c: char| c.is_ascii_digit();
    if !whole.chars().all(digit)
        || !part.chars().all(|c| digit(c) || c == '-')
        || (whole.is_empty() && !part.starts_with(digit))
    {
        return None;
    }
    let sign = &s[..s.len() - unsigned.len()];
    let part: String = part.chars().filter(|&c| c != '-').collect();
    format!("{sign}{whole}.{part}")
        .parse()
        .ok()
        .map(Object::Real)
}

/// A name's bytes: lopdf reads `#` and two hexadecimal digits as one byte and ends the name
/// at any other `#`, where Poppler and pdf.js keep it, so such a name doesn't read alike.
fn decode_name(n: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(n.len());
    let mut i = 0;
    while i < n.len() {
        if n[i] == b'#' {
            let h = n.get(i + 1..i + 3)?;
            if !h.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
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
    header(bytes, offset).map(|(id, _)| id)
}

/// [`header_id`], and a lexer past the header.
fn header(bytes: &[u8], offset: usize) -> Option<(ObjectId, Lexer<'_>)> {
    let mut lx = Lexer::new(bytes, offset);
    let first = lx.next_word();
    if !first.is_some_and(|(s, _, _)| bytes[offset..s].iter().all(|&c| is_white(c))) {
        return None;
    }
    let id = (word_num(first)?, word_num(lx.next_word())?);
    matches!(lx.next_word(), Some((_, Tok::Word(b"obj"), _))).then_some((id, lx))
}

/// Where stream data starts, `at` just past the `stream` keyword: lopdf, like pdf.js, takes
/// spaces and tabs, then a line end.
fn data_start(bytes: &[u8], mut at: usize) -> Option<usize> {
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    Some(match bytes.get(at..)? {
        [b'\r', b'\n', ..] => at + 2,
        [b'\r' | b'\n', ..] => at + 1,
        _ => return None,
    })
}

/// The dictionary of the stream whose object starts at `at`, and where its data starts.
fn stream_head(bytes: &[u8], at: usize) -> Option<(Dictionary, usize)> {
    let (_, mut lx) = header(bytes, at)?;
    let Object::Dictionary(dict) = read_object(&mut lx, 0)? else {
        return None;
    };
    let (_, Tok::Word(b"stream"), keyword) = lx.next_word()? else {
        return None;
    };
    Some((dict, data_start(bytes, keyword)?))
}

/// The `/Length` in a stream's dictionary `dict`, when it is a whole number written there or
/// in an object `spec` lists, `endobj` perhaps glued to it. An object `spec` lists in an
/// object stream is taken as `doc` holds it, given one; an object stream's own `/Length` may
/// not be in one.
fn stream_length(
    bytes: &[u8],
    dict: &Dictionary,
    spec: &HashMap<u32, Entry>,
    doc: Option<&Document>,
) -> Option<i64> {
    match dict.get(b"Length").ok()? {
        Object::Integer(n) => Some(*n),
        Object::Reference(id) => match spec.get(&id.0) {
            Some(&Entry::InUse { offset, gen }) if gen == id.1 => {
                let (found, mut lx) = header(bytes, offset)?;
                if found != *id {
                    return None;
                }
                if let Some((_, Tok::Word(w), _)) = lx.clone().next() {
                    if let Some(n) = w.strip_suffix(b"endobj") {
                        return number(n)?.as_i64().ok();
                    }
                }
                let Object::Integer(n) = read_object(&mut lx, 0)? else {
                    return None;
                };
                matches!(lx.next_word()?, (_, Tok::Word(b"endobj"), _)).then_some(n)
            }
            Some(Entry::Compressed { .. }) if id.1 == 0 => match doc?.objects.get(id)? {
                Object::Integer(n) => Some(*n),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Where the data of the stream whose object starts at `at` lies, as other apps take it: as
/// long as its `/Length` ([`stream_length`]), then `endstream` and `endobj`.
fn stream_data(
    bytes: &[u8],
    at: usize,
    spec: &HashMap<u32, Entry>,
    doc: Option<&Document>,
) -> Option<Range<usize>> {
    let (dict, start) = stream_head(bytes, at)?;
    let len = stream_length(bytes, &dict, spec, doc)?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    let mut tail = Lexer::new(bytes, end);
    (end <= bytes.len()
        && matches!(tail.next_word()?, (_, Tok::Word(b"endstream"), _))
        && matches!(tail.next_word()?, (_, Tok::Word(b"endobj"), _)))
    .then_some(start..end)
}

/// Where in the file the data lopdf took for stream `s`, whose object starts at `at`, lies,
/// when other apps take the same, white space at its end aside. Poppler and pdf.js take the
/// data as long as a whole number `/Length` when `endstream` follows, white space and comments
/// aside ([`stream_data`]). Otherwise both look for `endstream`: pdf.js for its first eight
/// bytes from the start of the data, Poppler for the word past the first token at the end of
/// the `/Length` it takes, 0 for anything but a whole number, skipping comments; Poppler
/// takes `endstream` in too, which draws nothing. lopdf takes the data as long as its
/// `/Length` when a line end at most comes before `endstream`, otherwise on to an `endstream`
/// of its own finding, and of a `/Length` written as a real as many bytes, whatever follows;
/// with none it takes nothing. What lopdf `decrypted` can't show which data it took: there
/// the others' must be followed by a line end at most and `endstream`.
fn framed_data(
    bytes: &[u8],
    at: usize,
    s: &Stream,
    spec: &HashMap<u32, Entry>,
    doc: Option<&Document>,
    decrypted: bool,
) -> Option<Range<usize>> {
    let theirs = stream_data(bytes, at, spec, doc);
    if decrypted {
        return theirs.filter(|r| {
            let rest = &bytes[r.end..];
            let rest = (rest.strip_prefix(b"\r\n"))
                .or_else(|| rest.strip_prefix(b"\n"))
                .or_else(|| rest.strip_prefix(b"\r"))
                .unwrap_or(rest);
            rest.starts_with(b"endstream")
        });
    }
    let (dict, start) = stream_head(bytes, at)?;
    let end = start.checked_add(s.content.len())?;
    if bytes.get(start..end)? != s.content {
        return None;
    }
    let white = |r: Range<usize>| bytes[r].iter().all(|&c| is_white(c));
    if let Some(r) = theirs {
        return white(r.end.min(end)..r.end.max(end)).then_some(start..end);
    }
    let from = match dict.get(b"Length") {
        Ok(Object::Integer(_) | Object::Reference(_)) => {
            let len = stream_length(bytes, &dict, spec, doc)?;
            start.checked_add(usize::try_from(len).ok()?)?
        }
        _ => start,
    };
    let found = end + bytes[end..].iter().take_while(|&&c| is_white(c)).count();
    let ended = Lexer::new(bytes, found).next();
    // A comment in the data ends before `endstream`, and so does Poppler's first token, a
    // string perhaps; when there is none, Poppler takes the data as long as its `/Length`.
    let mut first = Lexer::new(&bytes[..found], from);
    let ok = matches!(ended, Some((_, Tok::Word(b"endstream"), _)))
        && bytes[end..found].iter().any(|c| matches!(c, b'\n' | b'\r'))
        && from <= found
        && !(bytes[start..end].windows(8)).any(|w| w == b"endstrea" || w == b"endsteam")
        && (first.next().is_some() || white(from.min(end)..end));
    ok.then_some(start..end)
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
    /// The objects streams take their `/Length` from. lopdf writes the length it read in
    /// their place, so its reading no longer uses them, while other apps' does.
    pub(crate) lengths: HashSet<ObjectId>,
    /// The entry each object number has for other apps.
    spec: HashMap<u32, Entry>,
    /// Whether the newest cross-reference section is a table (a hybrid one too).
    table: bool,
}

impl Reading {
    /// Whether other apps find object `id`, which lopdf doesn't hold, in an object stream:
    /// they take an object from one whatever generation a reference to it gives, lopdf only
    /// under generation 0.
    pub(crate) fn others_find(&self, id: ObjectId) -> bool {
        matches!(self.spec.get(&id.0), Some(Entry::Compressed { container, .. })
            if matches!(self.spec.get(container), Some(Entry::InUse { .. })))
    }

    /// Whether other apps read the whole file again when they follow a reference to object
    /// `id`, which lopdf doesn't hold, so may then read any object otherwise. pdf.js does when
    /// the object's entry gives another generation. Poppler does when it can't read the object
    /// and the newest section is a table: it scans the file for objects and reads every object
    /// from what it found from then on.
    pub(crate) fn read_again(&self, id: ObjectId) -> bool {
        match self.spec.get(&id.0) {
            Some(Entry::InUse { .. }) => true,
            _ => self.table,
        }
    }
}

/// Compares lopdf's reading `doc` of `bytes` (the bytes it read) with the
/// specification's. Fails when the cross-reference information can't be read as written,
/// so the specification's reading isn't known.
pub(crate) fn compare_reading(bytes: &[u8], doc: &Document) -> Result<Reading, String> {
    // lopdf reads from the header on, and its offsets count from there.
    let start = bytes.windows(5).position(|w| w == b"%PDF-").unwrap_or(0);
    let bytes = &bytes[start..];
    let pointer = last_startxref(bytes);
    let WholeXref {
        spec,
        deleted,
        trailer,
        table: newest_table,
    } = whole_xref(bytes, pointer.unwrap_or(doc.xref_start))?;
    // lopdf must take the newest trailer too: its catalog, and its encryption dictionary,
    // which lopdf drops from the trailer once it has decrypted the file with it.
    let encrypt = (doc.trailer.get(b"Encrypt").ok().cloned()).or_else(|| {
        let id = doc.encryption_state.as_ref()?.encrypt_object_id()?;
        Some(Object::Reference(id))
    });
    if trailer.get(b"Root").ok() != doc.trailer.get(b"Root").ok()
        || trailer.get(b"Encrypt").ok() != encrypt.as_ref()
    {
        return Err(
            "they take its catalog or encryption from another cross-reference section".into(),
        );
    }
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
    // Other apps read the object as LimarePDF does when it is one whole object, followed by
    // `endobj` or a stream's data, as long as its `/Length` as lopdf took it, and, in an
    // encrypted file, lopdf doesn't cut it short.
    let endobjs: Option<Vec<usize>> = encrypt.is_some().then(|| {
        (bytes.windows(6).enumerate())
            .filter(|(_, w)| *w == b"endobj")
            .map(|(i, _)| i)
            .collect()
    });
    let mut lengths = HashSet::new();
    for (&num, e) in table {
        if let XrefEntry::Normal { offset, generation } = *e {
            let id = (num, generation);
            match header(bytes, offset as usize) {
                Some((found, lx)) if found == id => {
                    let at = offset as usize;
                    let held = doc.objects.get(&id);
                    if held.is_some()
                        && (!whole_object(lx.clone(), encrypt.is_some(), &mut lengths)
                            || endobjs.as_deref().is_some_and(|endobjs| {
                                cut_short(bytes, at, lx, &spec, doc, endobjs)
                            })
                            || held.is_some_and(|o| match o {
                                Object::Stream(s) => {
                                    let decrypted = encrypt.is_some();
                                    framed_data(bytes, at, s, &spec, Some(doc), decrypted).is_none()
                                }
                                _ => false,
                            }))
                    {
                        unsure.insert(num);
                    }
                }
                found => {
                    unsure.insert(num);
                    if let Some(((other, _), _)) = found {
                        unsure.insert(other);
                    }
                }
            }
        }
    }

    // Object streams: each holds the objects its index lists, and a reader takes an object
    // from the stream at the place its entry gives. lopdf takes any object a stream holds
    // that has no entry of its own, and one whose own object it couldn't read. lopdf,
    // Poppler and pdf.js open any stream an entry names as an object stream, typed or not.
    let mut copies: Vec<(u32, ObjectId)> = Vec::new();
    let mut listed_in: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&n, e) in &spec {
        if let Entry::Compressed { container, .. } = e {
            listed_in.entry(*container).or_default().push(n);
        }
    }
    for (&(c, g), o) in &doc.objects {
        let Object::Stream(s) = o else { continue };
        let typed = s.dict.has_type(b"ObjStm");
        if !typed && !listed_in.contains_key(&c) {
            continue;
        }
        // lopdf must have read the data other apps read.
        let framed = match spec.get(&c) {
            Some(&Entry::InUse { offset, gen }) if gen == g => {
                framed_data(bytes, offset, s, &spec, None, encrypt.is_some())
            }
            _ => None,
        };
        // pdf.js reads the last object on past the content: into the file after plain data,
        // and into the zeros filling its buffer after data it decrypts or decodes.
        let plain = encrypt.is_none() && matches!(s.dict.get(b"Filter"), Err(_) | Ok(Object::Null));
        let after = match &framed {
            _ if !plain => Some(&[0][..]),
            Some(r) => Some(&bytes[r.end..]),
            None => None,
        };
        let Some((members, alike)) = objstm_members(s, after) else {
            if typed {
                return Err(format!("its object stream {c} can't be read"));
            }
            unsure.insert(c);
            continue;
        };
        // Other apps may read none of the objects listed in it (see below), when they may
        // read it, decode it or find its objects differently. lopdf's stray copies of others
        // are checked below.
        if framed.is_none() || !alike || !decodes_alike(s, MAX_OBJECT_STREAM) {
            unsure.insert(c);
        }
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
                // pdf.js takes the object from the stream, and keeps it, when the stream's
                // number is the offset the object's own entry gives.
                Some(Entry::InUse { offset, .. }) if *offset == c as usize => {
                    unsure.insert(n);
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

    // pdf.js reads the encryption dictionary, and the objects it names, before it can decrypt:
    // as written, where lopdf decrypts their strings and data, and when one is in an object
    // stream, every object in that stream.
    let encrypt_num = match trailer.get(b"Encrypt") {
        Ok(Object::Reference(id)) => Some(id.0),
        _ => None,
    };
    let mut named_first: Vec<Object> = trailer.get(b"Encrypt").ok().cloned().into_iter().collect();
    let mut looked = HashSet::new();
    while let Some(o) = named_first.pop() {
        match o {
            Object::Reference(id) if looked.insert(id) => match spec.get(&id.0) {
                Some(&Entry::InUse { offset, gen }) if gen == id.1 => {
                    let read = header(bytes, offset)
                        .filter(|(found, _)| *found == id)
                        .and_then(|(_, mut lx)| {
                            let o = read_object(&mut lx, 0)?;
                            let stream = lx.next_word();
                            Some((o, matches!(stream, Some((_, Tok::Word(b"stream"), _)))))
                        });
                    match read {
                        Some((o, stream)) => {
                            if Some(id.0) != encrypt_num && (stream || holds_string(&o)) {
                                unsure.insert(id.0);
                            }
                            named_first.push(o);
                        }
                        None => {
                            unsure.insert(id.0);
                        }
                    }
                }
                Some(&Entry::Compressed { container, .. }) => {
                    unsure.extend([container, id.0]);
                }
                _ => {}
            },
            Object::Array(a) => named_first.extend(a),
            Object::Dictionary(d) => named_first.extend(d.into_iter().map(|(_, o)| o)),
            _ => {}
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
    // Objects a reader finds that lopdf doesn't hold. lopdf no longer holds the encryption
    // dictionary (see `references`).
    for (&n, &e) in &spec {
        let id = match e {
            _ if Some(n) == encrypt_num => continue,
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
    // Other apps may read none of the objects an object stream holds as lopdf does when they
    // may read the stream otherwise.
    let streams: Vec<u32> = (listed_in.keys())
        .filter(|c| unsure.contains(c))
        .copied()
        .collect();
    for c in streams {
        unsure.extend(&listed_in[&c]);
    }
    // lopdf must have found the encryption dictionary where other apps do.
    if encrypt_num.is_some_and(|n| unsure.contains(&n)) {
        return Err("they may decrypt it with another encryption dictionary".into());
    }
    Ok(Reading {
        hidden,
        unsure,
        ends_cleanly: pointer.is_some(),
        lengths,
        spec,
        table: newest_table,
    })
}

/// Whether `o` holds a string, at any depth.
fn holds_string(o: &Object) -> bool {
    match o {
        Object::String(..) => true,
        Object::Array(a) => a.iter().any(holds_string),
        Object::Dictionary(d) => d.iter().any(|(_, v)| holds_string(v)),
        _ => false,
    }
}

/// Whether one whole object follows `lx`, then `endobj` or a stream's data, as lopdf, Poppler
/// and pdf.js all read it. A number may be glued to `endobj`: they end it at the `e`. A
/// dictionary, array, string or name, which ends itself, may instead be followed by the next
/// object's header, `xref`, `trailer`, `startxref` or the end of the file, where they all stop
/// without `endobj`; not a number or a keyword, which lopdf may read on into a reference.
/// A dictionary followed by `stream` counts only with a line end after the keyword (spaces
/// and tabs aside): without one lopdf reads the dictionary alone, where Poppler and pdf.js
/// read a stream. `decrypted` as for [`skip_object`]. Adds the object a stream takes its
/// `/Length` from to `lengths`.
fn whole_object(mut lx: Lexer, decrypted: bool, lengths: &mut HashSet<ObjectId>) -> bool {
    let mut dict = lx.clone();
    let first = lx.clone().next();
    if let Some((_, Tok::Word(w), _)) = first {
        if let Some(n) = w.strip_suffix(b"endobj") {
            return number(n).is_some();
        }
    }
    if !skip_object(&mut lx, decrypted) {
        return false;
    }
    let ends_itself = first.is_some_and(|(_, t, _)| {
        matches!(
            t,
            Tok::DictOpen | Tok::ArrayOpen | Tok::Name(_) | Tok::Hex | Tok::Literal
        )
    });
    let next = lx.next_word();
    match next {
        Some((_, Tok::Word(b"endobj"), _)) => true,
        Some((_, Tok::Word(b"stream"), keyword)) => {
            if let Some(Object::Dictionary(d)) = read_object(&mut dict, 0) {
                if let Ok(Object::Reference(id)) = d.get(b"Length") {
                    lengths.insert(*id);
                }
            }
            !matches!(first, Some((_, Tok::DictOpen, _)))
                || data_start(lx.bytes(), keyword).is_some()
        }
        _ if !ends_itself => false,
        Some((_, Tok::Word(b"xref" | b"trailer" | b"startxref"), _)) => true,
        None => lx.at_end(),
        _ => {
            word_num::<u32>(next).is_some()
                && word_num::<u16>(lx.next_word()).is_some()
                && matches!(lx.next_word(), Some((_, Tok::Word(b"obj"), _)))
        }
    }
}

/// Whether lopdf, reading an encrypted file, may cut short the object `lx` starts, just past
/// its header at `at`. There it first cuts each object at the first `endobj` after its header,
/// in a string, a comment or a stream's data too (`endobjs` lists where each starts), and
/// reads only what it cut, where other apps read on: past a comment into a reference or a
/// stream, or a stream's data as long as its `/Length`, which lopdf then takes shorter.
fn cut_short(
    bytes: &[u8],
    at: usize,
    mut lx: Lexer,
    spec: &HashMap<u32, Entry>,
    doc: &Document,
    endobjs: &[usize],
) -> bool {
    let from = lx.pos();
    let Some(&cut) = endobjs.get(endobjs.partition_point(|&e| e < from)) else {
        return true;
    };
    let first = lx.clone().next();
    let end = match first {
        Some((_, Tok::Word(w), end)) if w.ends_with(b"endobj") => end,
        _ if !skip_object(&mut lx, true) => return true,
        _ => match lx.clone().next_word() {
            Some((_, Tok::Word(b"stream"), _)) if matches!(first, Some((_, Tok::DictOpen, _))) => {
                let Some(data) = stream_data(bytes, at, spec, Some(doc)) else {
                    return true;
                };
                let mut tail = Lexer::new(bytes, data.end);
                tail.next_word();
                tail.pos()
            }
            _ => lx.pos(),
        },
    };
    // What lopdf cuts keeps the `endobj` it cuts at, and so the whole object where that ends
    // it, glued to a number or a name.
    cut + 6 < end
}

/// The cross-reference information a reader following the specification takes.
struct WholeXref {
    /// The entry each object number has.
    spec: HashMap<u32, Entry>,
    /// For each number the entry frees, the object a revision deleted.
    deleted: HashMap<u32, Entry>,
    /// The newest section's trailer.
    trailer: Dictionary,
    /// Whether the newest section is a table (a hybrid one too).
    table: bool,
}

/// The cross-reference entry each object number has for a reader following the
/// specification: every section from the one at `at` along the `/Prev` chain (a hybrid
/// section's stream ranking after its table), the newest entry counting, free ones too.
/// Also, for each number that entry frees, the newest older entry placing an object: the
/// object a revision deleted.
fn whole_xref(bytes: &[u8], mut at: usize) -> Result<WholeXref, String> {
    let mut spec = HashMap::new();
    let mut deleted = HashMap::new();
    let mut trailer = Dictionary::new();
    let mut table = false;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(at) || seen.len() > MAX_SECTIONS {
            return Err("its chain of revisions loops or is too long".into());
        }
        let read = read_section(bytes, at)?;
        decoded_alike(&read, at)?;
        if seen.len() == 1 {
            newest_has_room(&read, at)?;
            trailer = read.trailer;
            table = read.kind == SectionKind::Table;
        }
        let mut entries = read.entries;
        if let Some(stm) = read.xref_stm {
            let extra = read_section(bytes, stm)?;
            if extra.kind != SectionKind::Stream {
                return Err("a hybrid revision's stream isn't a cross-reference stream".into());
            }
            decoded_alike(&extra, stm)?;
            entries.extend(extra.entries);
        }
        for (num, e) in entries {
            if *spec.entry(num).or_insert(e) == Entry::Free && e != Entry::Free {
                deleted.entry(num).or_insert(e);
            }
        }
        match read.prev {
            Some(p) => at = p,
            None => {
                return Ok(WholeXref {
                    spec,
                    deleted,
                    trailer,
                    table,
                })
            }
        }
    }
}

/// The object numbers an object stream holds, in order, when its index reads cleanly:
/// `/N` pairs of whole numbers before `/First`. lopdf reads every pair it finds, whatever
/// `/N` says, and other readers stop at `/N`. Also whether other readers find its objects
/// where lopdf does ([`laid_out_alike`]), given what pdf.js reads `after` the content; not
/// when that isn't known, nor when the index holds other white space than PDF's, which
/// lopdf takes between numbers too, or runs into the data, or Poppler can't take it.
fn objstm_members(s: &Stream, after: Option<&[u8]>) -> Option<(Vec<u32>, bool)> {
    let mut content = s.get_plain_content_with_limit(MAX_OBJECT_STREAM).ok()?;
    if content.is_empty() {
        return Some((Vec::new(), true));
    }
    let int = |key: &[u8]| usize::try_from(s.dict.get(key).ok()?.as_i64().ok()?).ok();
    let (first, n) = (int(b"First")?, int(b"N")?);
    let index = content.get(..first)?;
    let plain_index = index
        .iter()
        .all(|&c| c.is_ascii_digit() || c == b'+' || is_white(c));
    let words: Vec<&str> = std::str::from_utf8(index)
        .ok()?
        .split_whitespace()
        .collect();
    if words.len() != n.checked_mul(2)? {
        return None;
    }
    let (members, offsets): (Vec<u32>, Vec<usize>) = words
        .chunks(2)
        .map(|p| {
            Some((
                p[0].parse::<u32>().ok()?,
                p[1].parse::<u32>().ok()? as usize,
            ))
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .unzip();
    // Poppler drops the whole stream past a million objects or a number past its `int`, and
    // pdf.js reads the last offset on into the data when nothing parts them.
    let parted = index.last().is_none_or(|&c| is_white(c))
        || !matches!(content.get(first), Some(b'0'..=b'9' | b'.' | b'-'));
    let len = content.len();
    let alike = plain_index
        && parted
        && n <= 1_000_000
        && members.iter().all(|&m| i32::try_from(m).is_ok())
        && after.is_some_and(|after| {
            // pdf.js ends a number glued to what follows where the content ends, as the
            // others do, and reads a name or a keyword on into it.
            let regular = |c: u8| !is_white(c) && !is_delim(c);
            let word = content
                .iter()
                .rposition(|&c| !regular(c))
                .map_or(0, |k| k + 1);
            let glued = content.get(word.wrapping_sub(1)) != Some(&b'/')
                && number(&content[word..]).is_some();
            content.extend((after.first()).map(|&c| if glued && regular(c) { b' ' } else { c }));
            laid_out_alike(&content, len, first, &offsets)
        });
    Some((members, alike))
}

/// Whether other readers find an object stream's objects where lopdf does, its `len` bytes
/// of content in `read` followed by the byte pdf.js reads after them, if any. lopdf reads
/// one object at `/First` plus each offset, and pdf.js too, but only up to the next offset,
/// on past the content for the last, and taking a `stream` after a dictionary as its data.
/// Poppler reads each in a window as long as from its offset to the next one, but starts
/// the first window at `/First` unless the first offset is past `/First`, so all its windows
/// sit that much earlier. pdf.js also lexes on from `/First` past the index. They agree when
/// the offsets increase, each object starts on the same token from all these places and
/// ends in Poppler's window, only whole objects, `endobj` and signs pdf.js reads as 0 follow
/// it before the next offset, and the content doesn't end in a comment that runs on into
/// what pdf.js reads after it.
fn laid_out_alike(read: &[u8], len: usize, first: usize, offsets: &[usize]) -> bool {
    let start = |at| Lexer::new(read, at).next().map(|(s, _, _)| s);
    let shift = offsets.first().map_or(0, |&o| o.min(first));
    for (i, &offset) in offsets.iter().enumerate() {
        let end = match offsets.get(i + 1) {
            Some(&next) if next > offset => first.checked_add(next),
            Some(_) => return false,
            None => Some(len),
        };
        let (Some(at), Some(end)) = (first.checked_add(offset), end) else {
            return false;
        };
        // Poppler's last window runs to the end.
        let window = if i + 1 < offsets.len() {
            end - shift
        } else {
            end
        };
        let mut lx = Lexer::new(read, at);
        if start(at - shift) != start(at)
            || (i == 0 && start(first) != start(at))
            || !skip_object(&mut lx, false)
            || lx.pos() > window
        {
            return false;
        }
        // Every reader ignores what follows when it is whole objects, `endobj` or signs pdf.js
        // reads as 0: pdf.js fails on some other tokens, and takes `stream` as the data's.
        // pdf.js and Poppler stop at the next offset, but lopdf reads on past an object to look
        // for `N G R`, so the next object must start where reading on finds it. A comment
        // hiding that start is refused, though the readers agree on what it hides so far.
        loop {
            let mut look = lx.clone();
            match look.next() {
                Some((s, _, _)) if s >= end => {
                    if i + 1 < offsets.len() && start(end) != Some(s) {
                        return false;
                    }
                    break;
                }
                Some((_, Tok::Word(b"endobj"), _)) => lx = look,
                Some((_, Tok::Word(w), e)) if pdfjs_reads_zero(read, w, e) => lx = look,
                Some(_) => {
                    if !skip_object(&mut lx, false) {
                        return false;
                    }
                }
                None if look.pos() < end || i + 1 < offsets.len() => return false,
                None => break,
            }
            if lx.pos() > end {
                return false;
            }
        }
        // A comment ending the content runs on into what follows, past a line end in the
        // file. After decoded data pdf.js reads zeros there, which is fine, but that byte
        // can't tell the two apart.
        let tail = &read[lx.pos().min(len)..len];
        let eol = |c: &u8| matches!(c, b'\r' | b'\n');
        if i + 1 == offsets.len()
            && !read.get(len).is_none_or(eol)
            && tail.iter().rposition(|&c| c == b'%') > tail.iter().rposition(eol)
        {
            return false;
        }
    }
    true
}

/// Whether pdf.js lexes `word`, ending at `end` in `read`, as a number without digits, which
/// it takes as 0 rather than failing: `-`, `--` or `+`, then `.`, each optional, before a
/// space, a tab, a line end, `(`, `<` or the end, but not a zero byte. After a sign it reads
/// on past line ends, so those count only after the point.
fn pdfjs_reads_zero(read: &[u8], word: &[u8], end: usize) -> bool {
    let unsigned = [&b"--"[..], b"-", b"+"]
        .iter()
        .find_map(|sign| word.strip_prefix(*sign))
        .unwrap_or(word);
    matches!(unsigned, b"" | b".")
        && match read.get(end) {
            None | Some(b' ' | b'\t' | b'(' | b'<') => true,
            Some(b'\r' | b'\n') => unsigned == b".",
            Some(_) => false,
        }
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

/// How much of what other apps draw [`reached`] reads.
struct Within {
    /// The steps it may take: one for each byte of a drawing's data and each byte its
    /// filters give.
    steps: u64,
    /// The bytes of one drawing's data, its streams read as one.
    data: usize,
    /// The references it keeps from them, counted once for each drawing they are written in.
    refs: usize,
}

/// How much of what other apps draw [`reached`] reads: a drawing as much as a page's content
/// is read elsewhere, and references enough for any file (other apps' drawings write none,
/// but in an inline image's data that happens to read as one). Past it, the rest is unread.
const DRAWN: Within = Within {
    steps: 1 << 30,
    data: crate::MAX_CONTENT,
    refs: 1 << 16,
};

/// What other apps may follow in a document ([`reached`]).
#[derive(Default)]
pub(crate) struct Reached {
    /// The objects they may read.
    pub(crate) ids: HashSet<ObjectId>,
    /// The references Poppler reads in the data of what they draw ([`data_references`]),
    /// all taken as followed: it follows those in a dictionary there (an inline image's
    /// settings, marked content's).
    pub(crate) drawn: HashSet<ObjectId>,
    /// Those references by the drawing they are read in, under its first stream.
    pub(crate) drawings: Drawings,
    /// What they draw that LimarePDF can't decode, or past what [`DRAWN`] reads: what its
    /// data refers to isn't known.
    pub(crate) unread: BTreeSet<ObjectId>,
    /// The references kept from the drawings, as [`Within::refs`] counts them.
    kept: usize,
}

/// References read in the data of what is drawn, by drawing ([`Reached::drawings`]).
pub(crate) type Drawings = HashMap<ObjectId, Vec<ObjectId>>;

/// The references other apps may follow in `doc`: from its trailer's catalog and document
/// information, on through every object they lead to, and on from the data of what they
/// draw. They read no other key of the trailer.
pub(crate) fn reached(doc: &Document) -> Reached {
    reached_within(doc, &DRAWN)
}

/// [`reached`], reading what is drawn as far as `within` allows.
fn reached_within(doc: &Document, within: &Within) -> Reached {
    let mut work = budget::Work::unkept("reading the drawings", within.steps);
    let mut out = Reached::default();
    let mut read: HashSet<Vec<ObjectId>> = HashSet::new();
    let mut ids: Vec<ObjectId> = Vec::new();
    let mut stack: Vec<&Object> = [&b"Root"[..], b"Info"]
        .into_iter()
        .filter_map(|k| doc.trailer.get(k).ok())
        .collect();
    loop {
        if let Some(id) = ids.pop() {
            if out.ids.insert(id) {
                if let Some(o) = doc.objects.get(&id) {
                    if matches!(o, Object::Stream(s) if drawn_alone(doc, s)) {
                        let drawing = vec![id];
                        draw(
                            doc, drawing, within, &mut work, &mut read, &mut out, &mut ids,
                        );
                    }
                    stack.push(o);
                }
            }
            continue;
        }
        let Some(o) = stack.pop() else { break };
        let d = match o {
            Object::Reference(id) => {
                ids.push(*id);
                continue;
            }
            Object::Array(a) => {
                stack.extend(a);
                continue;
            }
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            _ => continue,
        };
        for drawing in drawn_in(doc, d) {
            draw(
                doc, drawing, within, &mut work, &mut read, &mut out, &mut ids,
            );
        }
        stack.extend(d.iter().map(|(_, o)| o));
    }
    out
}

/// Whether other apps draw stream `s` wherever it is: a form, or a tiling pattern.
fn drawn_alone(doc: &Document, s: &Stream) -> bool {
    let value = |k: &[u8]| {
        s.dict
            .get(k)
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .map(|o| o.1)
    };
    value(b"Subtype").is_some_and(|o| o.as_name().is_ok_and(|n| n == b"Form"))
        || value(b"PatternType").is_some_and(|o| matches!(o, Object::Integer(1)))
}

/// What other apps draw that dictionary `d` names, each drawing as the streams it is
/// written in: a page's content (in several streams read as one), an annotation's
/// appearances, a Type 3 font's glyphs, a soft mask's group.
fn drawn_in(doc: &Document, d: &Dictionary) -> Vec<Vec<ObjectId>> {
    let stream = |o: &Object| match doc.dereference(o) {
        Ok((Some(id), Object::Stream(_))) => Some(id),
        _ => None,
    };
    fn dict<'a>(doc: &'a Document, o: &'a Object) -> Option<&'a Dictionary> {
        doc.dereference(o).ok().and_then(|(_, o)| o.as_dict().ok())
    }
    let dict = |o| dict(doc, o);
    let alone = |o: &Object| stream(o).map(|id| vec![id]);
    let mut out = Vec::new();
    if let Ok(c) = d.get(b"Contents") {
        match doc.dereference(c) {
            Ok((_, Object::Array(a))) => out.push(a.iter().filter_map(stream).collect()),
            _ => out.extend(alone(c)),
        }
    }
    if let Some(ap) = d.get(b"AP").ok().and_then(dict) {
        for (_, o) in ap.iter() {
            match dict(o) {
                Some(states) => out.extend(states.iter().filter_map(|(_, o)| alone(o))),
                None => out.extend(alone(o)),
            }
        }
    }
    if let Some(glyphs) = d.get(b"CharProcs").ok().and_then(dict) {
        out.extend(glyphs.iter().filter_map(|(_, o)| alone(o)));
    }
    out.extend(d.get(b"G").ok().and_then(alone));
    out
}

/// Reads `drawing` (once) as far as `within` allows, and has its data's references followed.
fn draw(
    doc: &Document,
    drawing: Vec<ObjectId>,
    within: &Within,
    work: &mut budget::Work,
    read: &mut HashSet<Vec<ObjectId>>,
    out: &mut Reached,
    ids: &mut Vec<ObjectId>,
) {
    if read.contains(&drawing) {
        return;
    }
    let (mut data, mut breaks) = (Vec::new(), Vec::new());
    for id in &drawing {
        let Some(Object::Stream(s)) = doc.objects.get(id) else {
            continue;
        };
        let decoded = match as_poppler_decodes(doc, s) {
            Some(s) => work.decode(&s),
            None => Ok(None),
        };
        match decoded {
            Ok(Some(d)) if data.len() + d.len() <= within.data => {
                breaks.push(data.len());
                data.extend(d);
            }
            _ => {
                out.unread.insert(*id);
            }
        }
    }
    let mut found = BTreeSet::new();
    if data_references(&data, &breaks, &mut found, within.refs - out.kept) {
        out.kept += found.len();
        ids.extend(&found);
        if let Some(first) = drawing.first().filter(|_| !found.is_empty()) {
            out.drawings.entry(*first).or_default().extend(&found);
        }
        out.drawn.extend(found);
    } else {
        out.unread.extend(&drawing);
    }
    read.insert(drawing);
}

/// Stream `s` with its filters as Poppler reads them, for lopdf to decode: each through a
/// reference (the filter, the list, each filter in it, their settings and each setting), from
/// `/F` and `/DP` where `/Filter` and `/DecodeParms` are missing, by their short names too, with
/// settings for several filters only from a list. A list with something other than a name in it
/// leaves no data. `None` when `/Filter` and `/F`, or `/DecodeParms` and `/DP`, are both written
/// and differ: pdf.js and hayro read the other one.
fn as_poppler_decodes<'a>(doc: &'a Document, s: &'a Stream) -> Option<Cow<'a, Stream>> {
    const NULL: Object = Object::Null;
    let one = |o: &'a Object| -> &'a Object {
        match o {
            Object::Reference(id) => doc.objects.get(id).unwrap_or(&NULL),
            o => o,
        }
    };
    let get = |k: &[u8]| s.dict.get(k).map_or(&NULL, one);
    let differ = |a: &[u8], b: &[u8]| s.dict.has(a) && s.dict.has(b) && get(a) != get(b);
    if differ(b"Filter", b"F") || differ(b"DecodeParms", b"DP") {
        return None;
    }
    let or = |a: &[u8], b: &[u8]| match get(a) {
        Object::Null => get(b),
        o => o,
    };
    let settings = |o: &'a Object| match o {
        Object::Dictionary(d) => {
            Object::Dictionary(d.iter().map(|(k, v)| (k.clone(), one(v).clone())).collect())
        }
        _ => NULL,
    };
    let name = |n: &[u8]| Object::Name(filter_name(n).to_vec());
    let parms = or(b"DecodeParms", b"DP");
    let (filter, parms) = match or(b"Filter", b"F") {
        Object::Name(n) => (name(n), settings(parms)),
        Object::Array(a) => {
            let mut names = Vec::new();
            for o in a {
                let Object::Name(n) = one(o) else {
                    return Some(Cow::Owned(Stream::new(Dictionary::new(), Vec::new())));
                };
                names.push(name(n));
            }
            let each: Vec<Object> = match parms {
                Object::Array(p) => (0..names.len())
                    .map(|i| p.get(i).map_or(NULL, |o| settings(one(o))))
                    .collect(),
                _ => Vec::new(),
            };
            match (names.is_empty(), each.iter().all(|o| *o == NULL)) {
                // lopdf gives nothing for an empty list, Poppler the data.
                (true, _) => (NULL, NULL),
                (false, true) => (Object::Array(names), NULL),
                (false, false) => (Object::Array(names), Object::Array(each)),
            }
        }
        _ => return Some(Cow::Borrowed(s)),
    };
    let raw = |k: &[u8]| s.dict.get(k).unwrap_or(&NULL);
    if *raw(b"Filter") == filter && *raw(b"DecodeParms") == parms {
        return Some(Cow::Borrowed(s));
    }
    let mut d = Dictionary::new();
    d.set("Filter", filter);
    d.set("DecodeParms", parms);
    Some(Cow::Owned(Stream::new(d, s.content.clone())))
}

/// The full name of a filter Poppler reads by its short name too (`/Fl`).
fn filter_name(n: &[u8]) -> &[u8] {
    match n {
        b"AHx" => b"ASCIIHexDecode",
        b"A85" => b"ASCII85Decode",
        b"LZW" => b"LZWDecode",
        b"RL" => b"RunLengthDecode",
        b"CCF" => b"CCITTFaxDecode",
        b"DCT" => b"DCTDecode",
        b"Fl" => b"FlateDecode",
        n => n,
    }
}

/// The references Poppler may read in drawn data `data`, written in parts that start at
/// `breaks` (a page's content in several streams): `N G R`, three tokens as its lexer reads
/// them, the numbers whole numbers within 32 bits, `N` positive and `G` not negative. A sign
/// starts a number even right after another (`5+0R` is a reference), a comment separates
/// like white space, and a number, name or word ends at the end of a part (a word after 128
/// characters too), while white space, comments and strings run on into the next. From the
/// first inline image on (`BI`, or `ID`, after which Poppler skips a character), where
/// Poppler reads on is found as it decodes the image, so there every place a number may
/// start is tried, in strings, names and image data too. Each byte is read a few times at
/// most. False, leaving off, when there are more than `most` of them.
fn data_references(
    data: &[u8],
    breaks: &[usize],
    out: &mut BTreeSet<ObjectId>,
    most: usize,
) -> bool {
    let len = data.len();
    // Whether byte `i` runs on from the one before it in a number or word.
    let joined = |i: usize| i > 0 && breaks.binary_search(&i).is_err();
    let Some(from) = read_tokens(data, &joined, out, most) else {
        return false;
    };
    let digit = |i: usize| i < len && data[i].is_ascii_digit();
    let signed = |i: usize| i < len && matches!(data[i], b'+' | b'-');
    // The whole number starting at `i`, `None` past 32 bits, and where it ends; `None` for
    // a real.
    let whole = |mut i: usize| -> Option<(Option<i64>, usize)> {
        let neg = data[i] == b'-';
        let mut v = Some(0);
        if !signed(i) {
            v = Some(i64::from(data[i] - b'0'));
        }
        i += 1;
        while digit(i) && joined(i) {
            let more = |v: i64| v * 10 + i64::from(data[i] - b'0');
            v = v.map(more).filter(|v| *v <= i64::from(i32::MAX));
            i += 1;
        }
        // (A point starting the next part can't be read as `G` or `R` either.)
        if i < len && data[i] == b'.' {
            return None;
        }
        Some((v.map(|v| if neg { -v } else { v }), i))
    };
    let apart = |mut i: usize| {
        while i < len {
            match data[i] {
                b'%' => {
                    while i < len && !matches!(data[i], b'\r' | b'\n') {
                        i += 1;
                    }
                }
                b if is_white(b) => i += 1,
                _ => break,
            }
        }
        i
    };
    for start in from..len {
        let starts = signed(start)
            || (digit(start)
                && !(joined(start) && matches!(data[start - 1], b'0'..=b'9' | b'.' | b'+' | b'-')));
        if !starts {
            continue;
        }
        let Some((num, at)) = whole(start) else {
            continue;
        };
        let at = apart(at);
        if !(digit(at) || signed(at)) {
            continue;
        }
        let Some((gen, at)) = whole(at) else { continue };
        let at = apart(at);
        let ends = |i: usize| i == len || !joined(i) || is_white(data[i]) || is_delim(data[i]);
        if at < len && data[at] == b'R' && ends(at + 1) && !add_reference(out, num, gen, most) {
            return false;
        }
    }
    true
}

/// Reads drawn data `data` token by token as Poppler's lexer does (where `joined` says a
/// byte runs on from the one before it in a part), adding the references it reads to `out`.
/// Where the first inline image starts, or the end; `None`, leaving off, when `out` holds more
/// than `most`.
fn read_tokens(
    data: &[u8],
    joined: &dyn Fn(usize) -> bool,
    out: &mut BTreeSet<ObjectId>,
    most: usize,
) -> Option<usize> {
    let len = data.len();
    // Whether byte `i` is read in the token before it, if it may be: Poppler's lexer looks no
    // further than the end of a part.
    let on = |i: usize| i < len && joined(i);
    let special = |b: u8| is_white(b) || is_delim(b);
    // The last two tokens, each its value if it is a whole number within 32 bits.
    let mut last: [Option<i64>; 2] = [None, None];
    let mut i = 0;
    loop {
        while i < len && (is_white(data[i]) || data[i] == b'%') {
            if data[i] == b'%' {
                while i < len && !matches!(data[i], b'\r' | b'\n') {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        if i == len {
            return Some(len);
        }
        let start = i;
        let mut whole = None;
        i += 1;
        match data[start] {
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let mut v = Some(0);
                if data[start].is_ascii_digit() {
                    v = Some(i64::from(data[start] - b'0'));
                }
                let mut real = data[start] == b'.';
                while !real && on(i) && data[i].is_ascii_digit() {
                    let more = |v: i64| v * 10 + i64::from(data[i] - b'0');
                    v = v.map(more).filter(|v| *v <= i64::from(i32::MAX));
                    i += 1;
                }
                if !real && on(i) && data[i] == b'.' {
                    real = true;
                    i += 1;
                }
                // A real runs on through digits and minus signs.
                while real && on(i) && (data[i].is_ascii_digit() || data[i] == b'-') {
                    i += 1;
                }
                let neg = data[start] == b'-';
                whole = v.filter(|_| !real).map(|v| if neg { -v } else { v });
            }
            b'(' => {
                let mut depth = 1;
                while i < len {
                    match data[i] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        b'\\' => i += 1,
                        _ => {}
                    }
                    i += 1;
                    if depth == 0 {
                        break;
                    }
                }
                i = i.min(len);
            }
            b'<' | b'>' if on(i) && data[i] == data[start] => i += 1,
            b'<' => {
                while i < len && data[i] != b'>' {
                    i += 1;
                }
                i = len.min(i + 1);
            }
            b'/' => {
                while on(i) && !special(data[i]) {
                    // An escape's first digit is looked at, the character after it taken.
                    if data[i] == b'#' && on(i + 1) && data[i + 1].is_ascii_hexdigit() {
                        i += 2;
                    }
                    i = len.min(i + 1);
                }
            }
            b if special(b) => {}
            _ => {
                while on(i) && !special(data[i]) && i - start < 128 {
                    i += 1;
                }
                match &data[start..i] {
                    b"R" => {
                        if !add_reference(out, last[0], last[1], most) {
                            return None;
                        }
                    }
                    b"BI" | b"ID" => return Some(start),
                    _ => {}
                }
            }
        }
        last = [last[1], whole];
    }
}

/// Adds reference `num gen R` to `out` if Poppler reads one there; false when `out` then
/// holds more than `most`.
fn add_reference(
    out: &mut BTreeSet<ObjectId>,
    num: Option<i64>,
    gen: Option<i64>,
    most: usize,
) -> bool {
    if let (Some(n @ 1..), Some(g @ 0..)) = (num, gen) {
        let (n, g) = (u32::try_from(n), u16::try_from(g).unwrap_or(u16::MAX));
        out.extend(n.ok().map(|n| (n, g)));
    }
    out.len() <= most
}

// ---------------------------------------------------------------- one step

/// A version of the document: lopdf's reading, with the objects LimarePDF's reader found freed
/// hidden. lopdf drops them itself since 0.47 (before, it ignored free entries); the check
/// doesn't rest on that.
struct Version<'a> {
    pdf: &'a Pdf,
    /// The numbers freed, as of the version before `newer`.
    freed: &'a HashSet<u32>,
    /// The entries a later revision changes, which come first.
    newer: Option<&'a BTreeMap<u32, Entry>>,
    /// The references in the data of what it draws, by drawing.
    drawings: &'a Drawings,
}

impl Version<'_> {
    fn freed(&self, num: u32) -> bool {
        match self.newer.and_then(|m| m.get(&num)) {
            Some(e) => *e == Entry::Free,
            None => self.freed.contains(&num),
        }
    }

    fn get(&self, id: ObjectId) -> Option<&Object> {
        if self.freed(id.0) {
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
        if self.freed(num) {
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

/// Which objects the sections change, and which they free, newest entry first. Objects are
/// checked in number order, so a revision with several faults always gives the same reason
/// (a reason naming another object would read as a new change when saving).
fn effective(secs: &[&Section]) -> BTreeMap<u32, Entry> {
    let mut m: BTreeMap<u32, Entry> = BTreeMap::new();
    for s in secs {
        for &(num, e) in &s.entries {
            if num != 0 {
                m.entry(num).or_insert(e);
            }
        }
    }
    m
}

/// Compares the version ending at `a` with the one ending at `b`. `freed` are the numbers
/// the sections after the signature's own version and up to `a` free; `between` the
/// sections between `a` and `b`, newest first. `listed` as for [`analyse`].
fn compare_versions(
    versions: &mut Versions,
    a: usize,
    b: usize,
    freed: &HashSet<u32>,
    between: &[&Section],
    listed: &HashSet<ObjectId>,
) -> Vec<Seen> {
    let malformed = |why: String| vec![never(ChangeKind::Malformed(why), None)];
    let bytes = versions.bytes;
    // Object 0 heads the list of free objects, so no revision may list it in use, even when
    // a later one frees it again: lopdf keeps the object an entry's bytes name, so one
    // pointing at the signed bytes of another object brings back that old copy.
    let zero_in_use = between
        .iter()
        .flat_map(|s| &s.entries)
        .any(|&(num, e)| num == 0 && e != Entry::Free);
    if zero_in_use {
        return malformed("LimarePDF can't read object 0 reliably".into());
    }
    let newest = effective(between);
    for end in [a, b] {
        versions.load(end);
        versions.read_drawings(end);
    }
    // Only a later signed version can be missing, as a signature's own was read to check it
    // and the whole file is open; one not opened for the limits is past them.
    let (Some((old_pdf, old_drawings)), Some((new_pdf, new_drawings))) =
        (versions.peek_drawn(a), versions.peek_drawn(b))
    else {
        return malformed(if versions.allowed(a) && versions.allowed(b) {
            "LimarePDF can't read a later signed version".into()
        } else {
            too_many_versions()
        });
    };
    // Frees before `a`, unless `between` reuses the number.
    let old = Version {
        pdf: old_pdf,
        freed,
        newer: None,
        drawings: old_drawings,
    };
    let new = Version {
        pdf: new_pdf,
        freed,
        newer: Some(&newest),
        drawings: new_drawings,
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
            // lopdf must find it free too: one it reads in use is never compared.
            Entry::Free => matches!(
                new_table.get(&num),
                None | Some(XrefEntry::Free | XrefEntry::UnusableFree)
            ),
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
                            // What the data of a drawing it starts refers to is part of it.
                            for &r in v.drawings.get(&id).into_iter().flatten() {
                                self.refs(&Object::Reference(r), kind, None, &mut found);
                            }
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
        let found = analyse(&mut versions, &[sig], &[], &listed(&whole), certified);
        found[0]
            .iter()
            .map(|c| (c.kind.clone(), c.page, c.allowed()))
            .collect()
    }

    /// A number LimarePDF reads as freed after signing but lopdf as in use, written plainly
    /// or in an object stream, is refused, as one lopdf reads in use is never compared. The
    /// files read alike, so the freeing section is made up.
    #[test]
    fn a_number_lopdf_reads_in_use_but_freed_is_refused() {
        for modern in [false, true] {
            let mut p = Pdf::new();
            p.insert_blank(0, 300.0, 200.0).unwrap();
            let mut signed = Vec::new();
            match modern {
                false => p.doc.save_to(&mut signed),
                true => p.doc.save_modern(&mut signed),
            }
            .unwrap();
            let mut p = Pdf::from_bytes(&signed, None).unwrap();
            p.insert_blank(1, 300.0, 200.0).unwrap();
            let bytes = append_revision(&signed, &p.doc).unwrap().bytes;
            let whole = Pdf::from_bytes(&bytes, None).unwrap();
            let root = whole.doc.trailer.get(b"Root").unwrap();
            let num = root.as_reference().unwrap().0;
            let read = whole.doc.reference_table.get(num);
            match modern {
                false => assert!(matches!(read, Some(XrefEntry::Normal { .. }))),
                true => assert!(matches!(read, Some(XrefEntry::Compressed { .. }))),
            }
            let mut versions = Versions::new(&bytes, None, &whole);
            let freeing = Section {
                offset: signed.len(),
                end: bytes.len(),
                entries: vec![(num, Entry::Free)],
                stream_at: None,
            };
            let (a, b) = (signed.len(), bytes.len());
            let found = compare_versions(
                &mut versions,
                a,
                b,
                &HashSet::new(),
                &[&freeing],
                &listed(&whole),
            );
            let found: Vec<_> = found.into_iter().map(|s| (s.kind, s.need)).collect();
            let why = format!("LimarePDF can't read object {num} reliably");
            assert_eq!(found, [(ChangeKind::Malformed(why), Need::Never)]);
        }
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
        let sig_ends = [(end, end)];
        NAMES_COPIED.set(0);
        let raw = changes_after(&mut versions, &bytes, end, &sig_ends, &listed, &mut cache);
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
        let sig_ends = [(end, end)];
        NAMES_COPIED.set(0);
        let raw = changes_after(&mut versions, &bytes, end, &sig_ends, &listed, &mut cache);
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
            freed: &HashSet::new(),
            newer: None,
            drawings: &Drawings::new(),
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
            freed: &HashSet::new(),
            newer: None,
            drawings: &Drawings::new(),
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
            freed: &HashSet::new(),
            newer: None,
            drawings: &Drawings::new(),
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
    /// and the changes found are those without the spaces and empty revisions. So too with
    /// a later end every 64 bytes of the spaces, as signatures LimarePDF couldn't check may
    /// have, not at the spaces once an end.
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
            let sig_ends = signed_ends(bytes, sig_ends.iter().copied());
            let found = changes_after(&mut versions, bytes, end, &sig_ends, &listed, &mut cache);
            let found: Vec<_> = found.into_iter().map(|s| (s.kind, s.need)).collect();
            (found, SCANNED.get())
        };
        let (found, scanned) = changes(&bytes, &[end, later]);
        assert!(scanned <= 4 * bytes.len(), "{scanned} bytes looked at");
        assert!(!found.is_empty());
        assert_eq!(found, changes(&plain, &[end]).0);
        let many: Vec<usize> = std::iter::once(end)
            .chain((later..plain.len() + 65_536).step_by(64))
            .collect();
        let (found, scanned) = changes(&bytes, &many);
        assert!(scanned <= 4 * bytes.len(), "{scanned} bytes looked at");
        assert_eq!(found, changes(&plain, &[end]).0);
    }

    /// A plain one-page file, its page's number, the page written turned by the given angle
    /// (0, as it is), and the end of a revision listing the page alone, at offset `entry`,
    /// its section at `xref` following the one at `prev`.
    #[allow(clippy::type_complexity)]
    fn page_revisions() -> (
        Vec<u8>,
        u32,
        impl Fn(i64) -> String,
        impl Fn(usize, usize, usize) -> String,
    ) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let signed = p.snapshot().unwrap();
        let p = Pdf::from_bytes(&signed, None).unwrap();
        let (num, gen) = p.page_ids()[0];
        let Some(&XrefEntry::Normal { offset, .. }) = p.doc.reference_table.get(num) else {
            panic!("the page isn't written plainly");
        };
        let at = offset as usize;
        let len = signed[at..]
            .windows(6)
            .position(|w| w == b"endobj")
            .unwrap()
            + 6;
        let page = String::from_utf8(signed[at..at + len].to_vec()).unwrap();
        let turned = move |angle: i64| {
            let close = page.rfind(">>").unwrap();
            match angle {
                0 => format!("{page}\n"),
                _ => format!("{} /Rotate {angle}{}\n", &page[..close], &page[close..]),
            }
        };
        let (root, root_gen) = p.doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        let size = p.doc.trailer.get(b"Size").unwrap().as_i64().unwrap();
        let tail = move |entry: usize, prev: usize, xref: usize| {
            format!(
                "xref\n{num} 1\n{entry:010} {gen:05} n \ntrailer\n<< /Size {size} /Root {root} \
                 {root_gen} R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n"
            )
        };
        (signed, num, turned, tail)
    }

    /// A revision whose cross-reference pointer leads into the white space before its
    /// section, past where a later version is signed, is compared after that version. It
    /// fell between the versions compared and was never looked at: here it put the page,
    /// turned, at bytes the revision before holds but doesn't list.
    #[test]
    fn a_revision_starting_before_a_later_signed_end_is_compared() {
        let (signed, num, turned, tail) = page_revisions();
        // The page as it was, after a turned copy no entry lists.
        let mut bytes = signed.clone();
        let turned_at = bytes.len();
        bytes.extend_from_slice(turned(180).as_bytes());
        let page_at = bytes.len();
        bytes.extend_from_slice(turned(0).as_bytes());
        let xref = bytes.len();
        let r1 = tail(page_at, last_startxref(&signed).unwrap(), xref);
        bytes.extend_from_slice(r1.as_bytes());
        // Then 20 spaces, the next revision's pointer leading to the third.
        let spaces = bytes.len();
        bytes.resize(spaces + 20, b' ');
        let r2 = tail(turned_at, xref, spaces + 3);
        bytes.extend_from_slice(r2.as_bytes());
        let end = signed.len();
        let changes = |sig_ends: &[usize]| {
            let whole = Pdf::from_bytes(&bytes, None).unwrap();
            let mut versions = Versions::new(&bytes, None, &whole);
            let (listed, mut cache) = (listed(&whole), HashMap::new());
            let sig_ends = signed_ends(&bytes, sig_ends.iter().copied());
            let found = changes_after(&mut versions, &bytes, end, &sig_ends, &listed, &mut cache);
            found
                .into_iter()
                .map(|s| (s.kind, s.need))
                .collect::<Vec<_>>()
        };
        // Compared alone, it points into the revision before; with it, the page turned.
        let outside = format!("object {num} points outside the revision that changes it");
        assert_eq!(
            changes(&[end, spaces + 10]),
            [(ChangeKind::Malformed(outside), Need::Never)]
        );
        assert_eq!(changes(&[end]), [(ChangeKind::PageContent, Need::Never)]);
    }

    /// Changes found for an earlier signature are reused for a later one, a refusal too: the
    /// later signature stops at it, as when found afresh, not going on to what follows.
    #[test]
    fn a_refusal_found_for_an_earlier_signature_stops_a_later_one() {
        let (signed, _, turned, tail) = page_revisions();
        // A turned copy no entry lists, then the page listed as it was.
        let mut bytes = signed.clone();
        let turned_at = bytes.len();
        bytes.extend_from_slice(turned(180).as_bytes());
        let page_at = bytes.len();
        bytes.extend_from_slice(turned(0).as_bytes());
        let x1 = bytes.len();
        bytes.extend_from_slice(tail(page_at, last_startxref(&signed).unwrap(), x1).as_bytes());
        // A revision listing the copy, which lies in the revision before.
        let x2 = bytes.len();
        bytes.extend_from_slice(tail(turned_at, x1, x2).as_bytes());
        // And one turning the page.
        let (e1, e2, e3) = (signed.len(), x2, bytes.len());
        let again = bytes.len();
        bytes.extend_from_slice(turned(90).as_bytes());
        let x3 = bytes.len();
        bytes.extend_from_slice(tail(again, x2, x3).as_bytes());
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let listed = listed(&whole);
        let sig_ends = signed_ends(&bytes, [e1, e2, e3]);
        let found = |end: usize, versions: &mut Versions, cache: &mut _| {
            changes_after(versions, &bytes, end, &sig_ends, &listed, cache)
                .into_iter()
                .map(|s| s.kind)
                .collect::<Vec<_>>()
        };
        let mut cache = HashMap::new();
        let first = found(e1, &mut versions, &mut cache);
        assert!(matches!(first[..], [ChangeKind::Malformed(_)]), "{first:?}");
        let fresh = found(e2, &mut versions, &mut HashMap::new());
        assert_eq!(fresh, first);
        assert_eq!(found(e2, &mut versions, &mut cache), fresh);
    }

    /// A later signed version LimarePDF can't read refuses the earlier signatures, saying so,
    /// not that it's past the limits: here its revision encrypts it, with a password the
    /// empty one doesn't open, and the next leaves that out again.
    #[test]
    fn a_later_signed_version_that_cant_be_read_is_refused() {
        let (signed, num, turned, tail) = page_revisions();
        let mut bytes = signed.clone();
        let r1 = tail(0, 0, 0);
        let size = r1.split("/Size ").nth(1).unwrap();
        let size: u32 = size[..size.find(' ').unwrap()].parse().unwrap();
        let enc_at = bytes.len();
        let zeros = "00".repeat(32);
        let enc = format!(
            "{size} 0 obj\n<< /Filter /Standard /V 1 /R 2 /O <{zeros}> /U <{zeros}> /P -4 >>\n\
             endobj\n"
        );
        bytes.extend_from_slice(enc.as_bytes());
        let x1 = bytes.len();
        let r1 = tail(enc_at, last_startxref(&signed).unwrap(), x1)
            .replacen(&format!("xref\n{num} 1"), &format!("xref\n{size} 1"), 1)
            .replacen(&format!("/Size {size}"), &format!("/Size {}", size + 1), 1)
            .replacen(
                " >>\nstartxref",
                &format!(" /Encrypt {size} 0 R /ID [<00> <00>] >>\nstartxref"),
                1,
            );
        bytes.extend_from_slice(r1.as_bytes());
        let later = bytes.len();
        assert!(Pdf::from_bytes(&bytes, None).is_err());
        let page_at = bytes.len();
        bytes.extend_from_slice(turned(90).as_bytes());
        let x2 = bytes.len();
        bytes.extend_from_slice(tail(page_at, x1, x2).as_bytes());
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let (listed, mut cache) = (listed(&whole), HashMap::new());
        let end = signed.len();
        let sig_ends = signed_ends(&bytes, [end, later]);
        let found = changes_after(&mut versions, &bytes, end, &sig_ends, &listed, &mut cache);
        let found: Vec<_> = found.into_iter().map(|s| s.kind).collect();
        let why = "LimarePDF can't read a later signed version";
        assert_eq!(found, [ChangeKind::Malformed(why.into())]);
    }

    /// A later signed version not opened for the limits is refused as past them, also when
    /// it's first needed as the older one: here it's this signature's own version and some
    /// white space, so the window up to it holds nothing to compare.
    #[test]
    fn a_later_signed_version_past_the_limits_is_refused_as_such() {
        let (signed, _, turned, tail) = page_revisions();
        let mut bytes = signed.clone();
        bytes.extend_from_slice(b"  ");
        let later = bytes.len();
        let page_at = bytes.len();
        bytes.extend_from_slice(turned(90).as_bytes());
        let x1 = bytes.len();
        bytes.extend_from_slice(tail(page_at, last_startxref(&signed).unwrap(), x1).as_bytes());
        let whole = Pdf::from_bytes(&bytes, None).unwrap();
        let mut versions = Versions::new(&bytes, None, &whole);
        let listed = listed(&whole);
        let end = signed.len();
        let sig_ends = signed_ends(&bytes, [end, later]);
        let found = |versions: &mut Versions| {
            let cache = &mut HashMap::new();
            changes_after(versions, &bytes, end, &sig_ends, &listed, cache)
                .into_iter()
                .map(|s| s.kind)
                .collect::<Vec<_>>()
        };
        let (fresh, mut full) = (found(&mut versions), Versions::new(&bytes, None, &whole));
        assert_eq!(fresh, [ChangeKind::PageContent]);
        // Unreadable prefixes, each counted.
        (1..=100).for_each(|n| full.load(n));
        let want = [ChangeKind::Malformed(too_many_versions())];
        assert_eq!(found(&mut full), want);
    }

    /// 200 dots with `text` at each place given.
    fn dots(texts: &[(usize, &str)]) -> Vec<u8> {
        let mut b = vec![b'.'; 200];
        for &(at, text) in texts {
            b[at..at + text.len()].copy_from_slice(text.as_bytes());
        }
        b
    }

    #[test]
    fn lopdf_finds_object_headers_its_way() {
        for yes in [
            "1 0 obj",
            "1 0 obj<<",
            "12\t\r\n3 \n obj ",
            "4294967295 65535 obj",
        ] {
            assert!(lopdf_header(yes.as_bytes()), "{yes:?}");
        }
        for no in [
            "1 0 objx",
            "1 0 obj1",
            "1 0obj",
            "10 obj",
            "1\x0c0 obj",
            " 1 0 obj",
            "12345678901 0 obj",
            "4294967296 0 obj",
            "1 123456 obj",
            "1 65536 obj",
            "",
        ] {
            assert!(!lopdf_header(no.as_bytes()), "{no:?}");
        }
    }

    #[test]
    fn lopdf_moves_a_pointer_to_the_nearest_xref() {
        let moves = |texts: &[(usize, &str)]| lopdf_moves(&dots(texts), 100);
        // Straight to a section, or past the end: no move.
        assert_eq!(moves(&[(100, "xref")]), []);
        assert_eq!(moves(&[(100, "7 0 obj"), (90, "xref\n")]), []);
        assert_eq!(lopdf_moves(&dots(&[(150, "xref\n")]), 200), []);
        assert_eq!(moves(&[(100, "\n"), (101, "xref\n")]), [101]);
        assert_eq!(moves(&[(90, "xref\n"), (105, "xref\n")]), [105]);
        assert_eq!(moves(&[(96, "xref\n"), (104, "xref\n")]), [96]);
        // Not the one in `startxref`.
        assert_eq!(moves(&[(97, "startxref\n"), (120, "xref\n")]), [120]);
        let texts = [(96, "start"), (101, "xref\n"), (130, "xref\n")];
        assert_eq!(moves(&texts), [130]);
        // Within 64 bytes before, and up to 59 after (lopdf leaves 4 at the end).
        assert_eq!(moves(&[(36, "xref\n")]), [36]);
        assert_eq!(moves(&[(35, "xref\n")]), []);
        assert_eq!(moves(&[(159, "xref\n")]), [159]);
        assert_eq!(moves(&[(160, "xref\n")]), []);
        assert_eq!(lopdf_moves(&dots(&[(0, "xref\n")]), 30), [0]);
        let near_end = &dots(&[(150, "xref\n")])[..155];
        assert_eq!(lopdf_moves(near_end, 140), [150]);
    }

    /// lopdf reads a table only where a line ends after `xref`, with one space before it
    /// at most, and tries no other place when the nearest `xref` isn't one.
    #[test]
    fn lopdf_moves_a_pointer_only_to_an_xref_starting_a_table() {
        let moves = |texts: &[(usize, &str)]| lopdf_moves(&dots(texts), 100);
        for eol in ["\n", "\r", "\r\n", " \n", " \r"] {
            assert_eq!(moves(&[(90, &format!("xref{eol}"))]), [90], "{eol:?}");
        }
        for not in ["xref", "xref)", "xref  \n", "xref\t\n", "xrefs\n"] {
            assert_eq!(moves(&[(90, not), (70, "xref\n")]), [], "{not:?}");
        }
        assert_eq!(moves(&[(100, "\0"), (95, "xref)"), (101, "7 0 obj")]), []);
        assert_eq!(lopdf_moves(&dots(&[(150, "xref")])[..154], 140), []);
    }

    #[test]
    fn lopdf_moves_a_pointer_to_a_header_near_it_when_no_xref_is() {
        let moves = |texts: &[(usize, &str)]| lopdf_moves(&dots(texts), 100);
        // lopdf reads a stream after white space itself.
        assert_eq!(
            moves(&[(100, " \t\r\n\x0c"), (105, "7 0 obj"), (80, " 6 0 obj")]),
            []
        );
        // Every header in the window may be one, nearest or not; not one inside a word.
        let texts = [
            (100, "\0"),
            (101, "7 0 obj"),
            (80, " 6 0 obj"),
            (60, "a5 0 obj"),
        ];
        assert_eq!(moves(&texts), [81, 101]);
        // Within 64 bytes before, and 63 after.
        assert_eq!(
            moves(&[(100, "\0"), (36, "5 0 obj"), (162, " 8 0 obj")]),
            [36, 163]
        );
        assert_eq!(
            moves(&[(100, "\0"), (35, "5 0 obj"), (163, " 8 0 obj")]),
            []
        );
        assert_eq!(lopdf_moves(&dots(&[(0, "5 0 obj")]), 30), [0]);
    }

    /// Poppler takes a table's offset past 2^63 - 1, or an object stream index past 2^31 - 1,
    /// as damage, a free entry's or an unused object's too, and scans the whole file for
    /// objects (review round 4). LimarePDF's PDF library rebuilds a file with such an offset
    /// itself, so the comparison of readings refused it anyway; it misreads such an index,
    /// which was refused only where the object is used.
    #[test]
    fn numbers_poppler_takes_as_damage_are_refused() {
        let table = |offset: &str| format!("xref\n0 1\n{offset} 65535 f\r\ntrailer<</Size 1>>\n");
        assert!(read_section(table("9223372036854775807").as_bytes(), 0).is_ok());
        assert!(read_section(table("9223372036854775808").as_bytes(), 0).is_err());
        let stream = |index: u32| {
            let mut b =
                b"1 0 obj\n<</Type/XRef/Size 2/Index [1 1]/W [1 1 4]/Length 6>>\nstream\n".to_vec();
            b.extend([2, 5]);
            b.extend(index.to_be_bytes());
            b.extend(b"\nendstream\nendobj\n");
            b
        };
        assert!(read_section(&stream(i32::MAX as u32), 0).is_ok());
        assert!(read_section(&stream(1 << 31), 0).is_err());
    }

    /// Poppler can't make room for as many objects as the newest trailer's `/Size` past
    /// [`MAX_ENTRIES`] gives, and scans the whole file for objects instead; for an older
    /// trailer's it doesn't make room (review round 4).
    #[test]
    fn a_size_poppler_cant_make_room_for_differs() {
        let plain = table_file(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>",
        ]);
        let at = last_startxref(&plain).unwrap();
        let sized = |n: i64| {
            let s = at + plain[at..].windows(5).position(|w| w == b"/Size").unwrap() + 5;
            let s = s + plain[s..].iter().position(u8::is_ascii_digit).unwrap();
            let e = s + plain[s..].iter().position(|c| !c.is_ascii_digit()).unwrap();
            [&plain[..s], n.to_string().as_bytes(), &plain[e..]].concat()
        };
        let read = |b: &[u8]| compare_reading(b, &Document::load_mem(b).unwrap()).map(|_| ());
        assert_eq!(read(&sized(MAX_ENTRIES)), Ok(()));
        assert_eq!(read(&sized(MAX_ENTRIES + 1)), Err(malformed(at)));
        let older = sized(MAX_ENTRIES + 1);
        let newer = format!(
            "xref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Size 4 /Root 1 0 R /Prev {at} >>\n\
             startxref\n{}\n%%EOF\n",
            older.len()
        );
        assert_eq!(read(&[older, newer.into_bytes()].concat()), Ok(()));
    }

    /// The signed version's pointer must lead lopdf to the same section in the whole file as
    /// in the signed version: a later revision's `xref` may be nearer to it than the signed one.
    #[test]
    fn a_signed_pointer_lopdf_moves_into_a_later_revision_is_refused() {
        let file = |gap: usize| {
            let mut b = b"%PDF-1.7\n".to_vec();
            let x = b.len();
            b.extend_from_slice(b"xref\n0 1\n0000000000 65535 f\r\ntrailer<</Size 1>>\n");
            // Into the trailer, 41 bytes past the signed version's `xref`.
            let at = x + 41;
            b.extend_from_slice(format!("startxref\n{at}\n%%EOF\n").as_bytes());
            let signed_end = b.len();
            b.extend_from_slice(&vec![b' '; gap]);
            let t = b.len();
            let tail = format!("xref\n0 0\ntrailer<</Size 1/Prev {at}>>\nstartxref\n{t}\n%%EOF\n");
            b.extend_from_slice(tail.as_bytes());
            (b, signed_end, at)
        };
        let (b, signed_end, at) = file(0);
        assert_eq!(lopdf_moves(&b[..signed_end], at), [9]);
        assert_eq!(read_chain(&b, signed_end).err(), Some(moved(at)));
        // Farther from it than the signed one.
        let (b, signed_end, _) = file(20);
        assert_eq!(read_chain(&b, signed_end).map(|s| s.len()), Ok(1));
    }

    /// lopdf must take the trailer other apps take, the newest: its catalog, and its
    /// encryption dictionary (lopdf drops `/Encrypt` from the trailer once it decrypts), which
    /// it must find where they do.
    #[test]
    fn a_reading_taking_another_trailer_differs() {
        let other = Err(
            "they take its catalog or encryption from another cross-reference section".to_string(),
        );
        let read = |b: &[u8], change: &dyn Fn(&mut Document)| {
            let mut d = Document::load_mem(b).unwrap();
            change(&mut d);
            compare_reading(b, &d).map(|_| ())
        };
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let plain = p.to_bytes().unwrap();
        assert_eq!(read(&plain, &|_| {}), Ok(()));
        let pages = |d: &Document| d.catalog().unwrap().get(b"Pages").unwrap().clone();
        assert_eq!(read(&plain, &|d| d.trailer.set("Root", pages(d))), other);
        assert_eq!(read(&plain, &|d| d.trailer.set("Encrypt", pages(d))), other);
        // A revision naming a new catalog.
        let mut d = Document::load_mem(&plain).unwrap();
        let root = d.add_object(d.catalog().unwrap().clone());
        d.trailer.set("Root", root);
        let newer = append_revision(&plain, &d).unwrap().bytes;
        assert_eq!(read(&newer, &|_| {}), Ok(()));
        // Encrypted, read decrypted or not.
        let protect = |p: &mut Pdf, user: &str| {
            p.set_encryption(Some(crate::Encryption {
                user_password: user.into(),
                owner_password: "owner".into(),
                cipher: crate::Cipher::Aes128,
                restrictions: crate::Restrictions::default(),
            }));
            p.to_bytes().unwrap()
        };
        let locked = protect(&mut p, "");
        assert_eq!(read(&locked, &|_| {}), Ok(()));
        let encrypt = |d: &Document| {
            (d.encryption_state.as_ref())
                .and_then(|s| s.encrypt_object_id())
                .unwrap()
        };
        assert_eq!(
            read(&locked, &|d| {
                d.trailer.set("Encrypt", encrypt(d));
                d.encryption_state = None;
            }),
            Ok(())
        );
        assert_eq!(read(&locked, &|d| d.encryption_state = None), other);
        let another = |d: &mut Document| {
            d.trailer.set("Encrypt", pages(d));
            d.encryption_state = None;
        };
        assert_eq!(read(&locked, &another), other);
        // Without the password lopdf keeps `/Encrypt`.
        let password = protect(&mut p, "user");
        assert_eq!(
            read(&password, &|d| assert!(d.trailer.has(b"Encrypt"))),
            Ok(())
        );
        // The dictionary found elsewhere.
        let elsewhere = |d: &mut Document| {
            let normal = XrefEntry::Normal {
                offset: 0,
                generation: 0,
            };
            d.reference_table.entries.insert(encrypt(d).0, normal);
        };
        assert_eq!(
            read(&locked, &elsewhere),
            Err("they may decrypt it with another encryption dictionary".into())
        );
    }

    /// Unfiltered data and whole Flate data decode alike; anything else may not, however
    /// lopdf takes the filter.
    #[test]
    fn data_decodes_alike_only_unfiltered_or_whole_flate() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"1 0 2 0").unwrap();
        let z = z.finish().unwrap();
        let alike = |filter: Option<Object>, data: &[u8]| {
            let mut d = Dictionary::new();
            if let Some(f) = filter {
                d.set("Filter", f);
            }
            decodes_alike(&Stream::new(d, data.to_vec()), 1 << 10)
        };
        let flate = || Object::Name(b"FlateDecode".to_vec());
        assert!(alike(None, b"1 0 2 0"));
        assert!(alike(Some(flate()), &z));
        assert!(alike(Some(Object::Array(vec![flate()])), &z));
        // lopdf decodes these as unfiltered, or as far as it can.
        assert!(!alike(Some(Object::Reference((9, 0))), &z));
        assert!(!alike(Some(Object::Integer(1)), b"1 0 2 0"));
        // lopdf decodes data with no filters in the list as nothing.
        assert!(!alike(Some(Object::Array(vec![])), b"1 0 2 0"));
        assert!(!alike(Some(Object::Array(vec![flate(), flate()])), &z));
        assert!(!alike(Some(flate()), &z[..z.len() - 1]));
        assert!(!alike(Some(flate()), b""));
        // Over the limit.
        let mut big = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        big.write_all(&[0; 2 << 10]).unwrap();
        assert!(!alike(Some(flate()), &big.finish().unwrap()));
        // No filter, as the spec reads a null value.
        assert!(alike(Some(Object::Null), b"1 0 2 0"));
    }

    /// Readers find an object stream's objects alike only when each offset holds one object,
    /// found from Poppler's earlier windows and from `/First` too, with nothing but whole
    /// objects, `endobj` and signs pdf.js reads as 0 after it, also as pdf.js reads on past
    /// the content.
    #[test]
    fn objects_are_found_alike_only_one_at_each_offset() {
        // The index ends at `/First` (4); the offsets count from there. pdf.js reads `next`
        // after the content: a line end before `endstream` unless given.
        let before = |next: &str, data: &str, offsets: &[usize]| {
            let read = format!("9 0 {data}{next}");
            laid_out_alike(read.as_bytes(), read.len() - next.len(), 4, offsets)
        };
        let alike = |data: &str, offsets: &[usize]| before("\n", data, offsets);
        assert!(alike("<< /A 1 >> null", &[0, 11]));
        assert!(alike("[1 (x)] 2 0 R", &[0, 8]));
        // Poppler reads each 4 bytes early, from the comment and its line end on.
        assert!(alike("% a\n<</A[1]>>\n%b\n  -.5", &[4, 17]));
        assert!(alike("% a\n<</A[1]>>", &[4]));
        // An offset before the object's white space, as lopdf skips it.
        assert!(alike("1  2", &[0, 2]));
        assert!(alike("", &[]));
        // Every reader stops at the end of the object.
        assert!(alike("1 endobj 2", &[0, 9]));
        assert!(alike("<< /A 1 >>\nendobj\n", &[0]));
        assert!(alike("1 2 3", &[0, 4]));
        assert!(alike("1 (x) [2] 3 0 R", &[0]));
        // pdf.js reads a sign or point without digits as 0 before white space or the end.
        assert!(alike("1 - 2", &[0]));
        assert!(alike("1 -.", &[0]));
        assert!(before("", "<< /A 1 >>\n-", &[0]));
        // Nothing runs into what follows the content.
        assert!(before("endstream", "1 (x)", &[0]));
        assert!(before("endstream", "1 null\n", &[0]));
        // A comment at the end, before a line end or the end of the file.
        assert!(alike("1 %c", &[0]));
        assert!(before("", "1 %c", &[0]));
        // White space from `/First` to an offset past it.
        assert!(alike("      1", &[6]));
        // Something before the first object, also where Poppler skips it but pdf.js lexes it.
        assert!(!alike("1 2", &[2]));
        assert!(!alike(")     1", &[6]));
        // After one: pdf.js reads a stream, and Poppler an error; pdf.js can't lex the next
        // ones. Other words are refused too, though some every reader ignores (`obj`).
        assert!(!alike("<< /A 1 >> stream\nx\nendstream", &[0]));
        assert!(!alike("1 -x", &[0]));
        assert!(!alike("1 )", &[0]));
        assert!(!alike("1 obj", &[0]));
        assert!(!alike("1 ---", &[0]));
        // lopdf reads `+1` alone, other readers a reference.
        assert!(!alike("+1 0 R", &[0]));
        // A comment at the end, which pdf.js reads on past into what follows the content;
        // after decoded data, into zeros, which would be fine.
        assert!(!before("e", "1 %c", &[0]));
        assert!(!before("\0", "1 %c", &[0]));
        // A sign before what follows the content, where pdf.js fails: a line end and
        // `endstream`, or a zero filling its buffer after decoded data.
        assert!(!alike("<< /A 1 >>\n-", &[0]));
        assert!(!before("\0", "<< /A 1 >>\n-", &[0]));
        // pdf.js reads on into what follows the content.
        assert!(!before("endstream", "null", &[0]));
        assert!(!before("endstream", "1 null", &[0]));
        assert!(!before("e", "/A", &[0]));
        // Or something running into the next object, or past Poppler's earlier window.
        assert!(!alike("1 (x 2)", &[0, 4]));
        assert!(!alike("    (a%b)\n2", &[4, 10]));
        // Or a comment hiding the next object's start from reading on past the one before, as
        // lopdf does looking for `N G R` (pdf.js and Poppler stop at the next offset): a
        // precaution, as the readers agree here.
        assert!(alike("90 (\n)", &[0, 3]));
        assert!(!alike("90 %(\n)", &[0, 4]));
        // Also with a number hidden there, which lopdf could take as a generation.
        assert!(!alike("90 %(\n7)", &[0, 4]));
        // Poppler, reading 4 bytes early, starts in the comment.
        assert!(!alike("% a\n<</A[1]>>\n%b\n  -.5", &[4, 19]));
        // Out of order, the same twice, inside the object before, or past the end.
        assert!(!alike("1 2", &[2, 0]));
        assert!(!alike("1 2", &[0, 0]));
        assert!(!alike("<< /A 1 >> 2", &[0, 3]));
        assert!(!alike("1", &[0, 5]));
        assert!(!alike("1", &[usize::MAX]));
        assert!(!before("1", "1 ", &[0, 2]));
        // An offset inside a comment, and what isn't one object.
        assert!(!alike("% a 1\n2", &[4]));
        assert!(!alike("endobj", &[0]));
        assert!(!alike("<< /A >>", &[0]));
        assert!(!alike("[1 2", &[0]));
        assert!(!alike("1e5", &[0]));
        assert!(!alike("inf", &[0]));
    }

    /// An object stream's index reads alike only with PDF's white space between its
    /// numbers: lopdf splits it at any Unicode white space, other readers fail. Nor when
    /// pdf.js reads its last number on into the data, or Poppler can't take it.
    #[test]
    fn an_index_reads_alike_only_with_pdf_white_space() {
        let read = |index: &str, data: &str| {
            let n = i64::try_from(index.split_whitespace().count() / 2).unwrap();
            let first = i64::try_from(index.len()).unwrap();
            let d = dictionary! { "Type" => "ObjStm", "N" => n, "First" => first };
            objstm_members(
                &Stream::new(d, format!("{index}{data}").into_bytes()),
                Some(b"\n"),
            )
        };
        let members = |index: &str| read(index, "1 2");
        assert_eq!(members("3 0 6 2 "), Some((vec![3, 6], true)));
        assert_eq!(members("+3 0\r\n6\t+2\x0c"), Some((vec![3, 6], true)));
        assert_eq!(members("3 0\x0b6 2 "), Some((vec![3, 6], false)));
        assert_eq!(members("3 0\u{a0}6 2 "), Some((vec![3, 6], false)));
        // pdf.js reads offsets 0 and 21.
        assert_eq!(members("3 0 6 2"), Some((vec![3, 6], false)));
        assert_eq!(read("3 0 6 2", "+1 +2"), Some((vec![3, 6], true)));
        assert_eq!(read("3 0", "<<>>"), Some((vec![3], true)));
        assert_eq!(read("3 0", "-1"), Some((vec![3], false)));
        assert_eq!(read("3 0", ".5"), Some((vec![3], false)));
        // Poppler takes numbers up to its `int`, and a million objects.
        assert_eq!(
            members("2147483647 0 6 2 "),
            Some((vec![2_147_483_647, 6], true))
        );
        assert_eq!(
            members("2147483648 0 6 2 "),
            Some((vec![2_147_483_648, 6], false))
        );
        let many = |n: usize| {
            let index: String = (0..n).map(|i| format!("{} {} ", i + 1, 2 * i)).collect();
            read(&index, &"1 ".repeat(n)).map(|(m, alike)| (m.len(), alike))
        };
        assert_eq!(many(1_000_000), Some((1_000_000, true)));
        assert_eq!(many(1_000_001), Some((1_000_001, false)));
    }

    /// Other apps read an object as LimarePDF does only when it is one whole object, followed by
    /// `endobj` or its stream data. Poppler reads `134 +0 R` as a reference, and lopdf doesn't.
    /// An object nested deeper than LimarePDF reads, which lopdf holds, is unsure too.
    #[test]
    fn an_object_written_otherwise_is_unsure() {
        let unsure = |o: &str| {
            let b = table_file(&[
                "<< /Type /Catalog /Pages 2 0 R >>\nendobj",
                "<< /Type /Pages /Kids [] /Count 0 >>\nendobj",
                o,
            ]);
            let d = Document::load_mem(&b).unwrap();
            compare_reading(&b, &d).unwrap().unsure.contains(&3)
        };
        for ok in [
            "<< /A 1 /B [1 0 R (x) <00>] >>\nendobj",
            "%x\n[ 1 ]  % y\nendobj",
            "<< /Length 2 >>\nstream\nab\nendstream\nendobj",
            "58endobj",
            "<< /A 1 >>\n4 0 obj\n<< >>\nendobj",
            "<< /A 1 >>",
        ] {
            assert!(!unsure(ok), "{ok}");
        }
        for bad in [
            "[134 +0 R]\nendobj",
            "[1 65536 R]\nendobj",
            "<< /A 1 >> 5\nendobj",
            "<< /A 1 >> >>\nendobj",
            "[1 0 R\nendobj",
            &format!("{}{}\nendobj", "[".repeat(40), "]".repeat(40)),
            "5\n4 0 obj\n<< >>\nendobj",
        ] {
            assert!(unsure(bad), "{bad}");
        }
    }

    /// lopdf, Poppler and pdf.js end a number glued to `endobj` at the `e`, and an object that
    /// ends itself where the next object's header, the cross-reference information or the end
    /// of the file follows it without `endobj`; not a number or a keyword so followed, which
    /// lopdf may read on into a reference.
    #[test]
    fn an_object_ends_where_every_reader_ends_it() {
        let whole = |s: &str| whole_object(Lexer::new(s.as_bytes(), 0), false, &mut HashSet::new());
        for ok in [
            "5 endobj",
            "58endobj",
            "-2.5endobj",
            "0.00-4endobj",
            "<< /A 1 >>\n4 0 obj",
            "[1 2] xref",
            "(x)\ntrailer",
            "<00> startxref",
            "/N",
            "/Aendobj",
            "<< /A 1 >> % x\n",
            "<< /A 1 >>\nstream\n",
            "<< /A 1 >> stream \t\r\n",
            "[1 2] stream x",
        ] {
            assert!(whole(ok), "{ok}");
        }
        for bad in [
            "<< /A 1 >> stream %\n",
            "<< /A 1 >>\nstream\x0c\n",
            "<< /A 1 >> stream x\n",
            "<< /A 1 >>\nstream",
            "endobj",
            "nullendobj",
            "/Aendobj 5",
            "5endstream",
            "58e5endobj",
            "1 0 Rendobj",
            "5\n4 0 obj",
            "true xref",
            "5",
            "<< /A 1 >>\n4 0",
            "<< /A 1 >>\n4 0 R",
            "<< /A 1 >> 5",
            "[1 2] xrefs",
            "<< /A 1 >> <zz>",
        ] {
            assert!(!whole(bad), "{bad}");
        }
    }

    /// A file of `objects`, numbered from 1, the first the catalog, each written as given
    /// after its header, listed by a table.
    fn table_file(objects: &[&str]) -> Vec<u8> {
        let mut b = b"%PDF-1.7\n".to_vec();
        let mut at = Vec::new();
        for (i, o) in objects.iter().enumerate() {
            at.push(b.len());
            b.extend_from_slice(format!("{} 0 obj\n{o}\n", i + 1).as_bytes());
        }
        let (x, size) = (b.len(), objects.len() + 1);
        b.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f\r\n").as_bytes());
        for a in at {
            b.extend_from_slice(format!("{a:010} 00000 n\r\n").as_bytes());
        }
        let tail = format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n");
        b.extend_from_slice(tail.as_bytes());
        b
    }

    /// pdf.js ends a number glued to `endstream` where the content ends, as lopdf and Poppler
    /// do, but reads a name or a keyword on into it.
    #[test]
    fn a_number_glued_to_endstream_ends_with_the_content() {
        let glued = |data: &str| {
            let d = dictionary! { "Type" => "ObjStm", "N" => 2, "First" => 8 };
            let content = format!("3 0 6 2 1 {data}").into_bytes();
            objstm_members(&Stream::new(d, content), Some(b"endstream")).map(|(_, a)| a)
        };
        assert_eq!(glued("23"), Some(true));
        assert_eq!(glued("-2.5"), Some(true));
        assert_eq!(glued("null"), Some(false));
        assert_eq!(glued("/A"), Some(false));
        assert_eq!(glued("/23"), Some(false));
        assert_eq!(glued("1 %23"), Some(false));
    }

    /// lopdf reads `#` and two hexadecimal digits in a name as one byte, and ends the name at
    /// any other `#`, where Poppler and pdf.js keep it: such a name doesn't read alike.
    #[test]
    fn a_name_reads_alike_only_with_two_hexadecimal_digits_after_each_number_sign() {
        assert_eq!(decode_name(b"A#41#0a"), Some(b"AA\n".to_vec()));
        assert_eq!(decode_name(b"A"), Some(b"A".to_vec()));
        for n in [&b"V#+A"[..], b"V#zz", b"V#4", b"V#", b"V#-1", b"V# A"] {
            assert_eq!(decode_name(n), None, "{}", String::from_utf8_lossy(n));
        }
    }

    /// Numbers read as lopdf reads them, which Poppler and pdf.js agree with: a real may have
    /// minus signs after its point, which they all skip. Others are refused: a minus inside
    /// the whole part (pdf.js skips it, the others start a number there), and what lopdf
    /// can't read.
    #[test]
    fn numbers_read_alike_as_lopdf_reads_them() {
        let read = |w: &str| read_object(&mut Lexer::new(w.as_bytes(), 0), 0);
        assert_eq!(read("12"), Some(Object::Integer(12)));
        assert_eq!(read("+12"), Some(Object::Integer(12)));
        assert_eq!(read("-12"), Some(Object::Integer(-12)));
        assert_eq!(
            read("-9223372036854775808"),
            Some(Object::Integer(i64::MIN))
        );
        assert_eq!(read("0.00-4142502"), Some(Object::Real(0.004_142_502)));
        assert_eq!(read("841.8-9"), Some(Object::Real(841.89)));
        assert_eq!(read("-1.-5"), Some(Object::Real(-1.5)));
        assert_eq!(read("-.5"), Some(Object::Real(-0.5)));
        assert_eq!(read(".5-1"), Some(Object::Real(0.51)));
        assert_eq!(read("5."), Some(Object::Real(5.0)));
        for w in [
            "12-3",
            ".-5",
            "--1.5",
            "+-1",
            "1.2.3",
            ".",
            "-",
            "1e5",
            "inf",
            "NaN",
            "9223372036854775808",
            "99999999999999999999",
        ] {
            assert_eq!(read(w), None, "{w}");
        }
    }

    /// A key given twice reads as its last value in lopdf and pdf.js, and in Poppler's lookup
    /// while the dictionary has fewer than 32 entries, the repeats counted. From 32 Poppler
    /// sorts them and may take another, and of a font resource dictionary it takes the first at
    /// any size. So values written differently are refused, at any depth: in cross-reference
    /// information from 32 entries, in an object at any size. Values written alike read alike,
    /// but for `/Contents` in an object readers decrypt: Poppler decrypts the last one twice.
    #[test]
    fn a_key_repeated_reads_alike_only_written_alike() {
        // `others` distinct entries, then `/K 1` and `/{last} {value}`.
        let dict = |others: usize, last: &str, value: &str| {
            let mut s = String::from("<<");
            for i in 0..others {
                s += &format!(" /E{i} 0");
            }
            format!("{s} /K 1 /{last} {value} >>")
        };
        let read = |w: &str| read_object(&mut Lexer::new(w.as_bytes(), 0), 0);
        let skip = |w: &str, decrypted| skip_object(&mut Lexer::new(w.as_bytes(), 0), decrypted);
        let Some(Object::Dictionary(d)) = read(&dict(29, "K", "2")) else {
            panic!("31 entries");
        };
        assert_eq!((d.len(), d.get(b"K").unwrap()), (30, &Object::Integer(2)));
        for ok in [
            dict(30, "L", "2"),
            dict(30, "K", "1"),
            dict(300, "#4B", "\n 1"),
            format!("[{}]", dict(29, "K", "2")),
        ] {
            assert!(read(&ok).is_some(), "{ok}");
        }
        for bad in [
            dict(30, "K", "2"),
            dict(30, "#4B", "2"),
            dict(300, "K", "2"),
            format!("[1 {}]", dict(30, "K", "2")),
            format!("<< /A {} >>", dict(30, "K", "2")),
        ] {
            assert_eq!(read(&bad), None, "{bad}");
        }

        for decrypted in [false, true] {
            for ok in [
                dict(0, "L", "2"),
                dict(0, "K", "1"),
                dict(0, "#4B", "\r\n1"),
                dict(300, "K", "1"),
                "<< /K << /A 1 >> /K << /A 1 >> >>".into(),
                "<< /Contents (a) /K 1 /K 1 >>".into(),
            ] {
                assert!(skip(&ok, decrypted), "{ok}, {decrypted}");
            }
            for bad in [
                dict(0, "K", "2"),
                dict(0, "#4B", "2"),
                dict(0, "K", "1.0"),
                dict(0, "K", "%x\n1"),
                dict(29, "K", "2"),
                dict(300, "K", "2"),
                format!("[1 {}]", dict(0, "K", "2")),
                format!("<< /A {} >>", dict(0, "K", "2")),
                "<< /F1 5 0 R /F#31 6 0 R >>".into(),
            ] {
                assert!(!skip(&bad, decrypted), "{bad}, {decrypted}");
            }
        }
        let contents = "<< /Contents (a) /Contents (a) >>";
        assert!(skip(contents, false));
        assert!(!skip(contents, true));
        assert!(!skip(&format!("[<< /A {contents} >>]"), true));
    }

    /// Other apps take a stream's data as long as its `/Length`, written in its dictionary or
    /// in an object of its own, `endobj` perhaps glued to it, when `endstream` and `endobj`
    /// follow.
    #[test]
    fn stream_data_is_as_long_as_its_length() {
        let none = HashMap::new();
        let data = |length: &str, tail: &str| {
            let file = format!("%x\n4 0 obj\n<< /Length {length} >>\nstream \t\r\nab{tail}");
            stream_data(file.as_bytes(), 3, &none, None)
        };
        let at = "%x\n4 0 obj\n<< /Length 2 >>\nstream \t\r\n".len();
        assert_eq!(data("2", "\nendstream\nendobj"), Some(at..at + 2));
        assert_eq!(data("3", "\nendstream endobj"), Some(at..at + 3));
        assert_eq!(data("2", " % x\nendstream\nendobj"), Some(at..at + 2));
        // Running into the data, past the end of the file, or a length that isn't a whole
        // number.
        assert_eq!(data("1", "\nendstream\nendobj"), None);
        assert_eq!(data("40", "\nendstream\nendobj"), None);
        assert_eq!(data("2.0", "\nendstream\nendobj"), None);
        assert_eq!(data("-1", "\nendstream\nendobj"), None);
        // Not followed by `endstream` and `endobj`.
        assert_eq!(data("2", "\nendstreamX\nendobj"), None);
        assert_eq!(data("2", "\nendstream\n5 0 obj"), None);
        assert_eq!(data("2", "\nendstream"), None);
        // Not at an object's header, or no line end after `stream`.
        let file = b"%x\n4 0 obj\n<< /Length 2 >>\nstream\nab\nendstream\nendobj";
        assert_eq!(stream_data(file, 3, &none, None), Some(at - 3..at - 1));
        assert_eq!(stream_data(file, 5, &none, None), None);
        let file = b"4 0 obj <</Length 2>> stream x\nab\nendstream\nendobj";
        assert_eq!(stream_data(file, 0, &none, None), None);
        // The length in an object of its own, where its entry says.
        let held = |length: &str, entry: Entry| {
            let head = "4 0 obj\n<< /Length 5 0 R >>\nstream\nab\nendstream\nendobj\n";
            let file = format!("{head}5 0 obj {length}");
            let entry = match entry {
                Entry::InUse { offset: 0, gen } => Entry::InUse {
                    offset: head.len(),
                    gen,
                },
                e => e,
            };
            stream_data(file.as_bytes(), 0, &HashMap::from([(5, entry)]), None)
        };
        let at = "4 0 obj\n<< /Length 5 0 R >>\nstream\n".len();
        let listed = Entry::InUse { offset: 0, gen: 0 };
        assert_eq!(held("2 endobj", listed), Some(at..at + 2));
        assert_eq!(held("2endobj", listed), Some(at..at + 2));
        assert_eq!(held("2", listed), None);
        assert_eq!(held("2.0 endobj", listed), None);
        assert_eq!(held("2.0endobj", listed), None);
        assert_eq!(held("endobj", listed), None);
        assert_eq!(held("2 endobj", Entry::InUse { offset: 0, gen: 1 }), None);
        assert_eq!(held("2 endobj", Entry::InUse { offset: 1, gen: 0 }), None);
        let compressed = Entry::Compressed {
            container: 6,
            index: 0,
        };
        assert_eq!(held("2 endobj", compressed), None);
        // In an object stream, as lopdf holds it, under generation 0 only.
        let packed = |reference: &str, length: Object| {
            let file = format!("4 0 obj\n<< /Length {reference} >>\nstream\nab\nendstream\nendobj");
            let mut doc = Document::new();
            doc.objects.insert((5, 0), length);
            let spec = HashMap::from([(5, compressed)]);
            stream_data(file.as_bytes(), 0, &spec, Some(&doc))
        };
        assert_eq!(packed("5 0 R", Object::Integer(2)), Some(at..at + 2));
        assert_eq!(packed("5 0 R", Object::Real(2.0)), None);
        assert_eq!(packed("5 1 R", Object::Integer(2)), None);
    }

    /// pdf.js reads on past the data it decrypts into the zeros filling its buffer, also
    /// through the Identity crypt filter, which leaves the data as it is in the file: there
    /// `-.` at the end of an object stream fails, where before a line end it reads as 0.
    #[test]
    fn data_decrypted_unchanged_is_not_read_on_into_the_file() {
        let unsure = encrypted_page_in_a_stream(false);
        assert!(!unsure("", "\n", true));
        assert!(unsure(" -.", "\n", true));
    }

    /// In an encrypted file lopdf, Poppler and pdf.js open any stream an entry names as an
    /// object stream, with or without `/Type /ObjStm`; LimarePDF checked typed ones only.
    #[test]
    fn an_encrypted_files_object_stream_without_its_type_is_checked() {
        let unsure = encrypted_page_in_a_stream(false);
        assert!(!unsure("", "\n", false));
        assert!(unsure(" -.", "\n", false));
    }

    /// pdf.js reads the objects the encryption dictionary names before it can decrypt, so an
    /// object stream holding one is read as it is in the file, on past its data, and every
    /// object in it is kept as read so.
    #[test]
    fn an_object_stream_read_before_decrypting_is_unsure() {
        let unsure = encrypted_page_in_a_stream(true);
        assert!(unsure("", "\n", true));
    }

    /// lopdf reads an object stream's data as long as its `/Length` only when a line end, at
    /// most, comes before `endstream`; otherwise it takes the data on to an `endstream` of its
    /// own finding, which other apps don't. What it decrypted can't show which it took.
    #[test]
    fn an_encrypted_object_stream_framed_otherwise_is_unsure() {
        let unsure = encrypted_page_in_a_stream(false);
        for framed in ["\n", "\r\n", "\r", ""] {
            assert!(!unsure("", framed, true), "{framed:?}");
        }
        for otherwise in [" ", " %x\n", "\n\n", "\t\n"] {
            assert!(unsure("", otherwise, true), "{otherwise:?}");
        }
    }

    /// pdf.js reads the objects the encryption dictionary names as they are in the file, where
    /// lopdf decrypts them, so one is unsure when decrypting may change it: when it holds a
    /// string or is a stream. One of names and numbers only, as a crypt filter is, reads alike.
    #[test]
    fn an_object_the_encryption_dictionary_names_is_unsure_when_decrypting_may_change_it() {
        let unsure = |o: Object| {
            let mut d = Document::with_version("1.7");
            let kids = Vec::<Object>::new();
            let pages =
                d.add_object(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => 0 });
            let root = d.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
            d.trailer.set("Root", root);
            let named = d.add_object(o);
            let encrypt = encrypt_with_identity(&mut d);
            let e = d.get_object_mut(encrypt).unwrap().as_dict_mut().unwrap();
            e.set("X", named);
            let mut b = Vec::new();
            d.save_to(&mut b).unwrap();
            let read = Document::load_mem(&b).unwrap();
            assert!(read.encryption_state.is_some());
            let reading = compare_reading(&b, &read).unwrap();
            reading.unsure.contains(&named.0)
        };
        let filter = dictionary! { "CFM" => "AESV3", "Length" => 32, "A" => vec![1.into()] };
        assert!(!unsure(filter.into()));
        let string = dictionary! { "A" => vec![Object::string_literal("x")] };
        assert!(unsure(string.into()));
        assert!(unsure(Stream::new(dictionary! {}, b"x".to_vec()).into()));
    }

    /// Looking for `stream` after an object the encryption dictionary names reads no further
    /// into a string there than its first byte, as lopdf does: never ended, it runs on through
    /// the rest of the file. 20,000 objects so followed took seconds, where a letter in place
    /// of the string's first byte takes milliseconds.
    #[test]
    fn objects_the_encryption_dictionary_names_followed_by_strings_are_read_as_fast_as_others() {
        let mut d = Document::with_version("1.7");
        let kids = Vec::<Object>::new();
        let pages = d.add_object(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => 0 });
        let root = d.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        d.trailer.set("Root", root);
        let named: Vec<Object> = (0..20_000)
            .map(|_| d.add_object(dictionary! { "A" => 1 }).into())
            .collect();
        let encrypt = encrypt_with_identity(&mut d);
        let e = d.get_object_mut(encrypt).unwrap().as_dict_mut().unwrap();
        e.set("X", named);
        let mut base = Vec::new();
        d.save_to(&mut base).unwrap();
        let read = Document::load_mem(&base).unwrap();
        let timed = |opening: &[u8; 6]| {
            // As long as `endobj`, so that the offsets hold; not after the cross-reference
            // stream.
            let mut b = base.clone();
            let mut at = 0;
            while let Some(k) = b[at..read.xref_start]
                .windows(6)
                .position(|w| w == b"endobj")
            {
                b[at + k..at + k + 6].copy_from_slice(opening);
                at += k + 6;
            }
            let start = std::time::Instant::now();
            let _ = compare_reading(&b, &read);
            start.elapsed()
        };
        let (took, twin) = (timed(b"(     "), timed(b"x     "));
        assert!(took < twin * 20, "{took:?}, {twin:?} with x");
    }

    /// Reading an encrypted file, lopdf cuts each object at the first `endobj` after its
    /// header and reads only what it cut, where other apps read on: a stream's data as long as
    /// its `/Length` past an `endobj` in it, a reference or a stream past a comment holding
    /// one. Such an object is unsure; one whose first `endobj` ends it isn't.
    #[test]
    fn an_encrypted_object_lopdf_cuts_at_an_endobj_inside_it_is_unsure() {
        let unsure = object_added_to_an_encrypted_file();
        let content = |o: Option<Object>| o.unwrap().as_stream().unwrap().content.clone();

        let data = "AB\nendstream\nendobj\nCD";
        let (cut, held) = unsure(&format!(
            "<< /Length {} >>\nstream\n{data}\nendstream",
            data.len()
        ));
        assert!(cut);
        assert_eq!(content(held), b"AB");
        let (cut, held) = unsure("12 %endobj\n0 R");
        assert!(cut);
        assert_eq!(held, Some(Object::Integer(12)));
        let (cut, held) = unsure("<< /Length 2 >> %endobj\nstream\nAB\nendstream");
        assert!(cut);
        assert!(held.unwrap().as_dict().is_ok());

        let (cut, held) = unsure("<< /Length 2 >>\nstream\nAB\nendstream");
        assert!(!cut);
        assert_eq!(content(held), b"AB");
        for whole in [
            "12 0 R",
            "<< /A 1 >>",
            "58endobj",
            "/Aendobj",
            "<< /A 1 >> %endobj",
        ] {
            let (cut, held) = unsure(whole);
            assert!(!cut, "{whole}");
            assert!(held.is_some(), "{whole}");
        }
    }

    /// Reading a dictionary in an encrypted object, Poppler leaves its first `/Contents` as it
    /// is and decrypts any repeat; then, but in a signature, it decrypts the last value. So a
    /// `/Contents` given twice is decrypted twice in Poppler, where lopdf and pdf.js decrypt it
    /// once at most: such an object is unsure, its values written alike or not.
    #[test]
    fn an_encrypted_object_giving_contents_twice_is_unsure() {
        let unsure = object_added_to_an_encrypted_file();
        for twice in [
            "<< /Contents (a) /Contents (a) >>",
            "<< /Contents (a) /Contents (b) >>",
            "[<< /A << /Contents (a) /Contents (a) >> >>]",
        ] {
            let (found, held) = unsure(twice);
            assert!(found, "{twice}");
            assert!(held.is_some(), "{twice}");
        }
        for once in [
            "<< /Contents (a) /A (a) >>",
            "<< /A << /Contents (a) >> /Contents (a) >>",
        ] {
            let (found, held) = unsure(once);
            assert!(!found, "{once}");
            assert!(held.is_some(), "{once}");
        }
    }

    /// lopdf takes a stream's data as long as its `/Length` only when a line end, at most,
    /// comes before `endstream`, and of a `/Length` written as a real as many bytes, whatever
    /// follows; what it decrypted can't show which data it took. Such a stream is unsure.
    #[test]
    fn an_encrypted_stream_framed_otherwise_is_unsure() {
        let unsure = object_added_to_an_encrypted_file();
        for framed in ["\n", "\r\n", "\r", ""] {
            let (found, held) = unsure(&format!("<< /Length 2 >>\nstream\nAB{framed}endstream"));
            assert!(!found, "{framed:?}");
            assert!(held.is_some(), "{framed:?}");
        }
        for otherwise in [
            "<< /Length 2. >>\nstream\nAB\nendstream",
            "<< /Length 2 >>\nstream\nAB %x\nendstream",
            "<< /Length 2 >>\nstream\nAB\n\nendstream",
            "<< /Length 1 >>\nstream\nAB\nendstream",
        ] {
            let (found, held) = unsure(otherwise);
            assert!(found, "{otherwise:?}");
            assert!(held.is_some(), "{otherwise:?}");
        }
    }

    /// An encrypted file (Identity crypt filter), and how a revision adding an object written
    /// `text` reads: whether that object is unsure, and what lopdf holds.
    fn object_added_to_an_encrypted_file() -> impl Fn(&str) -> (bool, Option<Object>) {
        let mut d = Document::with_version("1.7");
        let kids = Vec::<Object>::new();
        let pages = d.add_object(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => 0 });
        let root = d.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        d.trailer.set("Root", root);
        let encrypt = encrypt_with_identity(&mut d);
        let mut base = Vec::new();
        d.save_to(&mut base).unwrap();
        let prev = Document::load_mem(&base).unwrap().xref_start;
        move |text: &str| {
            let (n, x) = (d.max_id + 1, d.max_id + 2);
            let mut b = [&base[..], b"\n"].concat();
            let at_n = b.len();
            b.extend_from_slice(format!("{n} 0 obj\n{text}\nendobj\n").as_bytes());
            let at = b.len();
            let row =
                |f1: usize| [&[1][..], &u32::try_from(f1).unwrap().to_be_bytes(), &[0, 0]].concat();
            let rows = [row(at_n), row(at)].concat();
            b.extend_from_slice(
                format!(
                    "{x} 0 obj\n<< /Type /XRef /W [1 4 2] /Index [{n} 2] /Size {} /Root {} 0 R \
                     /Encrypt {} 0 R /ID [<{id}> <{id}>] /Prev {prev} /Length {} >>\nstream\n",
                    x + 1,
                    root.0,
                    encrypt.0,
                    rows.len(),
                    id = "07".repeat(16)
                )
                .as_bytes(),
            );
            b.extend_from_slice(&rows);
            b.extend_from_slice(
                format!("\nendstream\nendobj\nstartxref\n{at}\n%%EOF\n").as_bytes(),
            );
            let read = Document::load_mem(&b).unwrap();
            assert!(read.encryption_state.is_some());
            let held = read.objects.get(&(n, 0)).cloned();
            let found = compare_reading(&b, &read).unwrap().unsure.contains(&n);
            (found, held)
        }
    }

    /// Encrypts `d`, which has no `/ID` yet, with the Identity crypt filter, which leaves strings
    /// and data as they are. The encryption dictionary.
    fn encrypt_with_identity(d: &mut Document) -> ObjectId {
        use lopdf::encryption::crypt_filters::CryptFilter;
        let id = Object::String(vec![7; 16], lopdf::StringFormat::Hexadecimal);
        d.trailer.set("ID", vec![id.clone(), id]);
        let state = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V4 {
            document: d,
            encrypt_metadata: true,
            crypt_filters: BTreeMap::<Vec<u8>, std::sync::Arc<dyn CryptFilter>>::new(),
            stream_filter: b"Identity".to_vec(),
            string_filter: b"Identity".to_vec(),
            owner_password: "owner",
            user_password: "",
            permissions: lopdf::Permissions::all(),
        })
        .unwrap();
        d.encrypt(&state).unwrap();
        d.trailer.get(b"Encrypt").unwrap().as_reference().unwrap()
    }

    /// An encrypted file (Identity crypt filter) and a revision taking its page, then `end`,
    /// from an unfiltered object stream, typed `/ObjStm` or not, `framing` between its data and
    /// `endstream`; the encryption dictionary names the page when `named`. Whether the page is
    /// unsure.
    fn encrypted_page_in_a_stream(named: bool) -> impl Fn(&str, &str, bool) -> bool {
        let mut d = Document::with_version("1.7");
        let pages = d.new_object_id();
        let page = d.add_object(dictionary! { "Type" => "Page", "Parent" => pages });
        let kids = dictionary! { "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1 };
        d.objects.insert(pages, Object::Dictionary(kids));
        let root = d.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        d.trailer.set("Root", root);
        let encrypt = encrypt_with_identity(&mut d);
        if named {
            let e = d.get_object_mut(encrypt).unwrap().as_dict_mut().unwrap();
            e.set("X", Object::Array(vec![page.into()]));
        }
        let mut base = Vec::new();
        d.save_to(&mut base).unwrap();
        let prev = Document::load_mem(&base).unwrap().xref_start;
        move |end: &str, framing: &str, typed: bool| {
            let (n, x) = (d.max_id + 1, d.max_id + 2);
            let index = format!("{} 0\n", page.0);
            let body = format!("<< /Type /Page /Parent {} 0 R >>{end}", pages.0);
            let mut b = [&base[..], b"\n"].concat();
            let at_c = b.len();
            let kind = if typed { "/Type /ObjStm " } else { "" };
            b.extend_from_slice(
                format!(
                    "{n} 0 obj\n<< {kind}/N 1 /First {} /Length {} >>\nstream\n\
                     {index}{body}{framing}endstream\nendobj\n",
                    index.len(),
                    index.len() + body.len()
                )
                .as_bytes(),
            );
            let at = b.len();
            let row = |kind: u8, f1: usize| {
                [
                    &[kind][..],
                    &u32::try_from(f1).unwrap().to_be_bytes(),
                    &[0, 0],
                ]
                .concat()
            };
            let rows = [row(2, n as usize), row(1, at_c), row(1, at)].concat();
            b.extend_from_slice(
                format!(
                    "{x} 0 obj\n<< /Type /XRef /W [1 4 2] /Index [{} 1 {n} 2] /Size {} \
                     /Root {} 0 R /Encrypt {} 0 R /ID [<{id}> <{id}>] /Prev {prev} \
                     /Length {} >>\nstream\n",
                    page.0,
                    x + 1,
                    root.0,
                    encrypt.0,
                    rows.len(),
                    id = "07".repeat(16)
                )
                .as_bytes(),
            );
            b.extend_from_slice(&rows);
            b.extend_from_slice(
                format!("\nendstream\nendobj\nstartxref\n{at}\n%%EOF\n").as_bytes(),
            );
            let read = Document::load_mem(&b).unwrap();
            assert!(read.encryption_state.is_some());
            compare_reading(&b, &read).unwrap().unsure.contains(&page.0)
        }
    }

    /// Flate data decodes alike only with predictor values every app takes the same way,
    /// written directly, and without the abbreviated keys some apps read as `/Filter`.
    #[test]
    fn decode_parms_decode_alike_only_in_range() {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"1 0 2 0").unwrap();
        let z = z.finish().unwrap();
        let alike = |entries: Vec<(&str, Object)>| {
            let mut d = Dictionary::new();
            d.set("Filter", Object::Name(b"FlateDecode".to_vec()));
            for (k, v) in entries {
                d.set(k, v);
            }
            decodes_alike(&Stream::new(d, z.clone()), 1 << 10)
        };
        let parms = |pairs: &[(&str, Object)]| {
            let mut d = Dictionary::new();
            for (k, v) in pairs {
                d.set(*k, v.clone());
            }
            Object::Dictionary(d)
        };
        let int = Object::Integer;
        let png = |more: &[(&str, Object)]| {
            parms(
                &[
                    [("Predictor", int(12)), ("Columns", int(5))].as_slice(),
                    more,
                ]
                .concat(),
            )
        };
        assert!(alike(vec![]));
        assert!(alike(vec![("DecodeParms", Object::Null)]));
        assert!(alike(vec![("DecodeParms", png(&[]))]));
        let in_array = || {
            (
                "Filter",
                Object::Array(vec![Object::Name(b"FlateDecode".to_vec())]),
            )
        };
        assert!(alike(vec![in_array()]));
        assert!(alike(vec![
            in_array(),
            ("DecodeParms", Object::Array(vec![png(&[])]))
        ]));
        assert!(alike(vec![
            in_array(),
            ("DecodeParms", Object::Array(vec![Object::Null]))
        ]));
        // Poppler takes parameters for a filter in an array only from an array, and for a
        // filter on its own only from a dictionary.
        assert!(!alike(vec![in_array(), ("DecodeParms", png(&[]))]));
        for bad in [
            vec![],
            vec![png(&[]), png(&[])],
            vec![Object::Reference((9, 0))],
            vec![Object::Integer(12)],
        ] {
            let bad = Object::Array(bad);
            assert!(
                !alike(vec![in_array(), ("DecodeParms", bad.clone())]),
                "{bad:?}"
            );
        }
        assert!(!alike(vec![("DecodeParms", Object::Array(vec![png(&[])]))]));
        for p in [1, 10, 15] {
            assert!(
                alike(vec![("DecodeParms", parms(&[("Predictor", int(p))]))]),
                "{p}"
            );
        }
        assert!(alike(vec![(
            "DecodeParms",
            png(&[("Colors", int(32)), ("BitsPerComponent", int(16))])
        )]));
        // As if left out, as lopdf and Poppler read it.
        assert!(alike(vec![(
            "DecodeParms",
            png(&[("Colors", Object::Null)])
        )]));
        // lopdf and some app take these differently (Poppler takes references and drops the
        // predictor for values out of its range, pdf.js takes 12.0 as 12 and fails on
        // predictor 3), or the spec doesn't allow them (3 bits). Poppler and pdf.js decode
        // the TIFF predictor differently from lopdf at some widths.
        for bad in [
            parms(&[("Predictor", int(2))]),
            parms(&[("Predictor", int(2)), ("BitsPerComponent", int(16))]),
            Object::Reference((9, 0)),
            Object::Integer(12),
            Object::Array(vec![]),
            Object::Array(vec![png(&[]), png(&[])]),
            Object::Array(vec![Object::Reference((9, 0))]),
            parms(&[("Predictor", int(3))]),
            parms(&[("Predictor", int(16))]),
            parms(&[("Predictor", Object::Real(12.0))]),
            parms(&[("Predictor", Object::Reference((9, 0)))]),
            png(&[("Colors", int(0))]),
            png(&[("Colors", int(33))]),
            png(&[("BitsPerComponent", int(3))]),
            png(&[("BitsPerComponent", int(0))]),
            png(&[("Columns", int(0))]),
            png(&[("Columns", int(i64::from(i32::MAX)))]),
        ] {
            assert!(!alike(vec![("DecodeParms", bad.clone())]), "{bad:?}");
        }
        // Read by some apps as /Filter and /DecodeParms.
        assert!(!alike(vec![("F", Object::Name(b"FlateDecode".to_vec()))]));
        assert!(!alike(vec![("DP", png(&[]))]));
        assert!(!alike(vec![(
            "FFilter",
            Object::Name(b"FlateDecode".to_vec())
        )]));
        assert!(!alike(vec![("FDecodeParms", png(&[]))]));
        // Without /Filter, an abbreviation, or parameters for no filter.
        for (k, v) in [
            ("F", Object::Name(b"FlateDecode".to_vec())),
            ("DecodeParms", png(&[])),
        ] {
            let mut d = Dictionary::new();
            d.set(k, v);
            assert!(
                !decodes_alike(&Stream::new(d, b"1 0 2 0".to_vec()), 1 << 10),
                "{k}"
            );
        }
    }

    /// Poppler reads `N G R` in drawn data as a reference however the three are written apart
    /// or together, from whole numbers in range before `R` alone; a number or word ends with
    /// the stream it is written in, white space, comments and strings run on into the next.
    /// In a string, a comment or a name there is none, nor in a word, but in a word's 129th
    /// character on; from an inline image on, wherever a number may start.
    #[test]
    fn references_in_drawn_data_are_read_as_poppler_reads_them() {
        let refs = |data: &str, breaks: &[usize]| {
            let mut out = BTreeSet::new();
            assert!(data_references(data.as_bytes(), breaks, &mut out, 2));
            Vec::from_iter(out)
        };
        let one = |data: &str| refs(data, &[]);
        for data in [
            "5 0 R",
            "5 0R",
            "5+0R",
            "5 -0 R",
            "5 - R",
            "5-R",
            "5 0 %c\nR",
            "5 %c\r0\tR",
            "05 +0 R\n",
            "+5 0 R",
            "5 0 R/x",
            "5 0 R(",
            "5\x0c0\0R",
            "x 5 0 R ",
            "1.5 5 0 R",
        ] {
            assert_eq!(one(data), [(5, 0)], "{data:?}");
        }
        assert_eq!(one("1 2 3 R"), [(2, 3)]);
        assert_eq!(one("5 7 R 6 0 R"), [(5, 7), (6, 0)]);
        assert_eq!(one("2147483647 70000 R"), [(i32::MAX as u32, u16::MAX)]);
        // Not in a string (however it nests or escapes), a hex string, a comment, a name or a
        // word.
        for data in [
            "(5 0 R)",
            "(a(b)5 0 R)",
            "(\\)5 0 R)",
            "(\x001\x003\x00 \x00R)",
            "(\\",
            "<5 0 R>",
            "% 5 0 R",
            "/F5 0 R",
            "x5 0 R",
        ] {
            assert_eq!(one(data), [], "{data:?}");
        }
        assert_eq!(one("(x)5 0 R"), [(5, 0)]);
        assert_eq!(one("% (\n5 0 R"), [(5, 0)]);
        assert_eq!(one("<<5 0 R>>"), [(5, 0)]);
        // A name's escape takes the character after its first digit, whatever it is.
        assert_eq!(one("/a#4( 5 0 R"), [(5, 0)]);
        // A word is cut after 128 characters.
        assert_eq!(one(&format!("{}5 0 R", "x".repeat(128))), [(5, 0)]);
        assert_eq!(one(&format!("{}5 0 R", "x".repeat(127))), []);
        // From an inline image on (where Poppler reads on is found as it decodes the image),
        // wherever a number may start.
        for data in ["(x) BI (5 0 R)", "ID (5 0 R)", "BI/F5 0 R"] {
            assert_eq!(one(data), [(5, 0)], "{data:?}");
        }
        assert_eq!(one("/ID (BI) (5 0 R)"), []);
        for data in [
            "5 0 RG",
            "5 0. R",
            "5. 0 R",
            "5 0.5 R",
            "5.0 0 R",
            "0 0 R",
            "-5 0 R",
            "5 -1 R",
            "2147483648 0 R",
            "-2147483648 0 R",
            "5 0 (x) R",
            "5 0",
            "5 R",
            "5 0 R5",
            "5 0 %R",
            "R",
            "",
        ] {
            assert_eq!(one(data), [], "{data:?}");
        }
        // In parts: a number or `R` ends with its part, a comment or a string runs on, and `<`
        // ending one starts a hex string.
        assert_eq!(refs("50 R", &[0, 1]), [(5, 0)]);
        assert_eq!(refs("56 0 R", &[0, 1]), [(6, 0)]);
        assert_eq!(refs("5 0 RG", &[0, 5]), [(5, 0)]);
        assert_eq!(refs("5 0 %cx\nR", &[0, 6]), [(5, 0)]);
        assert_eq!(refs("(a5 0 R)", &[0, 2]), []);
        assert_eq!(refs("<<5 0 R> 6 0 R", &[0, 1]), [(6, 0)]);
        // Each once, and no more than asked for.
        assert_eq!(one("5 0 R 5 0 R 6 0 R 6 0 R"), [(5, 0), (6, 0)]);
        let mut out = BTreeSet::new();
        assert!(!data_references(b"5 0 R 6 0 R 7 0 R", &[], &mut out, 2));
    }

    /// What the catalog leads to draws as other apps draw it: a page's content (its streams
    /// read as one), an annotation's appearances, a Type 3 font's glyphs, a soft mask's
    /// group, a form and a tiling pattern; the references in its data are followed. A
    /// picture's data and a form nothing leads to aren't read; a drawing LimarePDF can't
    /// decode, or every drawing past the steps, is unread; one drawn twice is read once.
    #[test]
    fn references_in_what_is_drawn_are_followed() {
        let r = |id: u32| Object::Reference((id, 0));
        let mut doc = Document::with_version("1.7");
        let mut add = |id: u32, dict: Dictionary, data: &str| {
            let s = Stream::new(dict, data.as_bytes().to_vec());
            doc.objects.insert((id, 0), Object::Stream(s));
        };
        add(3, Dictionary::new(), "100 0");
        add(4, Dictionary::new(), " R");
        add(5, Dictionary::new(), "101 0 R");
        add(6, Dictionary::new(), "102 0 R");
        add(7, Dictionary::new(), "103 0 R");
        add(8, Dictionary::new(), "104 0 R");
        add(9, dictionary! { "Subtype" => "Form" }, "105 0 R");
        add(10, dictionary! { "PatternType" => 1 }, "106 0 R");
        add(11, dictionary! { "Subtype" => "Image" }, "107 0 R");
        add(12, dictionary! { "Subtype" => "Form" }, "108 0 R");
        add(13, dictionary! { "Filter" => "JBIG2Decode" }, "x");
        add(14, dictionary! { "Subtype" => r(20) }, "110 0 R");
        doc.objects.insert((20, 0), Object::Name(b"Form".to_vec()));
        doc.objects
            .insert((105, 0), dictionary! { "Next" => r(109) }.into());
        let root = dictionary! {
            "Contents" => vec![r(3), r(4)],
            "AP" => dictionary! { "N" => r(5), "D" => dictionary! { "On" => r(6) }, "R" => r(13) },
            "CharProcs" => dictionary! { "a" => r(7) },
            "G" => r(8),
            "X" => vec![r(9), r(10), r(11), r(14)],
        };
        doc.objects.insert((1, 0), root.into());
        doc.trailer.set("Root", r(1));
        let all = reached_within(&doc, &DRAWN);
        let drawn: BTreeSet<u32> = all.drawn.iter().map(|id| id.0).collect();
        assert_eq!(drawn, (100..=106).chain([110]).collect());
        assert!(all.ids.contains(&(109, 0)));
        assert!(!all.ids.contains(&(107, 0)) && !all.ids.contains(&(108, 0)));
        assert_eq!(all.unread, BTreeSet::from([(13, 0)]));
        let none = reached_within(&doc, &Within { steps: 0, ..DRAWN });
        assert!(none.drawn.is_empty());
        let every = (3..=10).chain([13, 14]).map(|n| (n, 0)).collect();
        assert_eq!(none.unread, every);
        // References from 8 drawings, one past 7.
        let fewer = reached_within(&doc, &Within { refs: 7, ..DRAWN });
        assert_eq!((fewer.drawn.len(), fewer.unread.len()), (7, 2));
        // A form drawn as an appearance and as a form: 7 bytes, and a reference, read once.
        let mut doc = Document::with_version("1.7");
        let s = Stream::new(dictionary! { "Subtype" => "Form" }, b"105 0 R".to_vec());
        doc.objects.insert((9, 0), Object::Stream(s));
        let root = dictionary! { "AP" => dictionary! { "N" => r(9) } };
        doc.objects.insert((1, 0), root.into());
        doc.trailer.set("Root", r(1));
        let unread = |steps, data, refs| reached_within(&doc, &Within { steps, data, refs }).unread;
        assert!(unread(7, 7, 1).is_empty());
        for (steps, data, refs) in [(6, 7, 1), (7, 6, 1), (7, 7, 0)] {
            let why = format!("{steps} {data} {refs}");
            assert_eq!(unread(steps, data, refs), BTreeSet::from([(9, 0)]), "{why}");
        }
    }

    /// A drawing is decoded as Poppler reads its filters: by their short names, through
    /// references, from `/F` and `/DP` where `/Filter` and `/DecodeParms` are missing, with
    /// settings for several filters only from a list; a filter in a list that isn't a name
    /// leaves nothing, an empty list the data as written. One whose `/Filter` and `/F`, or
    /// `/DecodeParms` and `/DP`, differ, which pdf.js reads the other way round, is unread.
    #[test]
    fn a_drawing_is_decoded_as_poppler_reads_its_filters() {
        use std::io::Write;
        let r = |id: u32| Object::Reference((id, 0));
        let hex = |s: &str| {
            let hex: String = s.bytes().map(|b| format!("{b:02x}")).collect();
            format!("{hex}>").into_bytes()
        };
        let flate = |data: &[u8]| {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(data).unwrap();
            z.finish().unwrap()
        };
        let mut doc = Document::with_version("1.7");
        doc.objects.insert((20, 0), Object::Name(b"AHx".to_vec()));
        doc.objects
            .insert((21, 0), Object::Name(b"ASCIIHexDecode".to_vec()));
        doc.objects.insert((22, 0), Object::Integer(12));
        let (up, direct, wider) = (
            dictionary! { "Predictor" => r(22), "Columns" => 5 },
            dictionary! { "Predictor" => 12, "Columns" => 5 },
            dictionary! { "Predictor" => r(22), "Columns" => 6 },
        );
        let names = |n: &[&str]| n.iter().map(|&n| Object::from(n)).collect::<Vec<_>>();
        let forms = [
            (dictionary! { "Filter" => "AHx" }, hex("5 0 R")),
            (dictionary! { "F" => "AHx" }, hex("6 0 R")),
            (dictionary! { "Filter" => r(20) }, hex("7 0 R")),
            (dictionary! { "Filter" => vec![r(21)] }, hex("8 0 R")),
            // Each row of predicted data starts with its predictor, here 2.
            (
                dictionary! { "Filter" => "Fl", "DP" => up },
                flate(b"\x029 0 R"),
            ),
            (
                dictionary! { "Filter" => names(&["FlateDecode"]), "DecodeParms" => direct },
                flate(b"10 0 R"),
            ),
            (
                dictionary! { "Filter" => vec!["AHx".into(), 1.into()] },
                b"11 0 R".to_vec(),
            ),
            (
                dictionary! { "Filter" => "ASCIIHexDecode", "F" => "FlateDecode" },
                hex("12 0 R"),
            ),
            (
                dictionary! { "Filter" => "ASCIIHexDecode", "DecodeParms" => dictionary! {},
                "DP" => dictionary! { "Predictor" => 1 } },
                hex("13 0 R"),
            ),
            (
                dictionary! { "Filter" => names(&["FlateDecode"]), "DecodeParms" => vec![wider.into()] },
                flate(b"\x0214 0 R"),
            ),
            (dictionary! { "Filter" => names(&[]) }, b"15 0 R".to_vec()),
        ];
        let mut drawn = Vec::new();
        for (i, (mut d, data)) in forms.into_iter().enumerate() {
            d.set("Subtype", "Form");
            let id = (30 + i as u32, 0);
            doc.objects.insert(id, Object::Stream(Stream::new(d, data)));
            drawn.push(Object::Reference(id));
        }
        doc.objects
            .insert((1, 0), dictionary! { "X" => drawn }.into());
        doc.trailer.set("Root", r(1));
        let all = reached(&doc);
        let drawn: BTreeSet<u32> = all.drawn.iter().map(|id| id.0).collect();
        assert_eq!(drawn, (5..=10).chain([14, 15]).collect());
        assert_eq!(all.unread, BTreeSet::from([(37, 0), (38, 0)]));
    }
}
