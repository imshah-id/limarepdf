//! Annotations: comments, notes and markup on pages. Reading them, removing them, and
//! flattening them into the page content. Links, form widgets and popups have their own
//! code and are not listed here.

use crate::annot_ap::{self, drawable, Place, DRAWN, MAX_POINTS};
use crate::budget::{TooComplex, Work};
use crate::doc::decode_text;
use crate::form_flatten::{self, Flat};
use crate::matrix as mx;
use crate::sanitise::Layers;
use crate::{Align, Pdf, Result};
use anyhow::{anyhow, bail};
use lopdf::{Dictionary, Object, ObjectId};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// How many of a page's annotations are shown, a limit that keeps a malformed or hostile
/// file from running away. Removing information reads them all.
pub const MAX_ANNOTS: usize = 10_000;

/// Most bytes of a date (`/M`, `/CreationDate`) read: one written in full as UTF-16 takes
/// 48.
const MAX_DATE: usize = 64;

/// What [`Pdf::flatten_annotations`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flattened {
    /// How many annotations were drawn into the pages.
    pub drawn: usize,
    /// The page (zero-based) of each annotation left as it was because LimarePDF can't
    /// draw it, in page order.
    pub kept: Vec<usize>,
}

/// Annotation flags (`/F`).
const HIDDEN: i64 = 1 << 1;
const PRINT: i64 = 1 << 2;
pub(crate) const NO_VIEW: i64 = 1 << 5;
const READ_ONLY: i64 = 1 << 6;
const LOCKED: i64 = 1 << 7;

/// Whether an annotation with flags `flags` is shown on screen: neither Hidden nor NoView.
pub(crate) fn on_screen(flags: i64) -> bool {
    flags & (HIDDEN | NO_VIEW) == 0
}

/// Whether an annotation with flags `flags` is printed: Print set and Hidden clear. NoView
/// is about the screen alone.
pub(crate) fn prints(flags: i64) -> bool {
    flags & PRINT != 0 && flags & HIDDEN == 0
}

/// What kind of annotation it is (its `/Subtype`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AnnotKind {
    Highlight,
    Underline,
    StrikeOut,
    Squiggly,
    /// A sticky note (`/Text`).
    Note,
    /// Text written on the page (`/FreeText`).
    TextBox,
    Square,
    Circle,
    Line,
    Polygon,
    PolyLine,
    /// Freehand drawing (`/Ink`).
    Ink,
    Stamp,
    /// An area marked for redaction (`/Redact`), not yet applied.
    Redact,
    /// Any other subtype, as the file names it.
    Other(String),
}

impl AnnotKind {
    /// The kind for a subtype; `None` for links, form widgets and popups.
    fn of(subtype: &[u8]) -> Option<Self> {
        Some(match subtype {
            b"Link" | b"Widget" | b"Popup" => return None,
            b"Highlight" => Self::Highlight,
            b"Underline" => Self::Underline,
            b"StrikeOut" => Self::StrikeOut,
            b"Squiggly" => Self::Squiggly,
            b"Text" => Self::Note,
            b"FreeText" => Self::TextBox,
            b"Square" => Self::Square,
            b"Circle" => Self::Circle,
            b"Line" => Self::Line,
            b"Polygon" => Self::Polygon,
            b"PolyLine" => Self::PolyLine,
            b"Ink" => Self::Ink,
            b"Stamp" => Self::Stamp,
            b"Redact" => Self::Redact,
            other => Self::Other(String::from_utf8_lossy(other).into_owned()),
        })
    }

    /// A short lowercase name, as the command line takes and shows it.
    pub fn name(&self) -> &str {
        match self {
            Self::Highlight => "highlight",
            Self::Underline => "underline",
            Self::StrikeOut => "strikeout",
            Self::Squiggly => "squiggly",
            Self::Note => "note",
            Self::TextBox => "textbox",
            Self::Square => "square",
            Self::Circle => "circle",
            Self::Line => "line",
            Self::Polygon => "polygon",
            Self::PolyLine => "polyline",
            Self::Ink => "ink",
            Self::Stamp => "stamp",
            Self::Redact => "redact",
            Self::Other(s) => s,
        }
    }

    /// The kind for a name from [`AnnotKind::name`] (any case). A subtype LimarePDF doesn't
    /// list, such as `FileAttachment`, is taken as it is.
    pub fn parse(s: &str) -> Self {
        let known = [
            Self::Highlight,
            Self::Underline,
            Self::StrikeOut,
            Self::Squiggly,
            Self::Note,
            Self::TextBox,
            Self::Square,
            Self::Circle,
            Self::Line,
            Self::Polygon,
            Self::PolyLine,
            Self::Ink,
            Self::Stamp,
            Self::Redact,
        ];
        let lower = s.to_ascii_lowercase();
        known
            .into_iter()
            .find(|k| k.name() == lower)
            .unwrap_or_else(|| Self::Other(s.to_string()))
    }

    /// A label for people: "Highlight", "Note", "Text box".
    pub fn label(&self) -> String {
        match self {
            Self::StrikeOut => "Strike-out".into(),
            Self::TextBox => "Text box".into(),
            Self::PolyLine => "Polyline".into(),
            Self::Ink => "Drawing".into(),
            Self::Redact => "Redaction mark".into(),
            Self::Other(s) => s.clone(),
            k => {
                let n = k.name();
                n[..1].to_ascii_uppercase() + &n[1..]
            }
        }
    }
}

/// One annotation on a page.
#[derive(Clone, Debug, PartialEq)]
pub struct Annot {
    /// The annotation's object in the file; stays the same while the document is open.
    pub id: (u32, u16),
    /// The page it is on (zero-based).
    pub page: usize,
    pub kind: AnnotKind,
    /// Its area in displayed-page points (y down), like [`crate::PageObject::bbox`].
    pub bbox: [f32; 4],
    /// For text markup, the box around each marked line, in the same points; empty for
    /// other kinds.
    pub quads: Vec<[f32; 4]>,
    /// Its colour as RGB (grey and CMYK are converted), if it has one.
    pub color: Option<[f32; 3]>,
    /// 0 (invisible) to 1 (opaque).
    pub opacity: f32,
    /// The comment.
    pub contents: String,
    /// Who made it (`/T`).
    pub author: String,
    pub subject: String,
    /// Its icon name (`/Name`), for stamps, notes and attachments; empty when none.
    pub name: String,
    /// When it was last changed, as `YYYY-MM-DD HH:MM`, or empty when unknown.
    pub modified: String,
    /// The annotation flags (`/F`).
    pub flags: i64,
    /// In a layer that's off, or that a layer rule hides while the layers are as the
    /// document opens: not shown, as if hidden.
    pub layer_off: bool,
    /// The comment this one replies to (`/IRT`).
    pub reply_to: Option<(u32, u16)>,
    /// Whether the file has a drawing for it. LimarePDF draws the common kinds itself when
    /// not, on screen and when printing.
    pub has_appearance: bool,
    /// For text boxes, how the text is set; `None` for other kinds.
    pub text_style: Option<TextStyle>,
    /// For rectangles, ellipses, lines and drawings, how they are painted; `None` for
    /// other kinds.
    pub shape: Option<ShapeLook>,
    /// For lines, polylines and drawings, their points in displayed-page points, one list
    /// per stroke; empty for other kinds.
    pub paths: Vec<Vec<(f32, f32)>>,
    /// Listed past the budget for reading the annotations ([`crate::TooComplex`]): its
    /// text, points and text style weren't read, and are empty (`None` for the style). It
    /// is shown, and can be selected, moved and deleted, but its text can't be changed.
    pub unread: bool,
}

/// How a rectangle, ellipse, line or drawing is painted. Its line's colour is the
/// annotation's colour.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShapeLook {
    /// The inside of a rectangle or ellipse (none when transparent).
    pub fill: Option<[f32; 3]>,
    /// The line's width in points.
    pub width: f32,
    /// A line has an arrowhead at its end.
    pub arrow: bool,
}

impl Default for ShapeLook {
    fn default() -> Self {
        Self {
            fill: None,
            width: 1.0,
            arrow: false,
        }
    }
}

/// How a text box's text is set: Helvetica at `size` points in `color`, on `fill` (none
/// when transparent), with a border `border` points wide in the text colour (0 for none),
/// its lines aligned left, centred or right (its `/Q`). A PDF text box can't keep justified
/// text: [`Align::Justified`] is written left.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TextStyle {
    pub size: f32,
    pub color: [f32; 3],
    pub fill: Option<[f32; 3]>,
    pub border: f32,
    pub align: Align,
}

impl Default for TextStyle {
    fn default() -> Self {
        Self {
            size: 12.0,
            color: [0.0; 3],
            fill: None,
            border: 0.0,
            align: Align::Left,
        }
    }
}

impl Annot {
    /// A label for people: its kind, or "Signature", "Initials", "Tick" and so on for
    /// LimarePDF's fill-and-sign stamps.
    pub fn label(&self) -> String {
        match crate::sign_label(&self.name) {
            Some(l) if self.kind == AnnotKind::Stamp => l.into(),
            _ => self.kind.label(),
        }
    }

    /// Flagged Hidden, or in a layer that's off.
    pub fn hidden(&self) -> bool {
        self.flags & HIDDEN != 0 || self.layer_off
    }

    /// Whether it is shown on the page: not hidden and not a reply, which is listed with
    /// the comment it answers.
    pub fn on_page(&self) -> bool {
        self.flags & (HIDDEN | NO_VIEW) == 0 && !self.layer_off && self.reply_to.is_none()
    }

    /// Locked or read-only: it may not be moved, changed or deleted in the app.
    pub fn locked(&self) -> bool {
        self.flags & (LOCKED | READ_ONLY) != 0
    }
}

impl Pdf {
    /// The annotations on every page, page by page in the file's order, each once, on the
    /// first page that lists it (each page still shows it, [`Pdf::page_annotations`]): the
    /// first [`MAX_ANNOTS`] of each page's list. Those placed where they are drawn (PB-114)
    /// are drawn within one budget ([`crate::TooComplex`]); past it, each is placed at its
    /// own `/Rect`. The lists' entries are looked at, and their points and text read, within
    /// another; past it, each is listed [`Annot::unread`].
    pub fn annotations(&self) -> Vec<Annot> {
        self.listed(&mut Place::drawn())
    }

    /// [`Pdf::annotations`], placed and read by `place`.
    pub(crate) fn listed(&self, place: &mut Place) -> Vec<Annot> {
        self.every_annotation_in(place, MAX_ANNOTS)
    }

    /// The annotations pages `pages` (zero-based) list, each list read once: for choosing by
    /// page what [`Pdf::annotations`] lists, each on the first page that lists it.
    pub fn annotation_ids_on(&self, pages: &[usize]) -> Result<HashSet<(u32, u16)>> {
        let ids = self.page_ids();
        let on: Vec<ObjectId> = (self.page_list(Some(pages))?.into_iter())
            .map(|i| ids[i])
            .collect();
        Ok(self.listed_annots(&on).into_iter().map(|a| a.1).collect())
    }

    /// Annotation `id` as [`Pdf::annotations`] lists it (on the first page that does), but
    /// read alone: placed and read within budgets of its own, reading no other annotation.
    pub fn annotation(&self, id: (u32, u16)) -> Result<Annot> {
        self.listed_one(id, &mut Place::drawn())
    }

    /// [`Pdf::annotation`], placed and read by `place`.
    pub(crate) fn listed_one(&self, id: ObjectId, place: &mut Place) -> Result<Annot> {
        let pages = self.page_ids();
        let lists = |(_, _, list): &(usize, _, &[Object])| {
            (list.iter().take(MAX_ANNOTS)).any(|o| o.as_reference().ok() == Some(id))
        };
        let (i, _, _) = (self.each_annots(&pages))
            .find(lists)
            .ok_or_else(|| anyhow!("no such annotation"))?;
        let mut layers = self.layers_off();
        let one = self.annotations_in(i, pages[i], vec![id], &mut layers, place)?;
        one.into_iter()
            .next()
            .ok_or_else(|| anyhow!("no such annotation"))
    }

    /// The annotations on one page (zero-based), in the file's order (the order they are
    /// drawn in), placed and read as [`Pdf::annotations`] places and reads them.
    pub fn page_annotations(&self, page_index: usize) -> Result<Vec<Annot>> {
        let page = self.page_id_at(page_index)?;
        let list = self.annots_array(page).unwrap_or_default();
        let list = &list[..list.len().min(MAX_ANNOTS)];
        let mut place = Place::drawn();
        place.look(list.len());
        let refs = list.iter().filter_map(|o| o.as_reference().ok()).collect();
        let mut layers = self.layers_off();
        self.annotations_in(page_index, page, refs, &mut layers, &mut place)
    }

    /// Every annotation, each once, on the first page that lists it, without
    /// [`MAX_ANNOTS`], placed by `place`: for removing information, where one left out could
    /// keep what should go.
    pub(crate) fn every_annotation(&self, place: &mut Place) -> Vec<Annot> {
        self.every_annotation_in(place, usize::MAX)
    }

    /// The annotations the pages list, the first `most` of each list, each once, on the
    /// first page that lists it, placed by `place`. Each list is read once however many
    /// pages share it, its entries looked at within the reading budget ([`Place::look`]);
    /// none is built once `place` is done.
    fn every_annotation_in(&self, place: &mut Place, most: usize) -> Vec<Annot> {
        let placed = self.placed_pages();
        let pages: Vec<ObjectId> = placed.iter().map(|p| p.1).collect();
        let mut layers = self.layers_off();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (k, _, list) in self.each_annots(&pages) {
            let (i, _, to_vis) = placed[k];
            let list = &list[..list.len().min(most)];
            place.look(list.len());
            for id in list.iter().filter_map(|o| o.as_reference().ok()) {
                if place.done() {
                    return out;
                }
                if seen.insert(id) {
                    out.extend(self.annot(id, i, to_vis, &mut layers, place));
                }
            }
        }
        out
    }

    /// Every redaction mark, on each page that lists it, without [`MAX_ANNOTS`], placed by
    /// `place`: a mark several pages list is applied on each. Each list's entries are looked
    /// at once however many pages share it, within the reading budget ([`Place::look`]),
    /// and only marks are built; a page whose list was looked at before is charged a step
    /// for each of its marks, each placed there again. None is built once `place` is done.
    pub(crate) fn every_mark(&self, place: &mut Place) -> Vec<Annot> {
        let mut layers = self.layers_off();
        let mut found: HashMap<ObjectId, Rc<[ObjectId]>> = HashMap::new();
        let mut out = Vec::new();
        for (i, page, to_vis) in self.placed_pages() {
            let Some((at, list)) = self.annots_at(page) else {
                continue;
            };
            let marks = match at.and_then(|at| found.get(&at)) {
                Some(marks) => {
                    place.look(marks.len());
                    marks.clone()
                }
                None => {
                    place.look(list.len());
                    #[cfg(test)]
                    tests::ENTRIES_READ.set(tests::ENTRIES_READ.get() + list.len());
                    let marks: Rc<[ObjectId]> = (list.iter())
                        .filter_map(|o| o.as_reference().ok())
                        .filter(|&id| {
                            self.doc.get_dictionary(id).is_ok_and(|d| {
                                d.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Redact")
                            })
                        })
                        .collect();
                    if let Some(at) = at {
                        found.insert(at, marks.clone());
                    }
                    marks
                }
            };
            for &id in marks.iter() {
                if place.done() {
                    return out;
                }
                out.extend(self.annot(id, i, to_vis, &mut layers, place));
            }
        }
        out
    }

    /// The annotations `refs` of page `page`, number `page_index` (zero-based), placed by
    /// `place`, and whether each is in a layer `layers` hide. The page is given, not looked
    /// up by number again: its callers have it.
    fn annotations_in(
        &self,
        page_index: usize,
        page: ObjectId,
        refs: Vec<ObjectId>,
        layers: &mut Option<Layers>,
        place: &mut Place,
    ) -> Result<Vec<Annot>> {
        let (vd, _, _) = self.vis_down(page);
        let to_vis = mx::inv(vd).ok_or_else(|| anyhow!("degenerate page transform"))?;
        Ok(refs
            .into_iter()
            .filter_map(|id| self.annot(id, page_index, to_vis, layers, place))
            .collect())
    }

    /// The pages (zero-based) with more annotations than are shown ([`MAX_ANNOTS`]).
    pub fn pages_past_annotation_limit(&self) -> Vec<usize> {
        let ids = self.page_ids();
        (0..ids.len())
            .filter(|&i| {
                self.annots_array(ids[i])
                    .is_some_and(|a| a.len() > MAX_ANNOTS)
            })
            .collect()
    }

    /// The pages (zero-based) annotations `ids` are on, by the first page that lists each:
    /// `None` for one no page lists. One walk of the page tree, however many are asked, with
    /// each list read once ([`Pdf::each_annots`]).
    pub fn annotation_pages(&self, ids: &[(u32, u16)]) -> Vec<Option<usize>> {
        let mut out = vec![None; ids.len()];
        let mut wanted: HashMap<ObjectId, Vec<usize>> = HashMap::new();
        for (k, &id) in ids.iter().enumerate() {
            wanted.entry(id).or_default().push(k);
        }
        let pages = self.page_ids();
        for (i, _, list) in self.each_annots(&pages) {
            for id in list.iter().filter_map(|o| o.as_reference().ok()) {
                for k in wanted.remove(&id).unwrap_or_default() {
                    out[k] = Some(i);
                }
            }
            if wanted.is_empty() {
                break;
            }
        }
        out
    }

    /// Give annotations written into a page's `/Annots` directly, which the format doesn't
    /// allow, objects of their own, so that removing information finds them like any other.
    /// How they look and what they hold is unchanged, and pages sharing a list keep sharing
    /// it.
    pub(crate) fn own_direct_annots(&mut self) -> Result<()> {
        let pages = self.page_ids();
        let direct: Vec<(ObjectId, Option<ObjectId>, Vec<Object>)> = (self.each_annots(&pages))
            .filter(|(_, _, list)| list.iter().any(|o| o.as_dict().is_ok()))
            .map(|(i, at, list)| (pages[i], at, list.to_vec()))
            .collect();
        for (page, at, list) in direct {
            let list: Vec<Object> = list
                .into_iter()
                .map(|o| match o {
                    Object::Dictionary(d) => Object::Reference(self.doc.add_object(d)),
                    o => o,
                })
                .collect();
            match at {
                Some(at) => *self.doc.get_object_mut(at)? = Object::Array(list),
                None => self.doc.get_dictionary_mut(page)?.set("Annots", list),
            }
        }
        Ok(())
    }

    /// Remove the annotations `pick` chooses, with the replies to them and their popups;
    /// `pages` (zero-based) limits this to those any of these pages list. Locked ones are
    /// removed too; the app checks [`Annot::locked`] first. Every annotation is offered to
    /// `pick` once, as [`Pdf::every_annotation`] lists it, not only those shown, each at
    /// its own `/Rect`: none is drawn to place it. Each is read, for `pick` to choose by
    /// what it says: refused, with nothing changed, past the budget for reading them
    /// ([`crate::TooComplex`]), none read past it. Returns how many were removed, replies
    /// included.
    pub fn remove_annotations(
        &mut self,
        pages: Option<&[usize]>,
        pick: impl Fn(&Annot) -> bool,
    ) -> Result<usize> {
        self.atomically(|p| {
            p.own_direct_annots()?;
            let on = pages.map(|pages| p.annotation_ids_on(pages)).transpose()?;
            let mut place = Place::own().stopping();
            let all = p.every_annotation(&mut place);
            place.whole()?;
            let gone = (all.iter())
                .filter(|a| on.as_ref().is_none_or(|on| on.contains(&a.id)) && pick(a))
                .map(|a| a.id)
                .collect();
            p.drop_annotations(gone)
        })
    }

    /// Remove annotation `id`, with the replies to it and their popups, reading no other
    /// annotation; with nothing changed when it fails. Returns how many were removed,
    /// replies included.
    pub fn remove_annotation(&mut self, id: (u32, u16)) -> Result<usize> {
        self.atomically(|p| p.drop_annotations(HashSet::from([id])))
    }

    /// Remove the annotations `gone` (of any kind, links and form widgets too), with the
    /// replies to them and their popups. Returns how many were removed, replies included.
    pub(crate) fn drop_annotations(&mut self, gone: HashSet<ObjectId>) -> Result<usize> {
        Ok(self.drop_annotations_ids(gone)?.0)
    }

    /// As [`Pdf::drop_annotations`]: how many were removed, and the annotations removed,
    /// popups too.
    pub(crate) fn drop_annotations_ids(
        &mut self,
        mut gone: HashSet<ObjectId>,
    ) -> Result<(usize, HashSet<ObjectId>)> {
        if gone.is_empty() {
            return Ok((0, HashSet::new()));
        }
        // Each reply on every page and what it replies to (`/IRT`), from the kinds listed
        // ([`AnnotKind::of`]), without placing or reading any more of them.
        let pages = self.page_ids();
        let replies: Vec<(ObjectId, ObjectId)> = (self.listed_annots(&pages).into_iter())
            .filter_map(|(_, id)| {
                let d = self.doc.get_dictionary(id).ok()?;
                AnnotKind::of(d.get(b"Subtype").ok()?.as_name().ok()?)?;
                Some((id, d.get(b"IRT").and_then(Object::as_reference).ok()?))
            })
            .collect();
        loop {
            let before = gone.len();
            for &(id, to) in &replies {
                if gone.contains(&to) {
                    gone.insert(id);
                }
            }
            if gone.len() == before {
                break;
            }
        }
        // Each list is changed once: pages sharing one keep sharing it, or all lose it.
        let mut off = HashSet::new();
        let mut changed = Vec::new();
        for (i, at, refs) in self.each_annots(&pages) {
            let (kept, taken): (Vec<Object>, Vec<Object>) = refs.iter().cloned().partition(|o| {
                o.as_reference()
                    .map_or(true, |id| !gone.contains(&id) && !self.popup_of(id, &gone))
            });
            off.extend(taken.iter().filter_map(|o| o.as_reference().ok()));
            if !taken.is_empty() {
                changed.push((pages[i], at, kept));
            }
        }
        let mut emptied = HashSet::new();
        for (page, at, kept) in changed {
            match at {
                Some(at) => {
                    if kept.is_empty() {
                        emptied.insert(at);
                    }
                    *self.doc.get_object_mut(at)? = Object::Array(kept);
                }
                None if kept.is_empty() => {
                    self.doc.get_dictionary_mut(page)?.remove(b"Annots");
                }
                None => self.doc.get_dictionary_mut(page)?.set("Annots", kept),
            }
        }
        if !emptied.is_empty() {
            for page in pages {
                let at = self.annots_at(page).and_then(|(at, _)| at);
                if at.is_some_and(|at| emptied.contains(&at)) {
                    self.doc.get_dictionary_mut(page)?.remove(b"Annots");
                }
            }
        }
        off.extend(&gone);
        Ok((gone.len(), off))
    }

    /// Draw the annotations into the pages' content as they look now and remove them, so
    /// they are no longer annotations (each becomes a form XObject in the page's content,
    /// which content editing can still move or delete). `pages` (zero-based) limits this
    /// to some pages. Links, form fields, file attachments, media and redaction marks are kept;
    /// replies and popups go without being drawn, as do hidden annotations. Annotations
    /// without a drawing get LimarePDF's first. Every annotation is flattened, past the
    /// 10,000 a page shows too. One LimarePDF can't draw (no `/Rect`, or no drawing it can
    /// place or make) is left as it was, with its popup and replies, and counted in
    /// [`Flattened::kept`] (S1-05). Refused, with nothing changed, when one to draw is a
    /// text box whose text its font can't write ([`Pdf::box_unwritable`]), rather than draw
    /// `?` into the page for good (BUG-39), and when finding those popups and replies is too
    /// complex ([`crate::TooComplex`]): each is looked at once, however often a page lists
    /// it, within one budget for all the pages (A-06). Refused too when drawing those without
    /// a drawing is too complex: within one budget, each is charged what it draws, however
    /// many share its points or text.
    pub fn flatten_annotations(&mut self, pages: Option<&[usize]>) -> Result<Flattened> {
        let ids = self.page_ids();
        let pages = self.page_list(pages)?;
        let on: Vec<ObjectId> = pages.iter().map(|&i| ids[i]).collect();
        // What goes with the annotations kept, found on every page before anything is
        // changed, with one budget: each page's walk below finds no more.
        {
            let mut work = form_flatten::work();
            for &page in &on {
                if let Some(mut plan) = self.plan_page(page, flat_annot, true)? {
                    plan.walk(&mut work)?;
                }
            }
        }
        // Those without a drawing are drawn, with one budget, before any is put in the file.
        {
            let mut work = annot_ap::work();
            let missing = self.missing_on(&on);
            for &(k, id) in &missing {
                if let Some(chars) = self.box_unwritable(id, &mut work)? {
                    bail!(
                        "LimarePDF can't draw the text box on page {}: {}; nothing was \
                         flattened",
                        pages[k] + 1,
                        crate::embed::box_refusal(&chars)
                    );
                }
            }
            // File attachments stay annotations, so they keep having no drawing.
            let missing: Vec<ObjectId> = (missing.into_iter())
                .map(|(_, id)| id)
                .filter(|&id| {
                    self.doc.get_dictionary(id).is_ok_and(|d| {
                        d.get(b"Subtype").and_then(|o| o.as_name()).ok() != Some(b"FileAttachment")
                    })
                })
                .collect();
            self.draw_within(&missing, &mut work)?;
        }
        let mut done = Flattened::default();
        for (&i, page) in pages.iter().zip(on) {
            let mut unplaced = Vec::new();
            let removed = &mut HashSet::new();
            done.drawn += self.flatten_page(
                page,
                flat_annot,
                None,
                "LimareAnnot",
                removed,
                Some(&mut unplaced),
            )?;
            done.kept.extend(std::iter::repeat_n(i, unplaced.len()));
        }
        Ok(done)
    }

    /// The annotations on `pages` that LimarePDF can draw and that have no drawing of their own
    /// (no `/AP /N`), past the 10,000 a page shows too (H-06), each once however many pages
    /// list it. Hidden ones and replies are left out.
    pub(crate) fn missing_appearances(&self, pages: &[ObjectId]) -> Vec<ObjectId> {
        self.missing_on(pages).into_iter().map(|m| m.1).collect()
    }

    /// [`Pdf::missing_appearances`], each with the index in `pages` of the first page that
    /// lists it.
    fn missing_on(&self, pages: &[ObjectId]) -> Vec<(usize, ObjectId)> {
        (self.listed_annots(pages).into_iter())
            .filter(|&(_, id)| {
                let Ok(d) = self.doc.get_dictionary(id) else {
                    return false;
                };
                let drawn = d
                    .get(b"Subtype")
                    .and_then(|o| o.as_name())
                    .is_ok_and(drawable);
                let has_ap = d
                    .get(b"AP")
                    .ok()
                    .and_then(|o| self.dict_of(o))
                    .is_some_and(|ap| ap.has(b"N"));
                // Replies are listed, not drawn.
                let shown = self.flags(d) & (HIDDEN | NO_VIEW) == 0 && !d.has(b"IRT");
                drawn && !has_ap && shown
            })
            .collect()
    }

    /// The annotations of the kinds `pick` chooses on every page, each once however many
    /// pages list it: those [`Pdf::every_annotation`] lists, found without placing or reading
    /// any, for what needs only what each annotation is.
    pub(crate) fn annotations_of_kind(
        &self,
        pick: impl Fn(&AnnotKind) -> bool,
    ) -> HashSet<ObjectId> {
        let placed: Vec<ObjectId> = self.placed_pages().into_iter().map(|p| p.1).collect();
        (self.listed_annots(&placed).into_iter())
            .filter(|&(_, id)| {
                self.doc.get_dictionary(id).is_ok_and(|d| {
                    let kind = d.get(b"Subtype").and_then(Object::as_name).ok();
                    kind.and_then(AnnotKind::of).is_some_and(|k| pick(&k)) && self.has_rect(d)
                })
            })
            .map(|(_, id)| id)
            .collect()
    }

    /// Whether annotation `d` has a `/Rect` to place it by: the listings leave out one
    /// without.
    pub(crate) fn has_rect(&self, d: &Dictionary) -> bool {
        d.get(b"Rect").ok().and_then(|o| self.rect(o)).is_some()
    }

    /// The pages the listings list annotations on, those that can be placed, each with its
    /// index and the transform to displayed-page points: a page whose transform is
    /// degenerate lists none, so another sharing its list still does.
    fn placed_pages(&self) -> Vec<(usize, ObjectId, mx::M)> {
        (self.page_ids().into_iter().enumerate())
            .filter_map(|(i, page)| Some((i, page, mx::inv(self.vis_down(page).0)?)))
            .collect()
    }

    /// The page's `/Annots` array, resolved, and its object when the page refers to one
    /// rather than writing it in.
    fn annots_at(&self, page: ObjectId) -> Option<(Option<ObjectId>, &[Object])> {
        let o = self.doc.get_dictionary(page).ok()?.get(b"Annots").ok()?;
        let (at, o) = self.doc.dereference(o).ok()?;
        Some((at, o.as_array().ok()?))
    }

    /// The page's `/Annots` array, resolved.
    pub(crate) fn annots_array(&self, page: ObjectId) -> Option<&[Object]> {
        Some(self.annots_at(page)?.1)
    }

    /// The `/Annots` arrays of `pages`, each once however many of them share it, with the
    /// index in `pages` of the first that lists it and its object: for passes over every
    /// page's annotations, which would otherwise read a list once a page sharing it. One a
    /// page writes in is its alone.
    pub(crate) fn each_annots<'a>(
        &'a self,
        pages: &'a [ObjectId],
    ) -> impl Iterator<Item = (usize, Option<ObjectId>, &'a [Object])> + 'a {
        let mut seen = HashSet::new();
        (pages.iter().enumerate()).filter_map(move |(i, &page)| {
            let (at, list) = self.annots_at(page)?;
            if at.is_some_and(|at| !seen.insert(at)) {
                return None;
            }
            #[cfg(test)]
            tests::ENTRIES_READ.set(tests::ENTRIES_READ.get() + list.len());
            Some((i, at, list))
        })
    }

    /// The annotations `pages` list, each once, with the index in `pages` of the first page
    /// that lists it ([`Pdf::each_annots`]). Direct dictionaries are skipped;
    /// [`Pdf::own_direct_annots`] gives them objects first.
    pub(crate) fn listed_annots(&self, pages: &[ObjectId]) -> Vec<(usize, ObjectId)> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (i, _, list) in self.each_annots(pages) {
            for id in list.iter().filter_map(|o| o.as_reference().ok()) {
                if seen.insert(id) {
                    out.push((i, id));
                }
            }
        }
        out
    }

    /// Every annotation a page lists, without [`MAX_ANNOTS`]: for removing information,
    /// where one left out could keep what should go. Direct dictionaries are
    /// skipped; [`Pdf::own_direct_annots`] gives them objects first.
    pub(crate) fn all_annot_refs(&self, page: ObjectId) -> Vec<ObjectId> {
        let list = self.annots_array(page).unwrap_or_default();
        #[cfg(test)]
        tests::ENTRIES_READ.set(tests::ENTRIES_READ.get() + list.len());
        list.iter().filter_map(|o| o.as_reference().ok()).collect()
    }

    fn flags(&self, d: &Dictionary) -> i64 {
        d.get(b"F")
            .ok()
            .and_then(|o| self.int_value(o))
            .unwrap_or(0)
    }

    /// Whether `id` is a popup belonging to one of `gone`.
    fn popup_of(&self, id: ObjectId, gone: &HashSet<ObjectId>) -> bool {
        let Ok(d) = self.doc.get_dictionary(id) else {
            return false;
        };
        d.get(b"Subtype").and_then(|o| o.as_name()).ok() == Some(b"Popup")
            && d.get(b"Parent")
                .and_then(|o| o.as_reference())
                .is_ok_and(|p| gone.contains(&p))
    }

    fn annot(
        &self,
        id: ObjectId,
        page: usize,
        to_vis: mx::M,
        layers: &mut Option<Layers>,
        place: &mut Place,
    ) -> Option<Annot> {
        #[cfg(test)]
        tests::BUILT.set(tests::BUILT.get() + 1);
        let d = self.doc.get_dictionary(id).ok()?;
        let kind = AnnotKind::of(d.get(b"Subtype").ok()?.as_name().ok()?)?;
        let rect = place.rect(self, d)?;
        let read = place.read(|work| self.annot_read(d, &kind, rect, to_vis, work));
        let unread = read.is_none();
        let read = read.unwrap_or_default();
        let date = |key: &[u8]| {
            let (_, o) = self.doc.dereference(d.get(key).ok()?).ok()?;
            let s = o.as_str().ok()?;
            pdf_date(&decode_text(&s[..s.len().min(MAX_DATE)]))
        };
        let text_style = read.text.map(|(size, color)| {
            let q = d.get(b"Q").ok().and_then(|o| self.int_value(o));
            TextStyle {
                size,
                color,
                fill: self.colour(d, b"C").map(|c| rgb(&c)),
                border: self.border(d).0,
                align: Align::of_q(q.unwrap_or(0)),
            }
        });
        let shape = matches!(
            kind,
            AnnotKind::Square | AnnotKind::Circle | AnnotKind::Line | AnnotKind::Ink
        )
        .then(|| ShapeLook {
            fill: matches!(kind, AnnotKind::Square | AnnotKind::Circle)
                .then(|| self.colour(d, b"IC").map(|c| rgb(&c)))
                .flatten(),
            width: self.border(d).0,
            arrow: self.line_ends(d).iter().any(|e| e.as_slice() != b"None"),
        });
        Some(Annot {
            id,
            page,
            kind,
            bbox: mx::transform_rect(to_vis, rect),
            quads: read.quads,
            color: self.colour(d, b"C").map(|c| rgb(&c)),
            opacity: d
                .get(b"CA")
                .ok()
                .and_then(|o| self.num(o))
                .map_or(1.0, |a| a.clamp(0.0, 1.0)),
            contents: read.contents,
            author: read.author,
            subject: read.subject,
            name: read.name,
            modified: date(b"M")
                .or_else(|| date(b"CreationDate"))
                .unwrap_or_default(),
            flags: self.flags(d),
            layer_off: (layers.as_mut()).is_some_and(|l| self.annot_layer_off(d, l)),
            reply_to: d.get(b"IRT").and_then(|o| o.as_reference()).ok(),
            has_appearance: d
                .get(b"AP")
                .ok()
                .and_then(|o| self.dict_of(o))
                .is_some_and(|ap| ap.has(b"N")),
            text_style,
            shape,
            paths: read.paths,
            unread,
        })
    }

    /// The points and text of annotation `d`, of kind `kind`, whose box is `rect`: each
    /// charged to `work` before it is read, its points turned to displayed-page points
    /// (`to_vis`).
    fn annot_read(
        &self,
        d: &Dictionary,
        kind: &AnnotKind,
        rect: [f32; 4],
        to_vis: mx::M,
        work: &mut Work,
    ) -> std::result::Result<Read, TooComplex> {
        let text = |key: &[u8], work: &mut Work| {
            let t = self.text_charged(d.get(key).ok(), true, work)?;
            Ok::<_, TooComplex>(t.unwrap_or_default())
        };
        let markup = matches!(
            kind,
            AnnotKind::Highlight
                | AnnotKind::Underline
                | AnnotKind::StrikeOut
                | AnnotKind::Squiggly
                | AnnotKind::Redact
        );
        let quads = match markup {
            true => self.points_charged(d.get(b"QuadPoints").ok(), MAX_POINTS, work)?,
            false => None,
        };
        let quads = (quads.unwrap_or_default().as_chunks::<4>().0.iter())
            .map(|q| {
                let mut b = [f32::MAX, f32::MAX, f32::MIN, f32::MIN];
                for &(x, y) in q {
                    let (x, y) = mx::apply(to_vis, x, y);
                    (b[0], b[1]) = (b[0].min(x), b[1].min(y));
                    (b[2], b[3]) = (b[2].max(x), b[3].max(y));
                }
                b
            })
            .collect();
        let style = match *kind == AnnotKind::TextBox {
            // As it is drawn: from `/DA`, else `/DS`.
            true => {
                let g = self.box_geometry(d, rect, work)?;
                Some((g.size, rgb(&g.text_rgb)))
            }
            false => None,
        };
        let points = |key: &[u8], n: usize, work: &mut Work| {
            let p = self.points_charged(d.get(key).ok(), n, work)?;
            Ok::<_, TooComplex>(p.into_iter().collect())
        };
        let ink = || {
            let (_, o) = self.doc.dereference(d.get(b"InkList").ok()?).ok()?;
            o.as_array().ok()
        };
        let paths: Vec<Vec<(f32, f32)>> = match kind {
            AnnotKind::Line => points(b"L", 2, work)?,
            AnnotKind::PolyLine => points(b"Vertices", MAX_POINTS, work)?,
            AnnotKind::Ink => match ink() {
                Some(list) => self.ink_strokes(list, work)?,
                None => Vec::new(),
            },
            _ => Vec::new(),
        };
        let name = match d.get(b"Name").and_then(|o| o.as_name()) {
            Ok(n) => {
                work.take(n.len() as u64)?;
                String::from_utf8_lossy(n).into_owned()
            }
            Err(_) => String::new(),
        };
        Ok(Read {
            quads,
            paths: (paths.into_iter())
                .map(|p| {
                    p.into_iter()
                        .map(|(x, y)| mx::apply(to_vis, x, y))
                        .collect()
                })
                .collect(),
            contents: text(b"Contents", work)?,
            author: text(b"T", work)?,
            subject: text(b"Subj", work)?,
            name,
            text: style,
        })
    }
}

/// What listing an annotation reads within the budget for reading them
/// ([`Place::read`]): its points and text.
#[derive(Default)]
struct Read {
    quads: Vec<[f32; 4]>,
    paths: Vec<Vec<(f32, f32)>>,
    contents: String,
    author: String,
    subject: String,
    name: String,
    /// A text box's text size and colour, as it is drawn: from `/DA`, else `/DS`.
    text: Option<(f32, [f32; 3])>,
}

/// What flattening does with each annotation: draw the marks, drop replies and the
/// popups of drawn annotations, keep the rest.
fn flat_annot(pdf: &Pdf, d: &Dictionary) -> Flat {
    fn sub(d: &Dictionary) -> Option<&[u8]> {
        d.get(b"Subtype").and_then(|o| o.as_name()).ok()
    }
    // Redaction marks stay marks: drawing them in would hide nothing.
    let marks = |s: Option<&[u8]>| {
        s.is_some_and(|s| {
            (DRAWN.contains(&s) || matches!(s, b"Stamp" | b"Caret")) && s != b"Redact"
        })
    };
    match sub(d) {
        Some(b"Popup") => {
            let parent = d
                .get(b"Parent")
                .and_then(|o| o.as_reference())
                .ok()
                .and_then(|p| pdf.doc.get_dictionary(p).ok());
            if parent.is_some_and(|p| marks(sub(p))) {
                Flat::Drop
            } else {
                Flat::Keep
            }
        }
        s if marks(s) && d.has(b"IRT") => Flat::Drop,
        s if marks(s) => Flat::Draw,
        _ => Flat::Keep,
    }
}

/// A colour as RGB: grey and CMYK are converted simply.
fn rgb(c: &[f32]) -> [f32; 3] {
    match *c {
        [g] => [g; 3],
        [c, m, y, k] => [
            (1.0 - c) * (1.0 - k),
            (1.0 - m) * (1.0 - k),
            (1.0 - y) * (1.0 - k),
        ],
        [r, g, b, ..] => [r, g, b],
        [] | [_, _] => [0.0; 3],
    }
}

/// A PDF date (`D:YYYYMMDDHHmmSS…`) as `YYYY-MM-DD HH:MM`: in this computer's time zone
/// when the date says its own (LimarePDF writes UTC's), else as written; the time is left
/// out when the date has none.
fn pdf_date(s: &str) -> Option<String> {
    let s = s.strip_prefix("D:").unwrap_or(s);
    let all = s.chars().take_while(char::is_ascii_digit).count();
    let zoned = matches!(s[all..].chars().next(), Some('Z' | '+' | '-'));
    if all >= 12 && zoned {
        if let Some(t) = crate::sig_verify::parse_pdf_date(s) {
            let local = t.with_timezone(&chrono::Local);
            return Some(local.format("%Y-%m-%d %H:%M").to_string());
        }
    }
    let digits: String = s.chars().take(all.min(12)).collect();
    if digits.len() < 8 {
        return None;
    }
    let mut out = format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..8]);
    if digits.len() >= 12 {
        out += &format!(" {}:{}", &digits[8..10], &digits[10..12]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::budget_seam;
    use crate::print::{Orientation, PageSetup, Paper, PerSheet, Scale};
    use crate::{Hidden, TooComplex};
    use lopdf::dictionary;
    use std::cell::Cell;

    thread_local! {
        /// `/Annots` entries read listing annotations on this thread.
        pub(super) static ENTRIES_READ: Cell<usize> = const { Cell::new(0) };
        /// Entries listings built an annotation for on this thread.
        pub(super) static BUILT: Cell<usize> = const { Cell::new(0) };
    }

    /// `n` pages sharing one `/Annots` array of `k` squares without a drawing, and the first
    /// square.
    fn sharing_annots(n: usize, k: usize) -> (Pdf, ObjectId) {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let page = p.page_ids()[0];
        let squares: Vec<Object> = (0..k)
            .map(|_| {
                let d = dictionary! {
                    "Type" => "Annot",
                    "Subtype" => "Square",
                    "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
                    "F" => 4,
                };
                p.doc.add_object(d).into()
            })
            .collect();
        let first = squares[0].as_reference().unwrap();
        let list = p.doc.add_object(squares);
        let d = p.doc.get_dictionary_mut(page).unwrap();
        d.set("Annots", list);
        let d = d.clone();
        let tree = d.get(b"Parent").and_then(Object::as_reference).unwrap();
        let kids: Vec<Object> = std::iter::once(page.into())
            .chain((1..n).map(|_| p.doc.add_object(d.clone()).into()))
            .collect();
        let t = p.doc.get_dictionary_mut(tree).unwrap();
        t.set("Kids", kids);
        t.set("Count", n as i64);
        (p, first)
    }

    /// The `/Annots` entries `f` reads on 2,000 pages sharing one array of 1,000 squares past
    /// what it reads on two, and whether it worked on 2,000.
    fn read_past_two(f: impl Fn(&mut Pdf, ObjectId) -> bool) -> (usize, bool) {
        let read = |n| {
            let (mut p, first) = sharing_annots(n, 1_000);
            ENTRIES_READ.set(0);
            let worked = f(&mut p, first);
            (ENTRIES_READ.get(), worked)
        };
        let (two, _) = read(2);
        let (many, worked) = read(2_000);
        (many.saturating_sub(two), worked)
    }

    /// Pages sharing one `/Annots` array have it read once a pass, however many share it:
    /// saving, removing one, looking one up, deleting a page and removing hidden information
    /// read no more of it on 2,000 pages than on two. (The walks of what pages draw read each
    /// page's list, each entry charged to their budget: what a page draws is its own.)
    #[test]
    fn annotations_pages_share_are_read_once_a_pass() {
        let got = [
            read_past_two(|p, _| p.app_snapshot().is_ok()),
            read_past_two(|p, _| p.render_snapshot().is_ok()),
            read_past_two(|p, id| p.remove_annotation(id).is_ok()),
            read_past_two(|p, _| p.annotation((u32::MAX, 0)).is_err()),
            read_past_two(|p, _| p.delete_pages(&[1]).is_ok()),
            read_past_two(|p, _| {
                (p.remove_hidden(&[Hidden::Comments, Hidden::Attachments])).is_ok()
            }),
        ];
        assert_eq!(got, [(0, true); 6]);
    }

    /// Printing or flattening pages that share their annotations draws each once: 100 pages
    /// sharing 1,000 squares without a drawing, which drawing once a page would take past
    /// the budget for drawing them ([`annot_ap::work`]).
    #[test]
    fn annotations_pages_share_are_drawn_once() {
        let (mut p, _) = sharing_annots(100, 1_000);
        let paper = Paper {
            id: "page".into(),
            label: "page".into(),
            size: (300.0, 200.0),
            margins: Some([0.0; 4]),
        };
        let setup = PageSetup {
            paper,
            orientation: Orientation::Automatic,
            scale: Scale::ShrinkOversized,
            per_sheet: PerSheet::default(),
            booklet: None,
        };
        let pages: Vec<usize> = (0..100).collect();
        let printed = p.print_sheets(&pages, &setup).map(|_| ());
        let flattened = p.flatten_annotations(None).map(|f| f.drawn);
        let text = |e: anyhow::Error| e.to_string();
        assert_eq!(
            (printed.map_err(text), flattened.map_err(text)),
            (Ok(()), Ok(100_000))
        );
    }

    /// Removing an annotation from an array pages share takes it out of the array, which they
    /// still share; removing the rest takes the array off them.
    #[test]
    fn removing_one_keeps_pages_sharing_their_annotations() {
        let (mut p, first) = sharing_annots(3, 3);
        let at = |p: &Pdf| -> Vec<Option<Object>> {
            let page = |id| p.doc.get_dictionary(id).unwrap();
            (p.page_ids().into_iter())
                .map(|id| page(id).get(b"Annots").ok().cloned())
                .collect()
        };
        let shared = at(&p);
        assert_eq!(p.remove_annotation(first).unwrap(), 1);
        assert_eq!(at(&p), shared);
        let left = p.all_annot_refs(p.page_ids()[0]);
        assert_eq!(left.len(), 2);
        assert!(!left.contains(&first));
        for id in left {
            p.remove_annotation(id).unwrap();
        }
        assert_eq!(at(&p), [None, None, None]);
    }

    /// The listing gives an annotation several pages list once, on the first that lists it
    /// (Q1); each page still shows it, and choosing by page finds it on any of them.
    #[test]
    fn the_listing_gives_each_annotation_once_on_its_first_page() {
        let (mut p, first) = sharing_annots(3, 3);
        let pages = |list: Vec<Annot>| list.into_iter().map(|a| a.page).collect::<Vec<_>>();
        assert_eq!(pages(p.annotations()), [0, 0, 0]);
        assert_eq!(pages(p.page_annotations(2).unwrap()), [2, 2, 2]);
        assert!(p.annotation_ids_on(&[2]).unwrap().contains(&first));
        let removed = p.remove_annotations(Some(&[2]), |a| a.id == first);
        assert_eq!(removed.unwrap(), 1);
        assert_eq!(pages(p.annotations()), [0, 0]);
    }

    /// Removing annotations stops at the first refusal of the budget for reading them: none
    /// is built past it. 1,000 squares, with a budget for about 150.
    #[test]
    fn removing_builds_none_past_the_reading_budget() {
        let (mut p, _) = sharing_annots(1, 1_000);
        BUILT.set(0);
        let (e, _) = budget_seam::with_limit(10_000, || p.remove_annotations(None, |_| false));
        assert!(e.is_err_and(|e| e.is::<TooComplex>()));
        let built = BUILT.get();
        assert!(built <= 10_000 / 64 + 1, "{built} built");
    }

    /// Each entry of a list a listing looks at is charged a step of the budget for reading:
    /// removing annotations from a page listing 100,000 entries that aren't annotations is
    /// refused with a budget for fewer, and listing them takes a step for each of the 10,000
    /// shown.
    #[test]
    fn listings_charge_each_entry_they_look_at() {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let page = p.page_ids()[0];
        let d = p.doc.get_dictionary_mut(page).unwrap();
        d.set("Annots", vec![Object::Null; 100_000]);
        let remove = |p: &mut Pdf| p.remove_annotations(None, |_| true);
        let (removed, _) = budget_seam::with_limit(50_000, || remove(&mut p));
        let (_, taken) = budget_seam::with_limit(u64::MAX, || p.annotations());
        let refused = removed.is_err_and(|e| e.is::<TooComplex>());
        assert_eq!((refused, taken.iter().max()), (true, Some(&10_000)));
    }

    /// Redaction marks are listed on each page showing them, and only marks are built: 200
    /// pages sharing a mark and 999 squares look at the 1,000 entries once and build 200
    /// entries, not 200,000.
    #[test]
    fn redaction_marks_build_marks_only() {
        let (mut p, first) = sharing_annots(200, 1_000);
        let d = p.doc.get_dictionary_mut(first).unwrap();
        d.set("Subtype", "Redact");
        BUILT.set(0);
        ENTRIES_READ.set(0);
        let marks = p.redaction_marks().unwrap();
        let counts = (marks.len(), ENTRIES_READ.get(), BUILT.get());
        assert_eq!(counts, (200, 1_000, 200));
    }

    /// The squares of [`sharing_annots`] made redaction marks, without a `/Rect` unless
    /// `rect`.
    fn as_marks(p: &mut Pdf, rect: bool) {
        let page = p.page_ids()[0];
        let ids: Vec<ObjectId> = (p.annots_array(page).unwrap().iter())
            .filter_map(|o| o.as_reference().ok())
            .collect();
        for id in ids {
            let d = p.doc.get_dictionary_mut(id).unwrap();
            d.set("Subtype", "Redact");
            if !rect {
                d.remove(b"Rect");
            }
        }
    }

    /// The marks many pages share are counted once, as the listing gives them (Q1), and none
    /// is built: 2,000 pages sharing 100 marks count 100.
    #[test]
    fn marks_many_pages_share_are_counted_once_building_none() {
        let (mut p, _) = sharing_annots(2_000, 100);
        as_marks(&mut p, true);
        BUILT.set(0);
        let n = p.redaction_mark_count();
        assert_eq!((n, BUILT.get()), (100, 0));
    }

    /// The count is of marks, not the areas they cover (PB-40), within the budget for
    /// reading them and past it, where listing them is refused: 3 pages sharing a mark of
    /// two quads, one of none and one without a `/Rect`, listed and applied nowhere, count
    /// 2 marks of 9 areas.
    #[test]
    fn the_count_is_of_marks_not_areas() {
        let (mut p, first) = sharing_annots(3, 3);
        as_marks(&mut p, true);
        let quad = [10, 20, 20, 20, 10, 10, 20, 10].map(Object::from);
        let d = p.doc.get_dictionary_mut(first).unwrap();
        d.set("QuadPoints", [quad.clone(), quad].concat());
        let last = p.annots_array(p.page_ids()[0]).unwrap()[2].as_reference();
        p.doc
            .get_dictionary_mut(last.unwrap())
            .unwrap()
            .remove(b"Rect");
        let within = (p.redaction_mark_count(), p.redaction_marks().unwrap().len());
        let ((count, listed), _) = budget_seam::with_limit(1, || {
            let listed = p.redaction_marks();
            (
                p.redaction_mark_count(),
                listed.is_err_and(|e| e.is::<TooComplex>()),
            )
        });
        assert_eq!((within, count, listed), ((2, 9), 2, true));
    }

    /// Applying marks many pages share is refused past the budget for reading them, each
    /// page's marks charged, even marks with nothing to place: 2,000 pages sharing 100 marks
    /// without a `/Rect`, with a budget of 100,000 steps.
    #[test]
    fn applying_marks_many_pages_share_is_refused_past_the_budget() {
        let (mut p, _) = sharing_annots(2_000, 100);
        as_marks(&mut p, false);
        BUILT.set(0);
        let (e, _) = budget_seam::with_limit(100_000, || p.apply_redactions());
        let built = BUILT.get();
        let refused = e.as_ref().is_err_and(|e| e.is::<TooComplex>());
        assert!(refused && built <= 100_000, "{:?}, {built} built", e.err());
    }

    #[test]
    fn dates() {
        // Dates with a time zone are shown in this computer's: tests/local_dates.rs.
        assert_eq!(
            pdf_date("D:20240305142233").as_deref(),
            Some("2024-03-05 14:22")
        );
        assert_eq!(pdf_date("20240305").as_deref(), Some("2024-03-05"));
        assert_eq!(pdf_date("D:2024"), None);
    }

    #[test]
    fn kinds_round_trip_by_name() {
        for k in [
            AnnotKind::Highlight,
            AnnotKind::Note,
            AnnotKind::TextBox,
            AnnotKind::Ink,
        ] {
            assert_eq!(AnnotKind::parse(k.name()), k);
        }
        assert_eq!(AnnotKind::parse("HIGHLIGHT"), AnnotKind::Highlight);
        assert_eq!(
            AnnotKind::parse("FileAttachment"),
            AnnotKind::Other("FileAttachment".into())
        );
        assert_eq!(AnnotKind::TextBox.label(), "Text box");
        assert_eq!(AnnotKind::Highlight.label(), "Highlight");
    }

    #[test]
    fn colours_become_rgb() {
        assert_eq!(rgb(&[0.5]), [0.5; 3]);
        assert_eq!(rgb(&[0.0, 0.0, 1.0, 0.0]), [1.0, 1.0, 0.0]);
    }
}
