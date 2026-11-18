//! Interactive forms (AcroForm): the fields, their values and where their widgets are.

use crate::doc::{decode_shown_text, decode_text};
use crate::form_write::parse_da;
use crate::matrix::{self as mx, M};
use crate::{Align, FontChoice, Pdf};
use lopdf::{Dictionary, Object, ObjectId};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Limits that keep a malformed or hostile file from running away.
const MAX_FIELDS: usize = 10_000;
pub(crate) const MAX_DEPTH: usize = 32;

// Field flags (`/Ff`), as bit masks.
const READ_ONLY: i64 = 1;
const REQUIRED: i64 = 1 << 1;
const MULTILINE: i64 = 1 << 12;
const PASSWORD: i64 = 1 << 13;
const RADIO: i64 = 1 << 15;
const PUSH_BUTTON: i64 = 1 << 16;
const COMBO: i64 = 1 << 17;
const EDIT: i64 = 1 << 18;
const MULTI_SELECT: i64 = 1 << 21;
const COMB: i64 = 1 << 24;

/// What kind of field it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Text {
        multiline: bool,
        /// Typed characters are hidden, and the value isn't kept in the file.
        password: bool,
        /// Spread over `max_len` equal boxes, one character in each.
        comb: bool,
        max_len: Option<usize>,
    },
    Check,
    Radio,
    /// A drop-down list (`combo`), which may also take typed text (`editable`), or a list
    /// box, which may allow more than one choice (`multi`).
    Choice {
        combo: bool,
        editable: bool,
        multi: bool,
    },
    /// A push button. It only runs JavaScript, so it has no value.
    Button,
    Signature,
}

/// A field's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    Text(String),
    /// A checkbox: ticked or not.
    Check(bool),
    /// The chosen options' export values: at most one, except in a multi-select list
    /// box. For a radio group, the chosen button's export value.
    Choice(Vec<String>),
    /// Push buttons and signature fields.
    None,
}

/// One field, with everything inherited from its parents filled in.
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    /// The fully qualified name, with parents' names joined by dots.
    pub name: String,
    pub kind: FieldKind,
    pub value: FieldValue,
    /// For choices and radio groups: (export value, text shown).
    pub options: Vec<(String, String)>,
    pub read_only: bool,
    pub required: bool,
    /// The description the file gives for the field (`/TU`), if any.
    pub tooltip: Option<String>,
    /// The text size the field asks for (`/DA`), in points; 0 means fit to the field.
    pub text_size: f32,
    /// The font its value is set in when LimarePDF can't write it in the font `/DA` names as
    /// that is: the standard font nearest it, Helvetica when it names none. What this font
    /// lacks goes to fonts it falls back to ([`crate::fallbacks`]).
    pub font: FontChoice,
    /// Where the field is drawn and clicked. Widgets that aren't on any page are left out.
    pub widgets: Vec<Widget>,
}

/// One place a field is shown on a page.
#[derive(Clone, Debug, PartialEq)]
pub struct Widget {
    /// The widget annotation's object in the file; stays the same while the document is
    /// open.
    pub id: (u32, u16),
    /// The page (zero-based).
    pub page: usize,
    /// The widget's box in displayed-page points (y down), like
    /// [`crate::PageObject::bbox`].
    pub bbox: [f32; 4],
    /// For checkboxes and radio buttons: the state name meaning "on" for this widget.
    pub on_state: Option<String>,
    /// For radio buttons: the value choosing this one gives the field (the export value
    /// of its "on" state).
    pub export: Option<String>,
    /// The widget annotation's flags (`/F`), asked through [`Widget::on_screen`] and
    /// [`Widget::prints`].
    flags: i64,
    /// How text is set in it: left, centred or right, as its form says (its `/Q`, else its
    /// field's).
    pub align: Align,
}

impl Widget {
    /// Whether the page shows it on screen: neither Hidden nor NoView is set.
    pub fn on_screen(&self) -> bool {
        crate::annots::on_screen(self.flags)
    }

    /// Whether it is printed: Print is set and Hidden isn't, whatever NoView says.
    pub fn prints(&self) -> bool {
        crate::annots::prints(self.flags)
    }
}

/// Values inherited from parent fields.
#[derive(Clone, Default)]
struct Inherited {
    ft: Option<Vec<u8>>,
    ff: i64,
    v: Option<Object>,
    dv: Option<Object>,
    max_len: Option<usize>,
    opt: Option<Object>,
    da: Option<Vec<u8>>,
    q: Option<i64>,
}

/// The kind of a terminal field that inherits `inh`, or `None` for a node of no kind, which
/// is no field.
fn field_kind(inh: &Inherited) -> Option<FieldKind> {
    let ff = inh.ff;
    Some(match inh.ft.as_deref()? {
        b"Tx" => FieldKind::Text {
            multiline: ff & MULTILINE != 0,
            password: ff & PASSWORD != 0,
            comb: ff & COMB != 0,
            max_len: inh.max_len,
        },
        b"Btn" if ff & PUSH_BUTTON != 0 => FieldKind::Button,
        b"Btn" if ff & RADIO != 0 => FieldKind::Radio,
        b"Btn" => FieldKind::Check,
        b"Ch" => FieldKind::Choice {
            combo: ff & COMBO != 0,
            editable: ff & EDIT != 0,
            multi: ff & MULTI_SELECT != 0,
        },
        b"Sig" => FieldKind::Signature,
        _ => return None,
    })
}

/// Whether a node whose own or inherited `/FT` is `ft` has a kind: whether [`field_kind`]
/// gives it one.
pub(crate) fn of_a_kind(ft: Option<&[u8]>) -> bool {
    matches!(ft, Some(b"Tx" | b"Btn" | b"Ch" | b"Sig"))
}

/// Where a field is in the file, and what writing its value needs besides [`Field`].
pub(crate) struct Node {
    /// The terminal field's dictionary, which holds `/V`.
    pub id: ObjectId,
    /// All its widget annotations, on a page or not.
    pub widgets: Vec<ObjectId>,
    /// The default appearance (`/DA`): font, size and colour, inherited or from the form.
    pub da: Option<Vec<u8>>,
    /// Alignment: 0 left, 1 centred, 2 right.
    pub q: i64,
    /// The value a reset goes back to.
    pub dv: Option<Object>,
    /// For a choice or a button with `/Opt`: (export value, text shown).
    pub opt: Vec<(String, String)>,
}

/// How much of the field tree a walk takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reach {
    /// The fields LimarePDF lists, for showing them: the first [`MAX_FIELDS`].
    Listed,
    /// Every field: for all else, where a field left out would lose its value (flattening
    /// and printing, PB-90; removing values, PB-174), be missed by name or go uncounted.
    Every,
}

/// State kept while walking the field tree.
struct Walk {
    /// Each annotation's page and its object, from the pages' `/Annots`.
    pages: HashMap<ObjectId, (usize, ObjectId)>,
    /// Each page's matrix from user space to displayed-page points.
    to_vis: HashMap<usize, Option<M>>,
    /// The nodes walked with a kind.
    seen: HashSet<ObjectId>,
    /// The nodes walked with no kind: each is walked once more should it be reached with one.
    untyped: HashSet<ObjectId>,
    out: Vec<(Field, Node)>,
    /// How many fields the walk takes.
    limit: usize,
    /// Whether a field was left out for being nested more than [`MAX_DEPTH`] deep.
    too_deep: bool,
    /// Each `/Kids` array object reached, by its object.
    kids: HashMap<ObjectId, Kids>,
    /// The widgets fields have taken.
    claimed: HashSet<ObjectId>,
}

/// A node's kids, told apart.
#[derive(Clone)]
struct Kids {
    /// Those that are fields of their own.
    fields: Rc<[ObjectId]>,
    /// Those that are the node's widgets.
    widgets: Rc<[ObjectId]>,
    /// For a `/Kids` array object, the shallowest depth a node took its kids from.
    taken: Option<usize>,
    /// For a `/Kids` array object, the shallowest depth a node of no kind walked its kids
    /// from.
    looked: Option<usize>,
}

impl Pdf {
    /// The form's fields, in the order the form lists them, for showing them: at most the
    /// first 10,000 ([`Pdf::every_form_field`] has them all). Empty when there is no form.
    /// Broken entries are skipped, never fatal.
    pub fn form_fields(&self) -> Vec<Field> {
        self.listed_nodes().into_iter().map(|(f, _)| f).collect()
    }

    /// Every field of the form, without [`Pdf::form_fields`]' limit: for finding a field by
    /// name and for what has to know of each one.
    pub fn every_form_field(&self) -> Vec<Field> {
        self.form_nodes().into_iter().map(|(f, _)| f).collect()
    }

    /// How many signature fields hold a signature. Any full rewrite, such as
    /// [`Pdf::save`], makes those signatures invalid.
    pub fn signature_count(&self) -> usize {
        self.form_nodes()
            .iter()
            .filter(|(f, n)| {
                f.kind == FieldKind::Signature
                    && self.doc.get_dictionary(n.id).is_ok_and(|d| d.has(b"V"))
            })
            .count()
    }

    /// The signature fields among those [`Pdf::form_fields`] lists that hold no digital
    /// signature, in the order the form lists them: where a digital signature can go.
    pub fn empty_signature_fields(&self) -> Vec<Field> {
        self.listed_nodes()
            .into_iter()
            .filter(|(f, n)| {
                f.kind == FieldKind::Signature
                    && !self.doc.get_dictionary(n.id).is_ok_and(|d| d.has(b"V"))
            })
            .map(|(f, _)| f)
            .collect()
    }

    /// The boxes (displayed-page points) of the signature fields on page `page_index` that
    /// hold no digital signature, where fill and sign puts a signature.
    pub fn empty_signature_boxes(&self, page_index: usize) -> Vec<[f32; 4]> {
        self.empty_signature_fields()
            .iter()
            .flat_map(|f| f.widgets.iter())
            .filter(|w| w.page == page_index && w.on_screen())
            .map(|w| w.bbox)
            .collect()
    }

    /// Every field with where it is in the file.
    pub(crate) fn form_nodes(&self) -> Vec<(Field, Node)> {
        self.field_nodes(Reach::Every).0
    }

    /// The fields LimarePDF lists ([`Pdf::form_fields`]) with where each is in the file:
    /// for showing them.
    pub(crate) fn listed_nodes(&self) -> Vec<(Field, Node)> {
        self.field_nodes(Reach::Listed).0
    }

    /// The fields with where each is in the file, as far as `reach` goes, and whether some
    /// were left out for being nested more than [`MAX_DEPTH`] deep.
    pub(crate) fn field_nodes(&self, reach: Reach) -> (Vec<(Field, Node)>, bool) {
        let Some(form) = self.acro_form() else {
            return (Vec::new(), false);
        };
        let top = Inherited {
            da: form.get(b"DA").ok().and_then(|o| self.string_bytes(o)),
            q: form.get(b"Q").ok().and_then(|o| self.int_value(o)),
            ..Inherited::default()
        };
        let Some(fields) = form
            .get(b"Fields")
            .ok()
            .and_then(|o| self.doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
        else {
            return (Vec::new(), false);
        };
        let mut walk = Walk {
            pages: self.annot_pages(),
            to_vis: HashMap::new(),
            seen: HashSet::new(),
            untyped: HashSet::new(),
            out: Vec::new(),
            limit: match reach {
                Reach::Listed => MAX_FIELDS,
                Reach::Every => usize::MAX,
            },
            too_deep: false,
            kids: HashMap::new(),
            claimed: HashSet::new(),
        };
        for f in fields {
            if let Ok(id) = f.as_reference() {
                self.walk_field(id, "", &top, 0, &mut walk);
            }
        }
        (walk.out, walk.too_deep)
    }

    /// Every node of the field tree, fields and widgets, each once, with whether it belongs to
    /// a signature field (by its own or an inherited `/FT`). Unlike [`Pdf::every_form_field`]
    /// it fails rather than skip what is nested too deep: for removing values, where a node
    /// left out could keep one.
    pub(crate) fn value_nodes(&self) -> anyhow::Result<Vec<(ObjectId, bool)>> {
        fn walk(
            p: &Pdf,
            id: ObjectId,
            sig: bool,
            depth: usize,
            seen: &mut HashSet<ObjectId>,
            lists: &mut HashSet<ObjectId>,
            out: &mut Vec<(ObjectId, bool)>,
        ) -> anyhow::Result<()> {
            #[cfg(test)]
            tests::LOOKED.set(tests::LOOKED.get() + 1);
            if !seen.insert(id) {
                return Ok(());
            }
            let Ok(d) = p.doc.get_dictionary(id) else {
                return Ok(());
            };
            let sig = match d.get(b"FT").and_then(|o| o.as_name()) {
                Ok(ft) => ft == b"Sig",
                Err(_) => sig,
            };
            out.push((id, sig));
            let kids = d
                .get(b"Kids")
                .ok()
                .and_then(|o| p.doc.dereference(o).ok())
                .and_then(|(_, o)| o.as_array().ok())
                .filter(|k| !k.is_empty());
            // A field's widgets may be one level below the deepest field, as
            // [`Pdf::form_nodes`] reads them (PB-05).
            if kids.is_some() && depth > MAX_DEPTH {
                anyhow::bail!("the form's fields are nested more than {MAX_DEPTH} deep");
            }
            // A `/Kids` array object that more than one node lists, as no well-made form
            // has, is passed over once its kids are walked, as each was then.
            let list = d.get(b"Kids").and_then(|o| o.as_reference()).ok();
            if list.is_some_and(|l| lists.contains(&l)) {
                return Ok(());
            }
            for k in kids.into_iter().flatten() {
                if let Ok(k) = k.as_reference() {
                    walk(p, k, sig, depth + 1, seen, lists, out)?;
                }
            }
            lists.extend(list);
            Ok(())
        }
        let fields = self
            .acro_form()
            .and_then(|f| f.get(b"Fields").ok())
            .and_then(|o| self.doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok());
        let (mut seen, mut lists, mut out) = (HashSet::new(), HashSet::new(), Vec::new());
        for f in fields.into_iter().flatten() {
            if let Ok(id) = f.as_reference() {
                walk(self, id, false, 0, &mut seen, &mut lists, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Whether this is an XFA-only ("dynamic XFA") form: one made for Adobe Reader, whose
    /// pages and fields are built from XML that only Adobe software lays out. The PDF's
    /// own pages are then usually a "Please wait..." placeholder. Hybrid forms, which
    /// also carry ordinary fields, are not XFA-only: those fields are what LimarePDF fills.
    pub fn xfa_only(&self) -> bool {
        let Some(form) = self.acro_form() else {
            return false;
        };
        if !form.has(b"XFA") {
            return false;
        }
        let needs_rendering = self
            .doc
            .catalog()
            .ok()
            .and_then(|c| c.get(b"NeedsRendering").ok())
            .and_then(|o| o.as_bool().ok())
            .unwrap_or(false);
        needs_rendering || !self.form_nodes().iter().any(|(f, _)| !f.widgets.is_empty())
    }

    /// The catalog's `/AcroForm` dictionary.
    pub(crate) fn acro_form(&self) -> Option<&Dictionary> {
        let form = self.doc.catalog().ok()?.get(b"AcroForm").ok()?;
        self.doc.dereference(form).ok()?.1.as_dict().ok()
    }

    /// Each annotation listed on a page, with the first page (zero-based) that lists it and
    /// its object.
    fn annot_pages(&self) -> HashMap<ObjectId, (usize, ObjectId)> {
        let pages = self.page_ids();
        (self.listed_annots(&pages).into_iter())
            .map(|(i, a)| (a, (i, pages[i])))
            .collect()
    }

    fn walk_field(&self, id: ObjectId, parent: &str, inh: &Inherited, depth: usize, w: &mut Walk) {
        #[cfg(test)]
        tests::LOOKED.set(tests::LOOKED.get() + 1);
        if depth > MAX_DEPTH {
            w.too_deep |= self.doc.get_dictionary(id).is_ok();
            return;
        }
        if w.out.len() >= w.limit || w.seen.contains(&id) {
            return;
        }
        let Ok(d) = self.doc.get_dictionary(id) else {
            return;
        };
        // A node reached first with no kind, as a kid of a node of no kind, is walked again
        // should a node with a kind list it: its kid fields are then that node's.
        let ft = d.get(b"FT").ok().and_then(|o| o.as_name().ok());
        let typed = of_a_kind(ft.or(inh.ft.as_deref()));
        if typed {
            w.seen.insert(id);
        } else if !w.untyped.insert(id) {
            return;
        }
        let name = match d.get(b"T").ok().and_then(|o| self.text_value(o)) {
            Some(t) if parent.is_empty() => t,
            Some(t) => format!("{parent}.{t}"),
            None => parent.to_string(),
        };
        let mut inh = inh.clone();
        if let Some(ft) = ft {
            inh.ft = Some(ft.to_vec());
        }
        if let Some(ff) = d.get(b"Ff").ok().and_then(|o| self.int_value(o)) {
            inh.ff = ff;
        }
        if let Ok(v) = d.get(b"V") {
            inh.v = Some(v.clone());
        }
        if let Ok(dv) = d.get(b"DV") {
            inh.dv = Some(dv.clone());
        }
        if let Some(da) = d.get(b"DA").ok().and_then(|o| self.string_bytes(o)) {
            inh.da = Some(da);
        }
        if let Some(q) = d.get(b"Q").ok().and_then(|o| self.int_value(o)) {
            inh.q = Some(q);
        }
        if let Some(n) = d.get(b"MaxLen").ok().and_then(|o| self.int_value(o)) {
            inh.max_len = usize::try_from(n).ok();
        }
        if let Ok(opt) = d.get(b"Opt") {
            inh.opt = Some(opt.clone());
        }

        // A `/Kids` array object that more than one node lists, as no well-made form has, is
        // taken once its kids are walked: a node listing it after that takes them only from
        // nearer the top, where kids too deep before are not. A node listing it while they are
        // walked, through a loop, walks them as a node with its own list would, and names
        // them as `sig_changes`' roles do. A node of no kind walks them without taking them,
        // as fields of no kind a node with a kind may list after it, and a node of no kind
        // listing it after that passes over them as for a taken list.
        let list = d.get(b"Kids").and_then(|o| o.as_reference()).ok();
        let kids = match list.and_then(|l| w.kids.get(&l)) {
            Some(k) => k.clone(),
            None => self.kids_of(d),
        };
        let taken = kids.taken.is_some_and(|t| t <= depth)
            || !typed && kids.looked.is_some_and(|t| t <= depth);
        let take = |w: &mut Walk| {
            if let Some(l) = list.filter(|_| !taken) {
                let k = Kids {
                    taken: Some(depth),
                    ..kids.clone()
                };
                w.kids.insert(l, k);
            }
        };
        if !kids.fields.is_empty() {
            if taken {
                // Each was walked, or left out as too deep, from there.
                w.too_deep |= depth + 1 > MAX_DEPTH;
            } else {
                for &k in kids.fields.iter() {
                    self.walk_field(k, &name, &inh, depth + 1, w);
                }
                if typed {
                    take(w);
                } else if let Some(l) = list {
                    w.kids.entry(l).or_insert(kids).looked = Some(depth);
                }
            }
            return;
        }
        // A node of no kind is no field: it takes neither its list nor its widgets, but keeps
        // the list told apart for the next node listing it.
        let Some(kind) = field_kind(&inh) else {
            if let Some(l) = list {
                w.kids.entry(l).or_insert(kids);
            }
            return;
        };
        take(w);
        // A widget that more than one field lists, as no well-made form has, goes to the
        // first.
        let widgets = if kids.widgets.is_empty() && d.has(b"Rect") {
            vec![id]
        } else if taken {
            Vec::new()
        } else {
            let mut ws = kids.widgets.to_vec();
            ws.retain(|&k| {
                #[cfg(test)]
                tests::LOOKED.set(tests::LOOKED.get() + 1);
                w.claimed.insert(k)
            });
            ws
        };
        let field = self.make_field(name, d, kind, &inh, &widgets, w);
        let node = Node {
            id,
            widgets,
            da: inh.da,
            q: inh.q.unwrap_or(0),
            dv: inh.dv,
            opt: inh.opt.map(|o| self.options(&o)).unwrap_or_default(),
        };
        w.out.push((field, node));
    }

    /// The kids a field tree node `d` lists: those with a name, or with no `/Rect`, are
    /// fields of their own; the others are its widgets.
    fn kids_of(&self, d: &Dictionary) -> Kids {
        let kids: Vec<ObjectId> = d
            .get(b"Kids")
            .ok()
            .and_then(|o| self.doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
            .map(|a| a.iter().filter_map(|k| k.as_reference().ok()).collect())
            .unwrap_or_default();
        let (fields, widgets): (Vec<ObjectId>, Vec<ObjectId>) = kids.into_iter().partition(|k| {
            #[cfg(test)]
            tests::LOOKED.set(tests::LOOKED.get() + 1);
            self.doc
                .get_dictionary(*k)
                .is_ok_and(|k| k.has(b"T") || !k.has(b"Rect"))
        });
        Kids {
            fields: fields.into(),
            widgets: widgets.into(),
            taken: None,
            looked: None,
        }
    }

    /// A terminal field of `kind` from its dictionary, what it inherits and its widgets.
    fn make_field(
        &self,
        name: String,
        d: &Dictionary,
        kind: FieldKind,
        inh: &Inherited,
        widgets: &[ObjectId],
        w: &mut Walk,
    ) -> Field {
        let ff = inh.ff;
        let opt = inh
            .opt
            .as_ref()
            .map(|o| self.options(o))
            .unwrap_or_default();
        let mut ws: Vec<Widget> = widgets
            .iter()
            .filter_map(|&id| self.widget(id, w))
            .collect();
        for wd in &mut ws {
            wd.export = wd.on_state.as_deref().map(|s| button_export(s, &opt));
            wd.align = Align::of_q(self.widget_q(wd.id, inh.q.unwrap_or(0)));
        }
        let value = self.value_of(&kind, inh.v.as_ref(), &opt, widgets);
        let options = match &kind {
            FieldKind::Check | FieldKind::Radio => {
                let mut options: Vec<(String, String)> = Vec::new();
                for s in widgets.iter().filter_map(|&id| self.on_state(id)) {
                    let e = button_export(&s, &opt);
                    if !options.iter().any(|o| o.0 == e) {
                        options.push((e.clone(), e));
                    }
                }
                options
            }
            FieldKind::Choice { .. } => opt,
            _ => Vec::new(),
        };
        Field {
            name,
            kind,
            value,
            options,
            read_only: ff & READ_ONLY != 0,
            required: ff & REQUIRED != 0,
            tooltip: d.get(b"TU").ok().and_then(|o| self.shown_text_value(o)),
            text_size: inh.da.as_deref().map_or(0.0, |da| parse_da(da).1),
            font: self.da_font(inh.da.as_deref()),
            widgets: ws,
        }
    }

    /// The font a value is set in for the `/DA` `da` when the font it names can't be used
    /// as it is ([`Field::font`], as `form_write`'s `pick_font` picks it).
    fn da_font(&self, da: Option<&[u8]>) -> FontChoice {
        let base = (da.and_then(|da| parse_da(da).0))
            .and_then(|name| self.dr_font(&name))
            .and_then(|font| {
                let d = self.dict_of(&font)?;
                Some(decode_text(d.get(b"BaseFont").ok()?.as_name().ok()?))
            });
        FontChoice::from_name(base.as_deref().unwrap_or("Helvetica"))
    }

    /// A widget annotation, if it is on a page.
    fn widget(&self, id: ObjectId, w: &mut Walk) -> Option<Widget> {
        #[cfg(test)]
        tests::LOOKED.set(tests::LOOKED.get() + 1);
        let d = self.doc.get_dictionary(id).ok()?;
        let (page, pid) = *w.pages.get(&id)?;
        let rect = self.rect(d.get(b"Rect").ok()?)?;
        let to_vis = *w
            .to_vis
            .entry(page)
            .or_insert_with(|| mx::inv(self.vis_down(pid).0));
        let on_state = self.on_state(id);
        let flags = d
            .get(b"F")
            .ok()
            .and_then(|o| self.int_value(o))
            .unwrap_or(0);
        Some(Widget {
            id,
            page,
            bbox: mx::transform_rect(to_vis?, rect),
            on_state,
            export: None,
            flags,
            align: Align::Left,
        })
    }

    /// A field's value from its `/V` (or `/DV`) entry. For buttons, `widgets` give the
    /// states, and `opt` the export values when the states are numbers.
    pub(crate) fn value_of(
        &self,
        kind: &FieldKind,
        v: Option<&Object>,
        opt: &[(String, String)],
        widgets: &[ObjectId],
    ) -> FieldValue {
        match kind {
            FieldKind::Text { .. } => {
                FieldValue::Text(v.and_then(|o| self.text_value(o)).unwrap_or_default())
            }
            FieldKind::Check | FieldKind::Radio => {
                let on = v
                    .and_then(|o| self.doc.dereference(o).ok())
                    .and_then(|(_, o)| o.as_name().ok())
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .filter(|n| n != "Off");
                // A checkbox is ticked only when its value is one of its widgets' states
                // (or, when they have no drawings to name states, when it isn't Off).
                if *kind == FieldKind::Check {
                    let states: Vec<String> =
                        widgets.iter().filter_map(|&w| self.on_state(w)).collect();
                    let ticked = on.is_some_and(|s| states.is_empty() || states.contains(&s));
                    FieldValue::Check(ticked)
                } else {
                    FieldValue::Choice(on.map(|s| button_export(&s, opt)).into_iter().collect())
                }
            }
            FieldKind::Choice { .. } => {
                let chosen = match v.map(|o| self.doc.dereference(o).map(|x| x.1)) {
                    Some(Ok(Object::Array(a))) => {
                        a.iter().filter_map(|o| self.text_value(o)).collect()
                    }
                    Some(Ok(o)) => self.text_value(o).into_iter().collect(),
                    _ => Vec::new(),
                };
                FieldValue::Choice(chosen)
            }
            FieldKind::Button | FieldKind::Signature => FieldValue::None,
        }
    }

    /// A checkbox or radio widget's "on" state: the name in its normal appearance other
    /// than `Off`.
    pub(crate) fn on_state(&self, widget: ObjectId) -> Option<String> {
        self.doc
            .get_dictionary(widget)
            .ok()?
            .get(b"AP")
            .ok()
            .and_then(|o| self.doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_dict().ok())
            .and_then(|ap| ap.get(b"N").ok())
            .and_then(|o| self.doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_dict().ok())
            .and_then(|n| {
                n.iter()
                    .map(|(k, _)| k)
                    .find(|k| k.as_slice() != b"Off")
                    .map(|k| String::from_utf8_lossy(k).into_owned())
            })
    }

    /// A choice field's `/Opt`: each entry a string, or an [export value, text shown]
    /// pair.
    fn options(&self, opt: &Object) -> Vec<(String, String)> {
        let Some(a) = self
            .doc
            .dereference(opt)
            .ok()
            .and_then(|(_, o)| o.as_array().ok())
        else {
            return Vec::new();
        };
        a.iter()
            .filter_map(|o| match self.doc.dereference(o).ok()?.1 {
                Object::Array(pair) if pair.len() >= 2 => {
                    Some((self.text_value(&pair[0])?, self.text_value(&pair[1])?))
                }
                o => {
                    let t = self.text_value(o)?;
                    Some((t.clone(), t))
                }
            })
            .take(MAX_FIELDS)
            .collect()
    }

    /// A text string (or a name, as some files write), decoded.
    pub(crate) fn text_value(&self, o: &Object) -> Option<String> {
        match self.doc.dereference(o).ok()?.1 {
            Object::String(s, _) => Some(decode_text(s)),
            Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
            Object::Stream(s) => {
                let data = s.decompressed_content_with_limit(crate::MAX_CONTENT).ok()?;
                Some(decode_text(&data))
            }
            _ => None,
        }
    }

    /// [`Pdf::text_value`] for text that is only shown, never used to find something
    /// ([`decode_shown_text`]).
    pub(crate) fn shown_text_value(&self, o: &Object) -> Option<String> {
        match self.doc.dereference(o).ok()?.1 {
            Object::String(s, _) => Some(decode_shown_text(s)),
            _ => self.text_value(o),
        }
    }

    pub(crate) fn int_value(&self, o: &Object) -> Option<i64> {
        self.doc.dereference(o).ok()?.1.as_i64().ok()
    }

    /// A string's raw bytes.
    pub(crate) fn string_bytes(&self, o: &Object) -> Option<Vec<u8>> {
        match self.doc.dereference(o).ok()?.1 {
            Object::String(s, _) => Some(s.clone()),
            _ => None,
        }
    }
}

/// A button state's export value: the state itself, or, when the field has `/Opt` and
/// the state is a number, that entry of `/Opt`.
pub(crate) fn button_export(state: &str, opt: &[(String, String)]) -> String {
    state
        .parse::<usize>()
        .ok()
        .and_then(|i| opt.get(i))
        .map_or_else(|| state.to_string(), |o| o.0.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;
    use std::cell::Cell;

    thread_local! {
        /// Field tree entries looked at on this thread: nodes walked, kids told apart and
        /// widgets read.
        pub(super) static LOOKED: Cell<usize> = const { Cell::new(0) };
    }

    /// A form of `n` fields, `field(i)` each, listed in `/Fields` and each with the same
    /// `/Kids` array object, which `kids` makes from the fields' ids.
    fn sharing(
        n: usize,
        field: impl Fn(usize) -> Dictionary,
        kids: impl FnOnce(&mut Pdf, &[ObjectId]) -> Vec<Object>,
    ) -> Pdf {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let shared = p.doc.new_object_id();
        let ids: Vec<ObjectId> = (0..n)
            .map(|i| {
                let mut d = field(i);
                d.set("Kids", shared);
                p.doc.add_object(d)
            })
            .collect();
        let list = kids(&mut p, &ids);
        p.doc.objects.insert(shared, Object::Array(list));
        let fields: Vec<Object> = ids.iter().map(|&id| id.into()).collect();
        let form = dictionary! { "Fields" => fields };
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        p
    }

    fn name(i: usize) -> Object {
        Object::string_literal(format!("f{i}"))
    }

    fn text_field(i: usize) -> Dictionary {
        dictionary! { "FT" => "Tx", "T" => name(i) }
    }

    fn widget() -> Dictionary {
        let rect: Vec<Object> = vec![0.into(), 0.into(), 10.into(), 10.into()];
        dictionary! { "Subtype" => "Widget", "Rect" => rect }
    }

    /// How many widgets each field takes.
    fn taken(p: &Pdf) -> Vec<usize> {
        let out = p.field_nodes(Reach::Every).0;
        out.iter().map(|(_, node)| node.widgets.len()).collect()
    }

    #[test]
    fn fields_sharing_their_kids_are_walked_once() {
        // Each field lists the same `n` fields as its kids: they were told apart and walked
        // again for each field.
        let n = 2_000;
        let p = sharing(
            n,
            |i| dictionary! { "T" => name(i) },
            |p, _| {
                let kid = |i| p.doc.add_object(text_field(n + i)).into();
                (0..n).map(kid).collect()
            },
        );
        LOOKED.set(0);
        let out = p.field_nodes(Reach::Every).0;
        assert!(LOOKED.get() < 4 * n, "looked at {} entries", LOOKED.get());
        assert_eq!(out.len(), n);
        assert_eq!(out[0].0.name, format!("f0.f{n}"));
        LOOKED.set(0);
        assert_eq!(p.value_nodes().unwrap().len(), 2 * n);
        assert!(LOOKED.get() < 4 * n, "looked at {} entries", LOOKED.get());

        // Each field lists every field, a loop: the kids are walked again only as the walk
        // goes deeper, to as deep as fields may be.
        let p = sharing(
            n,
            |i| dictionary! { "T" => name(i) },
            |_, ids| ids.iter().map(|&id| id.into()).collect(),
        );
        LOOKED.set(0);
        assert!(p.field_nodes(Reach::Every).1);
        let most = 4 * (MAX_DEPTH + 2) * n;
        assert!(LOOKED.get() < most, "looked at {} entries", LOOKED.get());
    }

    #[test]
    fn widgets_shared_by_fields_go_to_the_first() {
        // Each field lists the same widgets as its kids: they were read again for each
        // field, and each field took them all.
        let (n, m) = (2_000, 2_000);
        let p = sharing(n, text_field, |p, _| {
            (0..m).map(|_| p.doc.add_object(widget()).into()).collect()
        });
        let most = 4 * (n + m);
        LOOKED.set(0);
        let each = taken(&p);
        assert!(LOOKED.get() < most, "looked at {} entries", LOOKED.get());
        assert_eq!(each.len(), n);
        assert_eq!(each[0], m);
        assert!(each[1..].iter().all(|&t| t == 0));
        LOOKED.set(0);
        assert_eq!(p.value_nodes().unwrap().len(), n + m);
        assert!(LOOKED.get() < most, "looked at {} entries", LOOKED.get());

        // As when each field lists the widget in an array of its own.
        let mut p = Pdf::new();
        let w = p.doc.add_object(widget());
        let fields: Vec<Object> = (0..2)
            .map(|i| {
                let mut f = text_field(i);
                f.set("Kids", vec![w.into()]);
                p.doc.add_object(f).into()
            })
            .collect();
        let form = dictionary! { "Fields" => fields };
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        assert_eq!(taken(&p), [1, 0]);
    }

    #[test]
    fn nodes_of_no_kind_sharing_widgets_read_them_once() {
        // Nodes of no kind, then a field, list the same widgets: each node of no kind read
        // them again, and the field still takes them all.
        let (n, m) = (2_000, 2_000);
        let node = |i| match i {
            i if i == n - 1 => text_field(i),
            i => dictionary! { "T" => name(i) },
        };
        let p = sharing(n, node, |p, _| {
            (0..m).map(|_| p.doc.add_object(widget()).into()).collect()
        });
        LOOKED.set(0);
        assert_eq!(taken(&p), [m]);
        let most = 4 * (n + m);
        assert!(LOOKED.get() < most, "looked at {} entries", LOOKED.get());
    }

    /// `/Fields [x, t]`, x of no kind and t a text field, both listing kid k, a field of no
    /// kind of its own with a widget, in a `/Kids` array of their own each or the same one.
    fn kid_of_a_node_of_no_kind_first(shared: bool) -> Pdf {
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let w = p.doc.add_object(widget());
        let k = dictionary! { "T" => "k", "Kids" => vec![w.into()] };
        let k: Object = p.doc.add_object(k).into();
        let mut list = || -> Object {
            match shared {
                true => p.doc.add_object(vec![k.clone()]).into(),
                false => vec![k.clone()].into(),
            }
        };
        let x_list = list();
        let t_list = if shared { x_list.clone() } else { list() };
        let x = dictionary! { "T" => "x", "Kids" => x_list };
        let t = dictionary! { "FT" => "Tx", "T" => "t", "Kids" => t_list };
        let (x, t) = (p.doc.add_object(x), p.doc.add_object(t));
        let form = dictionary! { "Fields" => vec![x.into(), t.into()] };
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        p
    }

    #[test]
    fn a_kid_listed_first_by_a_node_of_no_kind_is_the_next_fields() {
        // k was marked seen under x, where it is no field, and t's list taken: t lost it.
        for shared in [false, true] {
            let p = kid_of_a_node_of_no_kind_first(shared);
            let out = p.field_nodes(Reach::Every).0;
            let got: Vec<_> = (out.iter())
                .map(|(f, n)| (f.name.as_str(), n.widgets.len()))
                .collect();
            assert_eq!(got, [("t.k", 1)], "shared {shared}");
        }
    }

    #[test]
    fn nodes_of_no_kind_sharing_kid_fields_walk_them_once() {
        // Nodes of no kind, then a field, list the same kid fields of no kind of their own:
        // each is walked once as no field and once as the field's.
        let n = 2_000;
        let node = |i| match i {
            i if i == n - 1 => text_field(i),
            i => dictionary! { "T" => name(i) },
        };
        let p = sharing(n, node, |p, _| {
            let kid = |i| p.doc.add_object(dictionary! { "T" => name(n + i) }).into();
            (0..n).map(kid).collect()
        });
        LOOKED.set(0);
        let out = p.field_nodes(Reach::Every).0;
        assert!(LOOKED.get() < 6 * n, "looked at {} entries", LOOKED.get());
        assert_eq!(out.len(), n);
        assert_eq!(out[0].0.name, format!("f{}.f{n}", n - 1));
    }

    #[test]
    fn nodes_of_no_kind_reached_again_are_walked_once() {
        // Two fields below 20 layers of two nodes of no kind, each listing both nodes of the
        // layer below it: 2^20 ways down, each node walked once.
        let layers = 20;
        let mut p = Pdf::new();
        p.insert_blank(0, 300.0, 200.0).unwrap();
        let mut below: Vec<Object> = (0..2)
            .map(|i| p.doc.add_object(text_field(i)).into())
            .collect();
        for l in 0..layers {
            below = (0..2)
                .map(|i| {
                    let d = dictionary! { "T" => name(2 * l + i + 2), "Kids" => below.clone() };
                    p.doc.add_object(d).into()
                })
                .collect();
        }
        let form = dictionary! { "Fields" => below };
        p.doc.catalog_mut().unwrap().set("AcroForm", form);
        LOOKED.set(0);
        let out = p.field_nodes(Reach::Every).0;
        let looked = LOOKED.get();
        assert!(looked < 10 * layers, "looked at {looked} entries");
        assert_eq!(out.len(), 2);
    }
}
