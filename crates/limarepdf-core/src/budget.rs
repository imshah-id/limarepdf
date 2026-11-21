//! Work budgets: one for each operation that follows a document's structure wherever it
//! leads, charged across all of it, so a file built to be followed for ever (or for hours) is
//! refused with a [`TooComplex`] instead, before anything is changed.

use lopdf::{DecompressError, Stream};

/// What a stream's first try at decoding is limited to, when it has fewer bytes of its own
/// ([`Work::decode`]).
const FIRST_TRY: u64 = 4 << 10;

/// The work an operation may still do.
pub(crate) struct Work {
    left: u64,
    what: &'static str,
    limit: u64,
    /// Whether a test's [`budget_seam`] keeps what it took.
    #[cfg(any(test, feature = "test-seams"))]
    kept: bool,
}

/// An operation's limit, `normal` steps; a test can set another through [`budget_seam`].
pub(crate) fn limit(normal: u64) -> u64 {
    #[cfg(any(test, feature = "test-seams"))]
    if let Some(n) = budget_seam::limit() {
        return n;
    }
    normal
}

/// A test's limit ([`budget_seam`]) on the thread that hands work to others, carried to
/// them ([`Carry::run`]); outside tests, nothing.
#[derive(Clone, Copy)]
pub(crate) struct Carry {
    #[cfg(any(test, feature = "test-seams"))]
    limit: Option<u64>,
}

impl Carry {
    /// This thread's limit.
    pub(crate) fn here() -> Carry {
        Carry {
            #[cfg(any(test, feature = "test-seams"))]
            limit: budget_seam::limit(),
        }
    }

    /// Run `f` with the limit carried.
    pub(crate) fn run<T>(self, f: impl FnOnce() -> T) -> T {
        #[cfg(any(test, feature = "test-seams"))]
        return budget_seam::carried(self.limit, f);
        #[cfg(not(any(test, feature = "test-seams")))]
        f()
    }
}

impl Work {
    /// A budget of `limit` steps for `what` (as the refusal names it: "checking the
    /// drawings").
    pub(crate) fn new(what: &'static str, limit: u64) -> Work {
        Work {
            left: limit,
            what,
            limit,
            #[cfg(any(test, feature = "test-seams"))]
            kept: true,
        }
    }

    /// A budget like [`Work::new`]'s that a test's [`budget_seam`] doesn't keep: for a walk
    /// many operations make on their way, whose own steps leave it out.
    pub(crate) fn unkept(what: &'static str, limit: u64) -> Work {
        Work {
            left: limit,
            what,
            limit,
            #[cfg(any(test, feature = "test-seams"))]
            kept: false,
        }
    }

    /// Take `n` steps; refused, with nothing taken, when fewer are left.
    pub(crate) fn take(&mut self, n: u64) -> Result<(), TooComplex> {
        if n > self.left {
            return Err(self.refusal());
        }
        self.left -= n;
        Ok(())
    }

    /// The refusal for taking more steps than are left.
    pub(crate) fn refusal(&self) -> TooComplex {
        TooComplex {
            what: self.what,
            limit: self.limit,
        }
    }

    /// Stream `s` decoded within the steps left, charged a step for each of its own bytes
    /// and each byte its filters give, a failure too. lopdf limits each filter to a try's
    /// size, so a try takes at most its bytes and that size for each filter: it is tried at
    /// its own size (4 KiB at least), then four times larger as far as the steps left
    /// allow, each try that fails charged all it could take, and refused past them. `None`
    /// when it can't be decoded or gives more than [`crate::MAX_CONTENT`] bytes.
    pub(crate) fn decode(&mut self, s: &Stream) -> Result<Option<Vec<u8>>, TooComplex> {
        let filters = s.filters().map_or(0, |f| f.len()) as u64;
        if filters > Stream::MAX_FILTERS as u64 {
            // lopdf decodes none of it.
            self.take(filters)?;
            return Ok(None);
        }
        let (own, most) = (s.content.len() as u64, crate::MAX_CONTENT as u64);
        let fits = |left: u64| match filters {
            0 => most,
            n => (left.saturating_sub(own) / n).min(most),
        };
        let mut size = own.max(FIRST_TRY).min(fits(self.left));
        if own + filters * size > self.left {
            return Err(self.refusal());
        }
        loop {
            let at_most = own + filters * size;
            match s.decompressed_content_with_limit(size as usize) {
                Ok(data) => {
                    // The last filter gives what was decoded, the others at most the size.
                    let given = match filters {
                        0 => 0,
                        n => (n - 1) * size + data.len() as u64,
                    };
                    self.take(own + given)?;
                    return Ok(Some(data));
                }
                Err(lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => {
                    self.take(at_most)?;
                    if size == most {
                        return Ok(None);
                    }
                    let next = (4 * size).min(fits(self.left));
                    if next <= size {
                        return Err(self.refusal());
                    }
                    size = next;
                }
                Err(_) => {
                    self.take(at_most)?;
                    return Ok(None);
                }
            }
        }
    }

    /// The steps taken so far.
    #[cfg(any(test, feature = "test-seams"))]
    pub(crate) fn taken(&self) -> u64 {
        self.limit - self.left
    }
}

#[cfg(any(test, feature = "test-seams"))]
impl Drop for Work {
    fn drop(&mut self) {
        if self.kept {
            budget_seam::record(self.taken());
        }
    }
}

/// An operation was refused because the document is too complex to go through within its
/// budget; nothing was changed. Found through the error's chain (`downcast_ref`), like
/// [`crate::NotConfirmed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TooComplex {
    /// What the steps were for: "checking the drawings".
    pub what: &'static str,
    /// The steps allowed.
    pub limit: u64,
}

impl std::fmt::Display for TooComplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the document is too complex: {} would take more than {} steps, so nothing was changed",
            self.what, self.limit
        )
    }
}

impl std::error::Error for TooComplex {}

/// A test seam: operations on this thread get another limit ([`limit`]), and what each
/// budget took is kept, so a test can show a budget trips one step over what an operation
/// needs. A program a test runs (the CLI) takes its limit from [`budget_seam::VAR`]. Built
/// only for tests (core's own, and through the `test-seams` feature).
#[cfg(any(test, feature = "test-seams"))]
pub mod budget_seam {
    use std::cell::{Cell, RefCell};

    /// The limit, in steps, of every operation in a program a test runs, on threads with
    /// none of their own.
    pub const VAR: &str = "LIMAREPDF_TEST_BUDGET";

    thread_local! {
        static LIMIT: Cell<Option<u64>> = const { Cell::new(None) };
        static TAKEN: RefCell<Option<Vec<u64>>> = const { RefCell::new(None) };
    }

    /// Runs `f` with the operations on this thread meanwhile limited to `limit` steps.
    /// Returns what `f` returned, and the steps each budget made meanwhile took, in the
    /// order they were made.
    pub fn with_limit<T>(limit: u64, f: impl FnOnce() -> T) -> (T, Vec<u64>) {
        let was = LIMIT.replace(Some(limit));
        let kept = TAKEN.replace(Some(Vec::new()));
        let out = f();
        LIMIT.set(was);
        let taken = TAKEN.replace(kept).unwrap_or_default();
        (out, taken)
    }

    pub(super) fn limit() -> Option<u64> {
        LIMIT
            .get()
            .or_else(|| std::env::var(VAR).ok()?.parse().ok())
    }

    /// Runs `f` with the operations on this thread meanwhile limited to `limit`, another
    /// thread's ([`super::Carry`]).
    pub(super) fn carried<T>(limit: Option<u64>, f: impl FnOnce() -> T) -> T {
        let was = LIMIT.replace(limit);
        let out = f();
        LIMIT.set(was);
        out
    }

    pub(super) fn record(taken: u64) {
        TAKEN.with_borrow_mut(|t| {
            if let Some(t) = t {
                t.push(taken);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_up_to_the_limit_are_taken_and_one_more_is_refused() {
        let ((), taken) = budget_seam::with_limit(5, || {
            let mut w = Work::new("counting", limit(1000));
            assert_eq!(w.take(3), Ok(()));
            assert_eq!(w.take(2), Ok(()));
            let e = w.take(1).unwrap_err();
            assert_eq!(
                e,
                TooComplex {
                    what: "counting",
                    limit: 5
                }
            );
            assert_eq!(w.taken(), 5);
        });
        assert_eq!(taken, vec![5]);
    }

    #[test]
    fn a_refusal_is_found_through_the_error_chain() {
        let mut w = Work::new("counting", 0);
        let e = anyhow::Error::from(w.take(1).unwrap_err()).context("redacting");
        let t = e.downcast_ref::<TooComplex>().expect("too complex");
        assert_eq!(t.limit, 0);
        assert!(format!("{e:#}").contains("counting would take more than 0 steps"));
    }

    /// A stream is charged its own bytes and what each of its filters gives: tried at 4 KiB
    /// and then 16, a deflated one is charged both tries; one that can't be decoded, all its
    /// try could take; one giving more than the steps left allow, refused.
    #[test]
    fn a_stream_is_charged_its_bytes_and_what_its_filters_give() {
        use lopdf::dictionary;
        let mut w = Work::new("decoding", 1_000);
        let plain = Stream::new(dictionary! {}, vec![b'a'; 100]);
        let decoded = (w.decode(&plain), w.taken());
        assert_eq!(decoded, (Ok(Some(vec![b'a'; 100])), 100));
        let hex = |s: &[u8]| Stream::new(dictionary! { "Filter" => "ASCIIHexDecode" }, s.into());
        let mut w = Work::new("decoding", 1_000);
        let decoded = (w.decode(&hex(b"4142")), w.taken());
        assert_eq!(decoded, (Ok(Some(b"AB".to_vec())), 4 + 2));
        let mut w = Work::new("decoding", 1_000);
        assert_eq!((w.decode(&hex(b"zz")), w.taken()), (Ok(None), 1_000));
        let mut w = Work::new("decoding", 5);
        assert_eq!(w.decode(&hex(b"4142")), Err(w.refusal()));
        let mut flate = Stream::new(dictionary! {}, vec![b'a'; 10_000]);
        flate.compress().unwrap();
        let own = flate.content.len() as u64;
        let mut w = Work::new("decoding", 1_000_000);
        let decoded = (w.decode(&flate), w.taken());
        let taken = (own + 4_096) + (own + 10_000);
        assert_eq!(decoded, (Ok(Some(vec![b'a'; 10_000])), taken));
    }
}
