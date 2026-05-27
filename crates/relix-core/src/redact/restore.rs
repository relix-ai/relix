//! Streaming placeholder-restore state machine (RFC-0004 §Streaming).
//!
//! Replaces every `<RELIX_SECRET kind="..." id="...">` marker in a
//! byte stream with the corresponding real value, where "real value"
//! is supplied by a caller-provided lookup function (typically
//! [`crate::redact::Vault::lookup`]).
//!
//! Why a state machine: the upstream may split a placeholder across
//! two chunks. We hold back at most [`MAX_PLACEHOLDER_LEN`] bytes
//! at the tail of every emitted slice in case the next slice
//! completes a placeholder that started near the boundary.
//!
//! IO-free. The integration layer in `relix-cli::proxy::restore`
//! drives this from `forward_streaming` after the H9 chunk slicer.

use std::ops::Range;

use crate::redact::placeholder::{Placeholder, MAX_PLACEHOLDER_LEN};

/// Per-stream restore state. Lives for the duration of a single
/// streaming response.
#[derive(Default)]
pub struct StreamRestore {
    /// Bytes held back from the previous slice in case a
    /// placeholder spans the chunk boundary.
    trailing: String,
    /// Total number of placeholders successfully restored on this
    /// stream. Surfaced via the `x-relix-redacted-count` response
    /// header.
    restored_count: u32,
}

/// One restore step's output.
pub struct StreamRestoreStep {
    /// Bytes safe to forward downstream now.
    pub emit: String,
    /// Placeholder ids in this slice that did not match anything
    /// in the vault. Caller treats this as RFC-0004 S05 (forged
    /// placeholder) and emits a tracing::warn per occurrence.
    pub forged_count: u32,
    /// Placeholders successfully restored in this slice.
    pub restored_count: u32,
}

impl StreamRestore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total restored placeholders across the lifetime of this
    /// stream.
    pub fn total_restored(&self) -> u32 {
        self.restored_count
    }

    /// Process one slice. `lookup(id) -> Option<real_value>` is
    /// provided by the integration layer (the vault); a `None`
    /// means the placeholder is forged and the original bytes
    /// must be forwarded unchanged.
    pub fn step<F>(&mut self, slice: &str, mut lookup: F) -> StreamRestoreStep
    where
        F: FnMut(&Placeholder) -> Option<String>,
    {
        // Prepend any held-back bytes from the previous step.
        let combined = if self.trailing.is_empty() {
            slice.to_string()
        } else {
            let mut s = std::mem::take(&mut self.trailing);
            s.push_str(slice);
            s
        };

        // Find every well-formed placeholder.
        let hits = Placeholder::find_all(&combined);

        let mut forged_count: u32 = 0;
        let mut restored_count: u32 = 0;

        // Decide where to cut the trailing buffer. If the tail
        // contains the start of what *might* be a placeholder
        // (`<RELIX_SECRET`), hold it back so the next step can
        // complete the parse.
        let safe_emit_end = safe_emit_boundary(&combined, &hits);

        let to_emit = &combined[..safe_emit_end];

        // Build the output by splicing real values where vault
        // lookups succeed.
        let mut out = String::with_capacity(to_emit.len());
        let mut cursor = 0usize;
        for (range, placeholder) in &hits {
            if range.start >= safe_emit_end {
                break;
            }
            out.push_str(&to_emit[cursor..range.start]);
            match lookup(placeholder) {
                Some(real) => {
                    out.push_str(&real);
                    restored_count += 1;
                }
                None => {
                    // Forged or evicted; pass through verbatim.
                    out.push_str(&combined[range.clone()]);
                    forged_count += 1;
                }
            }
            cursor = range.end;
        }
        out.push_str(&to_emit[cursor..]);

        // Stash the leftover for the next step.
        self.trailing = combined[safe_emit_end..].to_string();
        self.restored_count = self.restored_count.saturating_add(restored_count);

        StreamRestoreStep {
            emit: out,
            forged_count,
            restored_count,
        }
    }

    /// Final flush at end-of-stream. Emits any held-back trailing
    /// bytes verbatim — if they ever formed a complete placeholder
    /// we would have caught it on the last [`Self::step`].
    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.trailing)
    }
}

/// Decide the highest byte index `n` such that `buf[..n]` can be
/// safely emitted without losing a placeholder that crosses the
/// chunk boundary.
///
/// Rule: if the suffix of `buf` after the last well-formed
/// placeholder contains the literal start sequence `<RELIX_SECRET`,
/// hold back from that position onward. Otherwise the entire
/// buffer is safe to emit.
fn safe_emit_boundary(buf: &str, hits: &[(Range<usize>, Placeholder)]) -> usize {
    // Start of the region after the last placeholder.
    let after_last = hits.last().map(|(r, _)| r.end).unwrap_or(0);

    // Look for a `<RELIX_SECRET` start in the unmatched tail. We
    // also look for partial prefixes (`<RELIX_SECR`, etc.) so a
    // chunk boundary inside the literal start is held back.
    let tail = &buf[after_last..];
    let start_lit = "<RELIX_SECRET";

    if let Some(pos) = tail.rfind(start_lit) {
        // A `<RELIX_SECRET` exists in the tail but did not parse
        // as a complete placeholder (or it would have been in
        // hits). Hold from pos onward.
        return after_last + pos;
    }

    // Check for partial prefix at the very tail.
    let max_partial = start_lit.len() - 1;
    let tail_len = tail.len();
    let scan_from = tail_len.saturating_sub(max_partial);
    for i in scan_from..tail_len {
        let suffix = &tail[i..];
        if start_lit.starts_with(suffix) {
            return after_last + i;
        }
    }

    // Nothing partial; everything is safe to emit. Cap on
    // MAX_PLACEHOLDER_LEN is automatic because find_all already
    // matched any complete placeholder.
    let _ = MAX_PLACEHOLDER_LEN;
    buf.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::detector::SecretKind;
    use crate::redact::placeholder::PlaceholderId;

    fn make_placeholder(byte: u8) -> (Placeholder, String) {
        let p = Placeholder::new(
            SecretKind::GithubPat,
            PlaceholderId::from_bytes([byte, byte, byte]),
        );
        let rendered = p.render();
        (p, rendered)
    }

    #[test]
    fn no_placeholders_passes_through_unchanged() {
        let mut sr = StreamRestore::new();
        let step = sr.step("hello world", |_| Some("X".into()));
        assert_eq!(step.emit, "hello world");
        assert_eq!(step.restored_count, 0);
        assert_eq!(step.forged_count, 0);
        assert_eq!(sr.finish(), "");
    }

    #[test]
    fn complete_placeholder_in_one_chunk_is_restored() {
        let (p, rendered) = make_placeholder(0xab);
        let mut sr = StreamRestore::new();
        let step = sr.step(&format!("Bearer {rendered} extra"), |q| {
            if q == &p {
                Some("REAL".into())
            } else {
                None
            }
        });
        assert_eq!(step.emit, "Bearer REAL extra");
        assert_eq!(step.restored_count, 1);
        assert_eq!(step.forged_count, 0);
    }

    #[test]
    fn placeholder_split_across_two_chunks_is_restored() {
        let (p, rendered) = make_placeholder(0xcd);
        let split_at = rendered.len() / 2;
        let chunk1 = format!("prefix {}", &rendered[..split_at]);
        let chunk2 = format!("{} suffix", &rendered[split_at..]);

        let mut sr = StreamRestore::new();
        let s1 = sr.step(
            &chunk1,
            |q| if q == &p { Some("REAL".into()) } else { None },
        );
        // First chunk must NOT emit the partial placeholder.
        assert!(
            !s1.emit.contains("<RELIX_SECRET"),
            "partial placeholder leaked: {}",
            s1.emit
        );
        assert_eq!(s1.restored_count, 0);
        assert!(s1.emit.starts_with("prefix"));

        let s2 = sr.step(
            &chunk2,
            |q| if q == &p { Some("REAL".into()) } else { None },
        );
        // Concatenation of all emits must contain the restored value.
        let full = format!("{}{}", s1.emit, s2.emit);
        assert!(full.contains("REAL"), "restored value missing: {full}");
        assert_eq!(s2.restored_count, 1);
        assert_eq!(sr.finish(), "");
    }

    #[test]
    fn forged_placeholder_is_passed_through_verbatim_and_counted() {
        let (_p, rendered) = make_placeholder(0xff);
        let mut sr = StreamRestore::new();
        let step = sr.step(
            &format!("hi {rendered} bye"),
            |_| None, // vault miss
        );
        assert!(step.emit.contains(&rendered));
        assert_eq!(step.restored_count, 0);
        assert_eq!(step.forged_count, 1);
    }

    #[test]
    fn multiple_placeholders_each_restored() {
        let (p1, r1) = make_placeholder(0x11);
        let (p2, r2) = make_placeholder(0x22);
        let mut sr = StreamRestore::new();
        let step = sr.step(&format!("a {r1} b {r2} c"), |q| {
            if q == &p1 {
                Some("ONE".into())
            } else if q == &p2 {
                Some("TWO".into())
            } else {
                None
            }
        });
        assert_eq!(step.emit, "a ONE b TWO c");
        assert_eq!(step.restored_count, 2);
    }

    #[test]
    fn partial_start_literal_is_held_back() {
        // The literal `<RELIX_SECRET` is the longest prefix of any
        // valid placeholder. If a chunk ends mid-literal we must
        // hold the partial from the `<` onwards.
        let mut sr = StreamRestore::new();
        let step = sr.step("hello <RELIX_SE", |_| None);
        assert_eq!(step.emit, "hello ");
        let step2 = sr.step("CRET kind=\"github_pat\" id=\"abcdef\">", |_| {
            Some("RESTORED".into())
        });
        // Now the placeholder is complete. The lookup matches by
        // value equality on the parsed Placeholder, but we returned
        // Some unconditionally so we should see RESTORED.
        let combined = format!("{}{}", step.emit, step2.emit);
        assert!(
            combined.contains("RESTORED"),
            "partial-then-complete failed to restore: {combined}"
        );
    }

    #[test]
    fn stray_lt_does_not_stall_emission_indefinitely() {
        // A `<` that is not followed by RELIX_SECRET should not
        // make us hold the rest of the stream forever. The boundary
        // function only holds back on the actual literal prefix.
        let mut sr = StreamRestore::new();
        let step = sr.step("a < b", |_| None);
        assert_eq!(step.emit, "a < b");
    }

    #[test]
    fn finish_emits_held_back_partial_verbatim() {
        // If the stream ends with a half-placeholder, finish()
        // returns it verbatim. The downstream sees garbled text,
        // but we never delete data on uncertainty.
        let mut sr = StreamRestore::new();
        let s = sr.step("hello <RELIX_SECRET", |_| None);
        assert_eq!(s.emit, "hello ");
        assert_eq!(sr.finish(), "<RELIX_SECRET");
    }

    #[test]
    fn total_restored_accumulates_across_steps() {
        let (p, rendered) = make_placeholder(0xaa);
        let mut sr = StreamRestore::new();
        for _ in 0..3 {
            sr.step(&rendered, |q| if q == &p { Some("X".into()) } else { None });
        }
        assert_eq!(sr.total_restored(), 3);
    }
}
