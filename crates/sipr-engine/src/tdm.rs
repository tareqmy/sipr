//! `-tdmmap` and `[tdmmap]` (docs/SIPP_COMPAT.md §6 M39): a table of TDM
//! circuits, one handed to each outgoing call and released when it ends.
//!
//! The map `{x-x'}{h}{y-y'}{z-z'}` spans `(x'-x+1)·(y'-y+1)·(z'-z+1)`
//! circuits; circuit `n` renders as `X.h.Y/Z` with `Z` cycling fastest,
//! SIPp's formula in `call.cpp` (`E_Message_TDM_Map`).

/// A parsed `-tdmmap {a-b}{h}{c-d}{e-f}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdmMap {
    /// Width of the first range minus one (`tdm_map_a`).
    a: u32,
    /// Start of the first range (`tdm_map_x`).
    x: u32,
    /// The fixed middle value (`tdm_map_h`).
    h: u32,
    /// Width of the second range minus one (`tdm_map_b`).
    b: u32,
    /// Start of the second range (`tdm_map_y`).
    y: u32,
    /// Width of the third range minus one (`tdm_map_c`).
    c: u32,
    /// Start of the third range (`tdm_map_z`).
    z: u32,
}

/// SIPp's wording for a map that does not fit the shape.
const BAD_FORM: &str = "Parameter -tdmmap must be of form {%d-%d}{%d}{%d-%d}{%d-%d}";

impl TdmMap {
    /// Parse SIPp's `{0-3}{99}{5-8}{1-31}` form.
    ///
    /// # Errors
    ///
    /// SIPp's message when the text is not four brace groups of that shape
    /// or a range runs backwards.
    pub fn parse(text: &str) -> Result<Self, String> {
        let groups = brace_groups(text).ok_or_else(|| BAD_FORM.to_owned())?;
        let [first, middle, second, third] = groups.as_slice() else {
            return Err(BAD_FORM.to_owned());
        };
        let (x, x_end) = range(first)?;
        let h = single(middle)?;
        let (y, y_end) = range(second)?;
        let (z, z_end) = range(third)?;
        Ok(Self {
            a: x_end - x,
            x,
            h,
            b: y_end - y,
            y,
            c: z_end - z,
            z,
        })
    }

    /// How many circuits the map holds.
    #[must_use]
    pub fn circuits(&self) -> u32 {
        (self.a + 1) * (self.b + 1) * (self.c + 1)
    }

    /// `[tdmmap]` for circuit `number` (0-based): `X.h.Y/Z`.
    #[must_use]
    pub fn circuit(&self, number: u32) -> String {
        let per_x = (self.b + 1) * (self.c + 1);
        format!(
            "{}.{}.{}/{}",
            self.x + (number / per_x) % (self.a + 1),
            self.h,
            self.y + (number / (self.c + 1)) % (self.b + 1),
            self.z + number % (self.c + 1)
        )
    }
}

/// The contents of consecutive `{…}` groups making up the whole text.
fn brace_groups(text: &str) -> Option<Vec<&str>> {
    let mut rest = text.trim();
    let mut out = Vec::new();
    while !rest.is_empty() {
        let inner = rest.strip_prefix('{')?;
        let close = inner.find('}')?;
        out.push(&inner[..close]);
        rest = &inner[close + 1..];
    }
    Some(out)
}

fn number(s: &str) -> Result<u32, String> {
    s.trim().parse().map_err(|_| BAD_FORM.to_owned())
}

fn single(s: &str) -> Result<u32, String> {
    number(s)
}

fn range(s: &str) -> Result<(u32, u32), String> {
    let (lo, hi) = s.split_once('-').ok_or_else(|| BAD_FORM.to_owned())?;
    let (lo, hi) = (number(lo)?, number(hi)?);
    if hi < lo {
        return Err(BAD_FORM.to_owned());
    }
    Ok((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sipps_documented_map() {
        let m = TdmMap::parse("{0-3}{99}{5-8}{1-31}").unwrap();
        assert_eq!(
            m,
            TdmMap {
                a: 3,
                x: 0,
                h: 99,
                b: 3,
                y: 5,
                c: 30,
                z: 1
            }
        );
        assert_eq!(m.circuits(), 4 * 4 * 31);
    }

    #[test]
    fn circuits_follow_sipps_formula() {
        let m = TdmMap::parse("{0-3}{99}{5-8}{1-31}").unwrap();
        assert_eq!(m.circuit(0), "0.99.5/1");
        assert_eq!(m.circuit(1), "0.99.5/2");
        assert_eq!(m.circuit(30), "0.99.5/31");
        assert_eq!(m.circuit(31), "0.99.6/1");
        assert_eq!(m.circuit(124), "1.99.5/1");
        assert_eq!(m.circuit(495), "3.99.8/31");
        // Past the table it wraps, never panics.
        assert_eq!(m.circuit(496), "0.99.5/1");
    }

    #[test]
    fn bad_shapes_use_sipps_wording() {
        for bad in [
            "",
            "{0-3}{99}{5-8}",
            "{0-3}{99}{5-8}{1-31}{2}",
            "{3-0}{99}{5-8}{1-31}",
            "{0-3}{x}{5-8}{1-31}",
            "0-3,99,5-8,1-31",
            "{0-3}{99}{5-8}{1-31",
        ] {
            assert_eq!(TdmMap::parse(bad).unwrap_err(), BAD_FORM, "{bad}");
        }
    }
}
