//! CSV formula injection defense and cell sanitization.

/// Sanitizes a string for inclusion in a CSV cell to prevent CSV / formula injection.
///
/// In spreadsheet software (e.g. Microsoft Excel, LibreOffice Calc, Google Sheets),
/// cells starting with `=`, `+`, `-`, `@`, `\t`, `\r`, or `\n` can be interpreted
/// as formulas or commands.
///
/// If `input` starts with any of these characters, or if `input` with leading whitespace
/// trimmed starts with a formula trigger (`=`, `+`, `-`, `@`), this function prefixes
/// the string with a single quote (`'`) so spreadsheet processors treat the cell contents
/// strictly as plain text.
#[must_use]
pub fn sanitize_csv_cell(input: &str) -> String {
    let raw_trigger = input.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']);
    let trimmed_trigger = input.trim_start().starts_with(['=', '+', '-', '@']);

    if raw_trigger || trimmed_trigger {
        format!("'{input}")
    } else {
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_string_unchanged() {
        assert_eq!(sanitize_csv_cell("normal_text"), "normal_text");
        assert_eq!(sanitize_csv_cell("12345"), "12345");
        assert_eq!(sanitize_csv_cell(""), "");
    }

    #[test]
    fn test_formula_injection_prefixed() {
        assert_eq!(sanitize_csv_cell("=1+1"), "'=1+1");
        assert_eq!(
            sanitize_csv_cell("+cmd|' /C calc'!A0"),
            "'+cmd|' /C calc'!A0"
        );
        assert_eq!(sanitize_csv_cell("-123"), "'-123");
        assert_eq!(sanitize_csv_cell("@SUM(1,2)"), "'@SUM(1,2)");
        assert_eq!(sanitize_csv_cell("\t=cmd"), "'\t=cmd");
        assert_eq!(sanitize_csv_cell("\r=calc"), "'\r=calc");
        assert_eq!(sanitize_csv_cell("\n=calc"), "'\n=calc");
    }

    #[test]
    fn test_leading_control_whitespace_prefixed() {
        assert_eq!(sanitize_csv_cell("\tSAFE"), "'\tSAFE");
        assert_eq!(sanitize_csv_cell("\rSAFE"), "'\rSAFE");
        assert_eq!(sanitize_csv_cell("\nSAFE"), "'\nSAFE");
    }

    #[test]
    fn test_leading_spaces_with_formula_character() {
        assert_eq!(sanitize_csv_cell("   =cmd"), "'   =cmd");
        assert_eq!(sanitize_csv_cell("  +123"), "'  +123");
        assert_eq!(sanitize_csv_cell("  @evil"), "'  @evil");
    }
}
