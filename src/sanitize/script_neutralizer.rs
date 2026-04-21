/// Comments out the specified 1-indexed lines in a C# source string.
///
/// Each matched line is replaced with `/* SANITIZED */ // <original line>`.
/// Lines not in `lines_to_comment` are emitted unchanged.
pub fn neutralize_script(source: &str, lines_to_comment: &[u64]) -> String {
    source
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if lines_to_comment.contains(&(i as u64 + 1)) {
                format!("/* SANITIZED */ // {line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neutralize_specific_lines() {
        let source = "using System;\nvoid Bad() { Process.Start(\"cmd\"); }\nvoid Good() {}";
        let result = neutralize_script(source, &[2]);
        assert!(result.contains("/* SANITIZED */"));
        assert!(result.contains("void Good() {}"));
        assert!(!result.lines().nth(1).unwrap().starts_with("void Bad"));
    }

    #[test]
    fn test_neutralize_no_lines() {
        let source = "using System;\nvoid Good() {}";
        let result = neutralize_script(source, &[]);
        assert_eq!(result, source);
    }
}
