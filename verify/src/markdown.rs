use std::path::PathBuf;

pub fn extract_markdown_url(bytes: &[u8]) -> Option<String> {
    let start = memchr::memchr(b']', bytes)? + 1;
    let end = memchr::memchr(b')', &bytes[start..])?;

    let url_bytes = &bytes[start + 1..start + end];
    Some(String::from_utf8_lossy(url_bytes).to_string())
}

pub fn path_constructor() -> Result<PathBuf, ()> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let markdown_path = project_root.join("../README.md");

    if !markdown_path.exists() {
        eprintln!("Source markdown file \"README.md\" does not exist");
        return Err(());
    }

    Ok(markdown_path)
}

pub fn find_indent_level(line: &[u8]) -> usize {
    line.iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(line.len())
}
