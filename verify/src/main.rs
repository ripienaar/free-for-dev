use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
};

mod markdown;
mod networking;

use futures::{stream, stream::StreamExt};
use markdown::{extract_markdown_url, path_constructor};
use networking::url_is_valid;

use crate::markdown::find_indent_level;

#[tokio::main]
async fn main() {
    if let Ok(path) = path_constructor() {
        if let Ok(file) = File::open(&path) {
            match section_reader(file) {
                Ok(mut sections) => {
                    let client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::limited(10))
                        .build()
                        .unwrap();

                    let mut invalid_counter = 0;

                    let results: Vec<bool> = stream::iter(sections.iter())
                        .map(|s| {
                            let client = client.clone();
                            let url = s.url.clone();
                            async move { url_is_valid(&client, &url).await }
                        })
                        .buffered(100)
                        .collect()
                        .await;

                    for (s, valid) in sections.iter_mut().zip(results) {
                        if !valid {
                            invalid_counter += 1;
                        }
                        s.valid = valid;
                    }
                    println!("{} URLs checked", sections.len());
                    println!("{} Faulty URLs found", invalid_counter,);
                    if let Err(e) = construct_new_file(&path, sections) {
                        eprintln!("Failed to construct file: {:?}", e);
                    } else {
                        println!("Successfully updated file");
                    }
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                }
            }
        } else {
            eprintln!("Filed to open file at location: {:?}", path);
        }
    }
}

struct SectionState {
    url: String,
    start: usize,
}
impl SectionState {
    fn new(url: String, start: usize) -> Self {
        Self { url, start }
    }
}
struct Section {
    url: String,
    pos: [usize; 2],
    valid: bool,
}
impl Section {
    fn new(url: String, pos: [usize; 2]) -> Self {
        Self {
            url,
            pos,
            valid: true,
        }
    }
}

fn construct_new_file(path: &PathBuf, sections: Vec<Section>) -> std::io::Result<()> {
    // Read lines into memory in to preserve
    let content = fs::read_to_string(path)?;
    let mut lines: Vec<&str> = content.lines().collect();

    // Remove in reverse order to preserve index
    for section in sections.into_iter().rev() {
        if !section.valid {
            lines.drain(section.pos[0]..=section.pos[1]);
        }
    }

    // Write into tmp file first
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    for line in lines {
        writeln!(writer, "{}", line)?;
    }

    // Ensure all data is written
    writer.flush()?;

    Ok(())
}

fn section_reader(file: File) -> io::Result<Vec<Section>> {
    let reader = BufReader::new(file);
    let mut spaces: [usize; 2] = [0, 0];
    let mut current: Option<SectionState> = None;
    let mut out: Vec<Section> = Vec::new();
    let mut section_indent: usize = 0;

    fn end_section(current: SectionState, idx: usize, spaces: [usize; 2], out: &mut Vec<Section>) {
        let end = idx - 1;
        let [pre, post] = spaces;

        let pos = [current.start - pre, end - post];

        let section = Section::new(current.url, pos);
        out.push(section);
    }

    for (idx, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        let bytes = line.as_bytes();
        let trimmed = bytes.trim_ascii();
        let local_indent = find_indent_level(bytes);

        match trimmed {
            _ if current.is_some() && !trimmed.is_empty() && local_indent > section_indent => {
                // Regular line, can skip
                continue;
            }
            t if t.starts_with(b"- [") || t.starts_with(b"* [") => {
                // New URL found
                if let Some(url) = extract_markdown_url(bytes).filter(|u| !u.starts_with("#")) {
                    // Valid url is caught → start new section
                    section_indent = local_indent;
                    if let Some(c) = current.replace(SectionState::new(url.clone(), idx)) {
                        end_section(c, idx, spaces, &mut out);
                    }
                    // Reset spaces
                    spaces = [spaces[1], 0];
                }
            }
            _ if !trimmed.is_empty() && local_indent > section_indent => {
                if current.is_some() {
                    spaces[1] = 0
                } else {
                    spaces[0] = 0
                }
            }
            _ if trimmed.is_empty() => {
                if current.is_some() {
                    spaces[1] += 1
                } else {
                    spaces[0] += 1
                }
            }
            _ => {
                // normal non-empty, non-indented line → end section
                if let Some(c) = current.take() {
                    end_section(c, idx, spaces, &mut out);
                }
                spaces = [0, 0];
            }
        }
    }

    Ok(out)
}
