// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::PathExt;
use crate::error::{Error, PathIo};
use anyhow::Result;
use std::fs;
use std::io;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};

#[derive(Clone, Copy)]
struct PathSyntax {
    separator: u8,
    case_insensitive: bool,
}

impl PathSyntax {
    const HOST: Self = Self {
        separator: MAIN_SEPARATOR as u8,
        case_insensitive: cfg!(windows),
    };

    fn is_separator(self, byte: u8) -> bool {
        byte == self.separator
    }

    fn fold(self, byte: u8) -> u8 {
        if self.case_insensitive {
            byte.to_ascii_lowercase()
        } else {
            byte
        }
    }

    fn matches_byte(self, pattern: u8, text: u8) -> bool {
        self.fold(pattern) == self.fold(text)
    }
}

pub(crate) struct GlobPattern<'a> {
    pattern: &'a str,
    syntax: PathSyntax,
}

impl<'a> GlobPattern<'a> {
    pub(crate) fn new(pattern: &'a str) -> Self {
        Self {
            pattern,
            syntax: PathSyntax::HOST,
        }
    }

    pub(crate) fn is_glob_byte(byte: u8) -> bool {
        matches!(byte, b'*' | b'?' | b'[' | b']')
    }

    pub(crate) fn is_glob_str(s: &str) -> bool {
        s.bytes().any(Self::is_glob_byte)
    }

    pub(crate) fn base(&self) -> PathBuf {
        let Some(glob_at) = self.pattern.bytes().position(Self::is_glob_byte) else {
            return PathBuf::from(self.pattern);
        };
        let prefix = &self.pattern[..glob_at];
        let mut base = if prefix.as_bytes().last() == Some(&(MAIN_SEPARATOR as u8)) {
            PathBuf::from(prefix)
        } else {
            Path::new(prefix)
                .parent()
                .map_or_else(|| PathBuf::from(prefix), Path::to_path_buf)
        };

        if base.as_os_str().is_empty() {
            base.push(MAIN_SEPARATOR.to_string());
        }

        base
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_path(&self, path: &Path) -> bool {
        let path_bytes = path.to_string_lossy();
        let pattern_bytes = self.pattern.as_bytes();
        let path_len = path_bytes.len();
        let pattern_len = pattern_bytes.len();
        let mut memo = vec![None; (pattern_len + 1) * (path_len + 1)];
        self.matches_at(pattern_bytes, path_bytes.as_bytes(), 0, 0, &mut memo)
    }

    pub(crate) fn matches_tree(&self, path: &Path) -> bool {
        path.ancestors().any(|ancestor| self.matches_path(ancestor))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_under(&self, root: &Path) -> bool {
        let base = self.base();
        if base.is_under(root) {
            return true;
        }
        if !root.is_under(&base) {
            return false;
        }
        let mut matches = Vec::new();
        self.collect_matches(root, &mut matches, 0).is_err() || !matches.is_empty()
    }

    pub(crate) fn expand(&self) -> Result<Vec<PathBuf>> {
        let base = self.base();
        let mut matches = Vec::new();

        match fs::symlink_metadata(&base) {
            Ok(_) => self.collect_matches(&base, &mut matches, 0)?,
            Err(error) if error.is_opaque() || error.kind() == io::ErrorKind::NotADirectory => {}
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        }

        Ok(matches)
    }

    fn collect_matches(&self, path: &Path, matches: &mut Vec<PathBuf>, depth: u32) -> Result<()> {
        const LIMIT: u32 = 40;

        if depth >= LIMIT {
            return Err(Error::PolicyTraversalDepth.into());
        }

        let candidate = path.clean_lexically();
        if self.matches_path(&candidate) {
            matches.push(candidate);
        }

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.is_opaque() => return Ok(()),
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(());
        }

        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.is_transport_failed() =>
            {
                return Ok(());
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.is_transport_failed() => continue,
                Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
            };
            self.collect_matches(&entry.path(), matches, depth + 1)?;
        }

        Ok(())
    }

    fn matches_at(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let memo_at = pattern_at * (text.len() + 1) + text_at;
        if let Some(result) = memo[memo_at] {
            return result;
        }

        let result = if pattern_at == pattern.len() {
            text_at == text.len()
        } else if self.globstar_at_separator(pattern, pattern_at) {
            self.globstar_slash_matches(pattern, text, pattern_at, text_at, memo)
        } else if pattern[pattern_at..].starts_with(b"**") {
            self.globstar_matches(pattern, text, pattern_at, text_at, memo)
        } else {
            match pattern[pattern_at] {
                b'*' => self.star_matches(pattern, text, pattern_at, text_at, memo),
                b'?' => {
                    text_at < text.len()
                        && !self.syntax.is_separator(text[text_at])
                        && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
                }
                b'[' => self.class_matches(pattern, text, pattern_at, text_at, memo),
                byte => {
                    text_at < text.len()
                        && self.syntax.matches_byte(byte, text[text_at])
                        && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
                }
            }
        };

        memo[memo_at] = Some(result);
        result
    }

    fn globstar_at_separator(&self, pattern: &[u8], pattern_at: usize) -> bool {
        pattern[pattern_at..].starts_with(b"**")
            && pattern
                .get(pattern_at + 2)
                .is_some_and(|byte| self.syntax.is_separator(*byte))
    }

    fn globstar_slash_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        if self.matches_at(pattern, text, pattern_at + 3, text_at, memo) {
            return true;
        }

        for next in text_at..text.len() {
            if self.syntax.is_separator(text[next])
                && self.matches_at(pattern, text, pattern_at + 3, next + 1, memo)
            {
                return true;
            }
        }

        false
    }

    fn globstar_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        for next in text_at..=text.len() {
            if self.matches_at(pattern, text, pattern_at + 2, next, memo) {
                return true;
            }
        }

        false
    }

    fn star_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let mut next = text_at;
        while next <= text.len() {
            if self.matches_at(pattern, text, pattern_at + 1, next, memo) {
                return true;
            }
            if next == text.len() || self.syntax.is_separator(text[next]) {
                break;
            }
            next += 1;
        }

        false
    }

    fn class_matches(
        &self,
        pattern: &[u8],
        text: &[u8],
        pattern_at: usize,
        text_at: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let Some(class_end) = pattern[pattern_at + 1..]
            .iter()
            .position(|byte| *byte == b']')
            .map(|offset| pattern_at + 1 + offset)
        else {
            return text_at < text.len()
                && self.syntax.matches_byte(b'[', text[text_at])
                && self.matches_at(pattern, text, pattern_at + 1, text_at + 1, memo);
        };

        text_at < text.len()
            && !self.syntax.is_separator(text[text_at])
            && self.byte_in_class(text[text_at], &pattern[pattern_at + 1..class_end])
            && self.matches_at(pattern, text, class_end + 1, text_at + 1, memo)
    }

    fn byte_in_class(&self, byte: u8, class: &[u8]) -> bool {
        let byte = self.syntax.fold(byte);
        let mut at = 0;

        while at < class.len() {
            if at + 2 < class.len() && class[at + 1] == b'-' {
                if byte >= self.syntax.fold(class[at]) && byte <= self.syntax.fold(class[at + 2]) {
                    return true;
                }
                at += 3;
            } else {
                if self.syntax.matches_byte(class[at], byte) {
                    return true;
                }
                at += 1;
            }
        }

        false
    }
}
