//! File service (docs/03-protocol.md §9). One `Open::File` stream per
//! operation; the reply shape depends on the op.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    /// → `Msg<Attrs>`
    Stat { path: String },
    /// → `Msg<ListPage>` repeated until `more == false`
    List { path: String },
    /// → close
    Mkdir { path: String, mode: u32 },
    /// → close
    Remove { path: String, recursive: bool },
    /// → close
    Rename { from: String, to: String },
    /// → close
    SetAttr {
        path: String,
        mode: Option<u32>,
        mtime: Option<i64>,
    },
    /// → `Msg<String>`
    Realpath { path: String },
    /// → `Msg<Attrs>`, then raw bytes until the server closes. With
    /// `follow`, the server keeps the stream open and sends bytes as the
    /// file grows (`tail -f`) until the client closes it.
    Get {
        path: String,
        offset: u64,
        follow: bool,
    },
    /// → `Msg<FileHash>`
    Hash { path: String, algo: HashAlgo },
    /// Client streams raw bytes then half-closes → `Msg<PutDone>`
    Put {
        path: String,
        mode: u32,
        mtime: Option<i64>,
        offset: u64,
        truncate: bool,
        atomic: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attrs {
    pub kind: FileKind,
    pub size: u64,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Seconds since the Unix epoch.
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    File,
    Dir,
    Symlink { target: String },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub attrs: Attrs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListPage {
    pub entries: Vec<DirEntry>,
    pub more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutDone {
    pub written: u64,
}

/// Hash algorithms for `FileOp::Hash`. Only BLAKE2s-256 in v1; the enum
/// exists so a stronger or faster choice can be appended later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgo {
    Blake2s256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub algo: HashAlgo,
    pub size: u64,
    pub digest: [u8; 32],
}
