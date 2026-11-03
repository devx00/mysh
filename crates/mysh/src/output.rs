//! Structured output for programs driving the client (docs/05-meta-shell.md
//! "Agent interface"). The result shapes, the [`Event`] stream, the error
//! codes and the output [`Mode`] live in [`mysh_client::types`] and are
//! re-exported here; the binary adds the clap-introspected [`HelpTree`] of
//! `help --json`.

use serde::{Deserialize, Serialize};

pub use mysh_client::types::*;

/// `help --json`: the clap command tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HelpTree {
    pub command: String,
    pub about: Option<String>,
    pub args: Vec<HelpArg>,
    pub subcommands: Vec<HelpTree>,
}

#[allow(clippy::struct_excessive_bools)] // independent facts about one argument
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HelpArg {
    pub name: String,
    pub long: Option<String>,
    pub short: Option<char>,
    /// Takes a value (`--port PORT`) rather than being a switch.
    pub takes_value: bool,
    /// Positional arguments have no `long`/`short`.
    pub positional: bool,
    pub required: bool,
    pub repeatable: bool,
    pub value_name: Option<String>,
    pub default: Option<String>,
    pub help: Option<String>,
}

impl HelpTree {
    /// Build the tree of `cmd` by introspection. The automatic `help` and
    /// `version` flags are skipped; everything else is reported.
    #[must_use]
    pub fn from_clap(cmd: &clap::Command) -> Self {
        let args = cmd
            .get_arguments()
            .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
            .map(|a| {
                let positional = a.is_positional();
                let action = a.get_action();
                HelpArg {
                    name: a.get_id().to_string(),
                    long: a.get_long().map(str::to_owned),
                    short: a.get_short(),
                    takes_value: action.takes_values(),
                    positional,
                    required: a.is_required_set(),
                    repeatable: matches!(action, clap::ArgAction::Append | clap::ArgAction::Count)
                        || a.get_num_args().is_some_and(|n| n.max_values() > 1),
                    value_name: a
                        .get_value_names()
                        .and_then(|names| names.first())
                        .map(ToString::to_string),
                    default: {
                        let defaults: Vec<String> = a
                            .get_default_values()
                            .iter()
                            .map(|v| v.to_string_lossy().into_owned())
                            .collect();
                        (!defaults.is_empty()).then(|| defaults.join(","))
                    },
                    help: a.get_help().map(ToString::to_string),
                }
            })
            .collect();
        Self {
            command: cmd.get_name().to_owned(),
            about: cmd.get_about().map(ToString::to_string),
            args,
            subcommands: cmd.get_subcommands().map(Self::from_clap).collect(),
        }
    }

    /// The subtree for `name`, if it is a direct subcommand.
    #[must_use]
    pub fn subcommand(&self, name: &str) -> Option<&Self> {
        self.subcommands.iter().find(|c| c.command == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_tree_from_cli() {
        use clap::CommandFactory as _;
        let tree = HelpTree::from_clap(&crate::cli::Cli::command());
        assert_eq!(tree.command, "mysh");
        assert!(tree.subcommand("serve").is_some());
        let serve = tree.subcommand("serve").unwrap();
        assert!(
            serve
                .args
                .iter()
                .any(|a| a.long.as_deref() == Some("listen"))
        );
        assert!(tree.subcommand("help").is_some());
    }
}
