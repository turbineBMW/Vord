//! Asking through `$SSH_ASKPASS`, the program OpenSSH runs for passphrases
//! and confirmations (on Omarchy, the shell's fullscreen password dialog).
//! The SSH agent uses it to unlock the vault and to ask before a key signs,
//! so neither needs Vord's window.
//!
//! OpenSSH's protocol: the prompt is the only argument, the answer comes back
//! on stdout, and exit status 0 means OK. With `SSH_ASKPASS_PROMPT=confirm`
//! it's a yes/no question with nothing to type. `ASKPASS_REASON` is
//! Omarchy's: a sentence its dialog shows under the prompt; other askpass
//! programs ignore it.
//!
//! Every call blocks until the user answers: run them on a worker.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// The session's askpass program, if it names one.
pub fn program() -> Option<PathBuf> {
    let program = PathBuf::from(std::env::var_os("SSH_ASKPASS").filter(|p| !p.is_empty())?);
    // A bare name is looked up on PATH when it runs; a path must exist.
    (!program.is_absolute() || program.is_file()).then_some(program)
}

/// Ask for something to type (a PIN, a password). `None` when cancelled or
/// the program couldn't run.
pub fn secret(program: &Path, prompt: &str, reason: &str) -> Option<Zeroizing<String>> {
    let output = run(program, prompt, reason, false)?;
    let mut text = Zeroizing::new(String::from_utf8(output.to_vec()).ok()?);
    while text.ends_with(['\n', '\r']) {
        text.pop();
    }
    Some(text)
}

/// Ask yes or no.
pub fn confirm(program: &Path, prompt: &str, reason: &str) -> bool {
    run(program, prompt, reason, true).is_some()
}

/// Stdout when the program says OK.
fn run(program: &Path, prompt: &str, reason: &str, confirm: bool) -> Option<Zeroizing<Vec<u8>>> {
    let mut command = Command::new(program);
    command
        .arg(prompt)
        .env("ASKPASS_REASON", reason)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if confirm {
        command.env("SSH_ASKPASS_PROMPT", "confirm");
    } else {
        command.env_remove("SSH_ASKPASS_PROMPT");
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            log::warn!("askpass: could not run {}: {error}", program.display());
            return None;
        }
    };
    let stdout = Zeroizing::new(output.stdout);
    output.status.success().then_some(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in askpass that echoes what it was given, or refuses.
    fn fake(dir: &Path, script: &str) -> PathBuf {
        let path = dir.join("askpass");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn passes_prompt_and_reason_and_trims_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake(
            dir.path(),
            r#"printf '%s|%s|%s\n' "$1" "$ASKPASS_REASON" "${SSH_ASKPASS_PROMPT:-none}""#,
        );
        let answer = secret(&program, "Vord PIN", "git wants a key").unwrap();
        assert_eq!(answer.as_str(), "Vord PIN|git wants a key|none");
    }

    #[test]
    fn confirm_sets_the_openssh_mode() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake(dir.path(), r#"[ "$SSH_ASKPASS_PROMPT" = confirm ]"#);
        assert!(confirm(&program, "Use SSH key?", ""));
        assert!(secret(&program, "PIN", "").is_none());
    }

    #[test]
    fn cancelling_or_a_missing_program_is_no() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake(dir.path(), "exit 1");
        assert!(secret(&program, "PIN", "").is_none());
        assert!(!confirm(&program, "Use SSH key?", ""));
        assert!(secret(&dir.path().join("missing"), "PIN", "").is_none());
    }
}
