//! An SSH agent for the vault's SSH keys, as Bitwarden's desktop app has.
//!
//! It listens on a Unix socket in `$XDG_RUNTIME_DIR/vord` (mode 0700) and
//! speaks the agent protocol's two requests that matter: list the keys,
//! and sign with one. Everything else gets a failure, as from an agent
//! that doesn't do it.
//!
//! Each connection runs on its own thread; what it needs from the vault it
//! asks the window for ([`Request`]), and waits. The window decides: it
//! knows which keys exist (their public halves, kept after locking so `ssh`
//! can still offer one), asks the user before a key is used, and hands
//! over the private key only for that one signature.

use rsa::signature::{SignatureEncoding, Signer};
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;
/// Bigger requests are refused; a signature request is a few KiB.
const MAX_MESSAGE: usize = 256 * 1024;
/// How long a request waits for the user (to unlock, to allow).
pub const WAIT: Duration = Duration::from_secs(120);

/// A key the agent offers: its public key in SSH wire form, and a comment
/// (the item's name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

/// What a connection asks the window. The answer goes back on `reply`;
/// dropping it refuses.
pub enum Request {
    /// The keys to offer. `process` is who asked (the unlock prompt names
    /// it when the keys aren't known yet).
    List {
        process: String,
        reply: mpsc::Sender<Vec<Identity>>,
    },
    /// The private key (OpenSSH format) for the key whose public half is
    /// `blob`, if the user allows `process` to use it.
    Sign {
        blob: Vec<u8>,
        process: String,
        reply: mpsc::Sender<Zeroizing<String>>,
    },
}

/// Where the agent listens.
pub fn socket_path() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    runtime.join("vord").join("ssh-agent.sock")
}

/// The public key's wire form, from an `ssh-ed25519 AAAA… comment` line.
pub fn public_blob(openssh: &str) -> Option<Vec<u8>> {
    ssh_key::PublicKey::from_openssh(openssh.trim())
        .ok()?
        .to_bytes()
        .ok()
}

/// Listen until `stop` is set. Returns once the socket is bound; accepting
/// happens on a thread of its own. `ask` is called from connection threads.
pub fn serve(
    stop: Arc<AtomicBool>,
    ask: impl Fn(Request) + Send + Sync + 'static,
) -> std::io::Result<PathBuf> {
    serve_at(socket_path(), stop, ask)
}

fn serve_at(
    path: PathBuf,
    stop: Arc<AtomicBool>,
    ask: impl Fn(Request) + Send + Sync + 'static,
) -> std::io::Result<PathBuf> {
    let dir = path.parent().expect("a directory");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    // A socket left by an earlier run (Vord is single-instance).
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let ask = Arc::new(ask);
    let bound = path.clone();
    std::thread::Builder::new()
        .name("vord-ssh-agent".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let ask = ask.clone();
                        let _ = std::thread::Builder::new()
                            .name("vord-ssh-agent-client".into())
                            .spawn(move || {
                                if let Err(error) = handle(stream, &*ask) {
                                    log::debug!("ssh agent: a connection ended: {error}");
                                }
                            });
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(error) => {
                        log::warn!("ssh agent: {error}");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            let _ = std::fs::remove_file(&bound);
        })?;
    Ok(path)
}

/// Who's on the other end: its process name, and its parent's
/// ("ssh, from git"). Refuses another user's process.
fn peer(stream: &UnixStream) -> std::io::Result<String> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of the size given.
    let ok = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if ok != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getuid can't fail.
    if cred.uid != unsafe { libc::getuid() } {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "another user's process",
        ));
    }
    Ok(process_name(cred.pid))
}

fn process_name(pid: i32) -> String {
    let comm = |pid: i32| {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|c| c.trim().to_string())
    };
    let parent = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            // The name is in parentheses and may hold spaces; the parent's
            // pid is the second field after it.
            let rest = &stat[stat.rfind(')')? + 1..];
            rest.split_whitespace().nth(1)?.parse::<i32>().ok()
        })
        .and_then(comm);
    match (comm(pid), parent) {
        (Some(name), Some(parent)) if parent != name && !is_shell(&parent) => {
            format!("{name}, from {parent}")
        }
        (Some(name), _) => name,
        (None, _) => "A program".into(),
    }
}

fn is_shell(name: &str) -> bool {
    matches!(name, "bash" | "zsh" | "fish" | "sh" | "dash" | "nu")
}

fn read_message(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(std::io::Error::new(ErrorKind::InvalidData, "bad length"));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_message(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

/// Reads the agent protocol's strings and numbers in turn.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }
}

/// Serve one connection until it closes.
fn handle(mut stream: UnixStream, ask: &dyn Fn(Request)) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    let process = peer(&stream)?;
    while let Some(message) = read_message(&mut stream)? {
        let answer = answer(&message, &process, ask).unwrap_or_else(|| vec![FAILURE]);
        write_message(&mut stream, &answer)?;
    }
    Ok(())
}

fn answer(message: &[u8], process: &str, ask: &dyn Fn(Request)) -> Option<Vec<u8>> {
    let (&kind, body) = message.split_first()?;
    match kind {
        REQUEST_IDENTITIES => {
            let (reply, answer) = mpsc::channel();
            ask(Request::List {
                process: process.to_string(),
                reply,
            });
            let keys = answer.recv_timeout(WAIT).ok()?;
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend((keys.len() as u32).to_be_bytes());
            for key in keys {
                put_string(&mut out, &key.blob);
                put_string(&mut out, key.comment.as_bytes());
            }
            Some(out)
        }
        SIGN_REQUEST => {
            let mut reader = Reader(body);
            let blob = reader.string()?.to_vec();
            let data = reader.string()?;
            let flags = reader.u32().unwrap_or(0);
            let (reply, answer) = mpsc::channel();
            ask(Request::Sign {
                blob,
                process: process.to_string(),
                reply,
            });
            let private = answer.recv_timeout(WAIT).ok()?;
            match sign(&private, data, flags) {
                Ok(signature) => {
                    let mut out = vec![SIGN_RESPONSE];
                    put_string(&mut out, &signature);
                    Some(out)
                }
                Err(error) => {
                    log::warn!("ssh agent: could not sign: {error}");
                    None
                }
            }
        }
        _ => None,
    }
}

/// Sign `data` with an OpenSSH private key, as the agent protocol wants
/// the signature: its algorithm's name, then the signature itself. An RSA
/// key signs with the hash the flags ask for.
pub fn sign(private: &str, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    let key = PrivateKey::from_openssh(private.trim()).map_err(|e| e.to_string())?;
    if key.is_encrypted() {
        return Err("the key is protected by a passphrase".into());
    }
    let signature = match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let private = rsa_key(keypair)?;
            let (name, bytes) = if flags & RSA_SHA2_512 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private);
                ("rsa-sha2-512", signer.try_sign(data).map(|s| s.to_vec()))
            } else if flags & RSA_SHA2_256 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
                ("rsa-sha2-256", signer.try_sign(data).map(|s| s.to_vec()))
            } else {
                // Plain "ssh-rsa": SHA-1, for servers that know nothing newer.
                let signer = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(private);
                ("ssh-rsa", signer.try_sign(data).map(|s| s.to_vec()))
            };
            let bytes = bytes.map_err(|e| e.to_string())?;
            // ssh-key won't make an "ssh-rsa" signature; the form is simple.
            let mut out = Vec::new();
            put_string(&mut out, name.as_bytes());
            put_string(&mut out, &bytes);
            return Ok(out);
        }
        _ => key.try_sign(data).map_err(|e| e.to_string())?,
    };
    let mut out = Vec::new();
    ssh_encoding::Encode::encode(&signature, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// The `rsa` crate's key. ssh-key 0.6's own conversion passes the first
/// prime twice, so every RSA key would fail it; this passes both.
fn rsa_key(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    let big = |m: &ssh_key::Mpint| rsa::BigUint::try_from(m).map_err(|e| e.to_string());
    rsa::RsaPrivateKey::from_components(
        big(&keypair.public.n)?,
        big(&keypair.public.e)?,
        big(&keypair.private.d)?,
        vec![big(&keypair.private.p)?, big(&keypair.private.q)?],
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::signature::Verifier;
    use ssh_key::Algorithm;

    fn key(algorithm: Algorithm) -> PrivateKey {
        let mut rng = rand::rngs::OsRng;
        PrivateKey::random(&mut rng, algorithm).unwrap()
    }

    fn identity(key: &PrivateKey, comment: &str) -> Identity {
        Identity {
            blob: key.public_key().to_bytes().unwrap(),
            comment: comment.into(),
        }
    }

    fn decode(signature: &[u8]) -> ssh_key::Signature {
        let mut reader = signature;
        ssh_encoding::Decode::decode(&mut reader).unwrap()
    }

    #[test]
    fn signatures_verify() {
        let ed25519 = key(Algorithm::Ed25519);
        let pem = ed25519.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let signature = decode(&sign(&pem, b"hello", 0).unwrap());
        assert!(ed25519
            .public_key()
            .key_data()
            .verify(b"hello", &signature)
            .is_ok());

        let ecdsa = key(Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        });
        let pem = ecdsa.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let signature = decode(&sign(&pem, b"hello", 0).unwrap());
        assert!(ecdsa
            .public_key()
            .key_data()
            .verify(b"hello", &signature)
            .is_ok());

        // RSA: the hash the flags ask for.
        let rsa = PrivateKey::new(
            KeypairData::Rsa(
                ssh_key::private::RsaKeypair::random(&mut rand::rngs::OsRng, 2048).unwrap(),
            ),
            "",
        )
        .unwrap();
        let pem = rsa.to_openssh(ssh_key::LineEnding::LF).unwrap();
        for (flags, name) in [
            (RSA_SHA2_256, "rsa-sha2-256"),
            (RSA_SHA2_512, "rsa-sha2-512"),
            (0, "ssh-rsa"),
        ] {
            let blob = sign(&pem, b"hello", flags).unwrap();
            let mut reader = Reader(&blob);
            assert_eq!(reader.string(), Some(name.as_bytes()));
            if flags != 0 {
                let signature = decode(&blob);
                assert!(rsa
                    .public_key()
                    .key_data()
                    .verify(b"hello", &signature)
                    .is_ok());
            }
        }
    }

    /// OpenSSH's own tools against the agent: `ssh-add` lists the keys,
    /// `ssh-keygen -Y` signs through it and checks the signature.
    #[test]
    fn openssh_uses_it() {
        if std::process::Command::new("ssh-keygen")
            .arg("-?")
            .output()
            .is_err()
        {
            eprintln!("no ssh-keygen; skipped");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ed25519 = key(Algorithm::Ed25519);
        let rsa = PrivateKey::new(
            KeypairData::Rsa(
                ssh_key::private::RsaKeypair::random(&mut rand::rngs::OsRng, 2048).unwrap(),
            ),
            "",
        )
        .unwrap();
        let keys: Vec<(Identity, Zeroizing<String>)> =
            [(&ed25519, "Build server"), (&rsa, "Old box")]
                .into_iter()
                .map(|(key, name)| {
                    let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
                    (identity(key, name), Zeroizing::new(pem))
                })
                .collect();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop: Arc<AtomicBool> = Default::default();
        let socket = serve_at(dir.path().join("agent").join("s.sock"), stop.clone(), {
            let asked = asked.clone();
            move |request| match request {
                Request::List { reply, .. } => {
                    let _ = reply.send(keys.iter().map(|(i, _)| i.clone()).collect());
                }
                Request::Sign {
                    blob,
                    process,
                    reply,
                } => {
                    asked.lock().unwrap().push(process);
                    if let Some((_, pem)) = keys.iter().find(|(i, _)| i.blob == blob) {
                        let _ = reply.send(pem.clone());
                    }
                }
            }
        })
        .unwrap();
        let run = |program: &str, args: &[&str], input: Option<&[u8]>| {
            let mut child = std::process::Command::new(program)
                .args(args)
                .env("SSH_AUTH_SOCK", &socket)
                .current_dir(dir.path())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            if let Some(input) = input {
                child.stdin.take().unwrap().write_all(input).unwrap();
            }
            drop(child.stdin.take());
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{program} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };

        let listed = run("ssh-add", &["-L"], None);
        for (key, name) in [(&ed25519, "Build server"), (&rsa, "Old box")] {
            let line = key.public_key().to_openssh().unwrap();
            assert!(listed.contains(&format!("{line} {name}")), "{listed}");
        }

        std::fs::write(dir.path().join("data"), b"signed through Vord").unwrap();
        for (key, file) in [(&ed25519, "ed25519"), (&rsa, "rsa")] {
            let public = key.public_key().to_openssh().unwrap();
            std::fs::write(dir.path().join(format!("{file}.pub")), &public).unwrap();
            std::fs::write(dir.path().join("allowed"), format!("me {public}\n")).unwrap();
            run(
                "ssh-keygen",
                &[
                    "-Y",
                    "sign",
                    "-f",
                    &format!("{file}.pub"),
                    "-n",
                    "file",
                    "data",
                ],
                None,
            );
            let checked = run(
                "ssh-keygen",
                &[
                    "-Y", "verify", "-f", "allowed", "-I", "me", "-n", "file", "-s", "data.sig",
                ],
                Some(b"signed through Vord"),
            );
            assert!(checked.contains("Good"), "{checked}");
            std::fs::remove_file(dir.path().join("data.sig")).unwrap();
        }
        assert!(asked
            .lock()
            .unwrap()
            .iter()
            .all(|p| p.starts_with("ssh-keygen")));
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn the_protocol() {
        let key = key(Algorithm::Ed25519);
        let pem = Zeroizing::new(key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string());
        let known = identity(&key, "Build server");
        let ask = {
            let known = known.clone();
            move |request: Request| match request {
                Request::List { reply, .. } => {
                    let _ = reply.send(vec![known.clone()]);
                }
                Request::Sign { blob, reply, .. } => {
                    if blob == known.blob {
                        let _ = reply.send(pem.clone());
                    }
                }
            }
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || handle(server, &ask));

        write_message(&mut client, &[REQUEST_IDENTITIES]).unwrap();
        let list = read_message(&mut client).unwrap().unwrap();
        let mut reader = Reader(&list[1..]);
        assert_eq!(list[0], IDENTITIES_ANSWER);
        assert_eq!(reader.u32(), Some(1));
        assert_eq!(reader.string(), Some(&known.blob[..]));
        assert_eq!(reader.string(), Some(&b"Build server"[..]));

        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, &known.blob);
        put_string(&mut request, b"session data");
        request.extend(0u32.to_be_bytes());
        write_message(&mut client, &request).unwrap();
        let signed = read_message(&mut client).unwrap().unwrap();
        assert_eq!(signed[0], SIGN_RESPONSE);
        let signature = decode(Reader(&signed[1..]).string().unwrap());
        assert!(key
            .public_key()
            .key_data()
            .verify(b"session data", &signature)
            .is_ok());

        // An unknown key, and a request the agent doesn't do.
        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, b"not a key");
        put_string(&mut request, b"x");
        write_message(&mut client, &request).unwrap();
        assert_eq!(read_message(&mut client).unwrap().unwrap(), vec![FAILURE]);
        write_message(&mut client, &[17]).unwrap();
        assert_eq!(read_message(&mut client).unwrap().unwrap(), vec![FAILURE]);

        drop(client);
        assert!(thread.join().unwrap().is_ok());
    }
}
