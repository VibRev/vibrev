//! The output net, over a real transport, against a real binary.
//!
//! `vibrev-kit`'s own tests cover the trimming, the spill and the preview shape
//! as functions. What they cannot cover is the part that only exists once the
//! decorator is wired into a server and a client talks to it over stdio: that
//! `_meta` survives serialization, that a second content block arrives, that the
//! `file://` URL a client reads out of the payload actually opens.
//!
//! `report` is the tool used because its answer is as large as the caller makes
//! it — the engine holds no data of its own, so the oversized answer here is
//! genuinely produced and returned rather than constructed by a test helper.
//!
//! The last test here is not about output at all. It is about what a decorator
//! does to *everything it was not written for*, and it lives in this file
//! because this is where the decorator gets wired to a real transport.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

struct Server {
    child: Child,
    /// An `Option` so that [`Server::shut_down`] can close it: closing stdin is
    /// how an MCP stdio client says goodbye, and it is the only exit that runs
    /// the server's destructors.
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_toy-engine"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn toy-engine");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut server = Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
        };
        server.call(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "output-net-test", "version": "0"},
            }),
        );
        server.notify("notifications/initialized");
        server
    }

    fn notify(&mut self, method: &str) {
        let line = json!({"jsonrpc": "2.0", "method": method}).to_string();
        self.send(&line);
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{line}").expect("write");
        stdin.flush().expect("flush");
    }

    /// Close stdin and wait, the way a client that is finished does.
    fn shut_down(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        self.send(&line);
        loop {
            let mut buffer = String::new();
            let read = self.stdout.read_line(&mut buffer).expect("read");
            assert!(read > 0, "server closed the transport waiting for {method}");
            let message: Value = match serde_json::from_str(&buffer) {
                Ok(message) => message,
                // Not every line is a response: notifications share the stream.
                Err(_) => continue,
            };
            if message.get("id").and_then(Value::as_i64) == Some(id) {
                return message;
            }
        }
    }

    fn capabilities(&mut self) -> Value {
        // `initialize` already ran in `start`; ask again on a fresh id rather
        // than caching, so this reads the same path a second client would.
        self.call(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "output-net-test", "version": "0"},
            }),
        )["result"]["capabilities"]
            .clone()
    }

    fn report(&mut self, body: String) -> Value {
        self.call(
            "tools/call",
            json!({
                "name": "report.build",
                "arguments": {
                    "title": "coverage",
                    "section": {"heading": "findings", "body": body},
                },
            }),
        )["result"]
            .clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An ordinary answer crosses the wire untouched.
///
/// The half that is easy to lose: a net that trims everything is not a net.
#[test]
fn an_answer_within_the_limit_arrives_whole() {
    let mut server = Server::start();
    let body = "a finding".repeat(10);

    let result = server.report(body.clone());

    assert!(
        result["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains(&body),
        "the body was altered"
    );
    assert_eq!(result["content"].as_array().map(Vec::len), Some(1));
    assert!(result.get("_meta").is_none(), "{result}");
}

/// An oversized answer is trimmed, and what it says about itself is true.
#[test]
fn an_oversized_answer_is_trimmed_and_still_reachable() {
    let mut server = Server::start();
    // Comfortably past the 50,000-character default, and distinctive enough
    // that finding it in the spill file means something.
    let body = "S".repeat(120_000);

    let result = server.report(body.clone());

    let meta = &result["_meta"]["vibrev"];
    assert_eq!(meta["output_truncated"], json!(true), "{result}");
    assert!(
        meta["total_chars"].as_u64().expect("total_chars") > 120_000,
        "{meta}"
    );

    // The wire payload is small, and the preview kept the shape: `content` is
    // still the report's text, not a JSON envelope describing one.
    let text = result["content"][0]["text"].as_str().expect("text");
    assert!(text.len() < 60_000, "preview was {} bytes", text.len());
    assert!(
        text.starts_with("# coverage"),
        "{}",
        &text[..40.min(text.len())]
    );
    assert_eq!(
        result["content"].as_array().map(Vec::len),
        Some(2),
        "the hint rides as its own block"
    );
    assert!(
        result["content"][1]["text"]
            .as_str()
            .expect("hint")
            .starts_with("Output truncated."),
        "{result}"
    );

    // The structured payload still has every key its schema declares.
    let structured = result["structuredContent"]
        .as_object()
        .expect("structured content");
    assert_eq!(structured.keys().collect::<Vec<_>>(), vec!["content"]);

    // And the URL in the payload opens.
    let url = meta["download_url"].as_str().expect("download_url");
    let path = url.strip_prefix("file://").expect("a file URL");
    let spilled: Value =
        serde_json::from_slice(&std::fs::read(path).expect("read spill")).expect("spill json");
    assert!(
        spilled["content"]
            .as_str()
            .expect("content")
            .contains(&body),
        "the spill did not hold the whole answer"
    );
}

/// The spill does not outlive the server that wrote it.
///
/// "Does not outlive" means *on a clean exit*, and that limit is worth stating:
/// the directory is removed by a destructor, and a process killed with SIGKILL
/// runs no destructors. A crashed engine leaves its spilled outputs in the
/// temporary directory — 0700, so not readable by other users, but there until
/// something else cleans up.
#[test]
fn the_spill_directory_goes_when_a_client_says_goodbye() {
    let mut server = Server::start();
    let result = server.report("S".repeat(120_000));
    let url = result["_meta"]["vibrev"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();
    let path = std::path::PathBuf::from(url.strip_prefix("file://").expect("a file URL"));
    let directory = path.parent().expect("parent").to_path_buf();
    assert!(directory.exists());

    server.shut_down();

    assert!(
        !directory.exists(),
        "{} survived the server",
        directory.display()
    );
}

/// A decorator passes through everything it was not written for.
///
/// The failure this pins is the one that already happened. `Capped` was written
/// as a bare `impl ServerHandler` with six methods, and wrapping
/// `ida-headless-mcp`'s supervisor in it left the server advertising `resources`
/// in its capabilities while `resources/list` returned `[]` and
/// `resources/read` returned `-32601`. Nothing failed to compile and no test
/// noticed, because every test asked about tools.
///
/// So this one asks about the *other* capability, through the same wrapped
/// server and the same transport a client uses. `toy://manifest` exists for no
/// other reason.
#[test]
fn a_capability_the_decorator_never_heard_of_still_answers() {
    let mut server = Server::start();

    let capabilities = server.capabilities();
    assert!(
        capabilities.get("resources").is_some(),
        "the engine advertises resources: {capabilities}"
    );

    let listed = server.call("resources/list", json!({}));
    let resources = listed["result"]["resources"]
        .as_array()
        .unwrap_or_else(|| panic!("resources/list returned no array: {listed}"));
    assert_eq!(
        resources.len(),
        1,
        "an advertised capability answered with nothing: {listed}"
    );
    assert_eq!(resources[0]["uri"], json!("toy://manifest"));

    let read = server.call("resources/read", json!({"uri": "toy://manifest"}));
    assert!(
        read.get("error").is_none(),
        "resources/read did not reach the engine: {read}"
    );
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no resource text: {read}"));
    let manifest: Value = serde_json::from_str(text).expect("manifest json");
    assert!(
        manifest["tools"]
            .as_array()
            .is_some_and(|tools| tools.contains(&json!("report.build"))),
        "{manifest}"
    );

    server.shut_down();
}
