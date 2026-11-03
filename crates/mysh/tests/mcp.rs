//! `mysh mcp` conformance through the real binary over pipes
//! (docs/07-embedding.md "MCP server"): the handshake, the tool list with
//! both schemas, every tool against a loopback server, the error mapping,
//! resources, and a clean exit on stdin EOF.

#![allow(clippy::needless_pass_by_value)] // `json!` arguments read best inline

mod common;

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use base64::Engine as _;
use serde_json::{Value, json};

const TOOLS: [&str; 14] = [
    "exec",
    "read_file",
    "write_file",
    "list_dir",
    "stat",
    "session_new",
    "session_send",
    "session_read",
    "session_kill",
    "session_list",
    "put",
    "get",
    "info",
    "hosts",
];

/// A `mysh mcp` child driven over its pipes.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    /// `mysh mcp --hosts HOSTS [extra...]` with the harness environment.
    fn spawn(server: &common::TestServer, hosts: &str, extra: &[&str]) -> Self {
        let mut cmd = Command::new(common::mysh_bin());
        cmd.env_clear()
            .envs(common::client_env(server))
            .current_dir(server.dir.path())
            .arg("mcp")
            .arg("--hosts")
            .arg(hosts)
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().expect("spawn mysh mcp");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    /// The usual: `--accept-new --allow-local-paths` against the one host.
    fn standard(server: &common::TestServer) -> Self {
        Self::spawn(
            server,
            &server.host_arg(),
            &["--accept-new", "--allow-local-paths"],
        )
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(bytes).expect("write request");
        stdin.flush().expect("flush");
    }

    fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.send_raw(format!("{msg}\n").as_bytes());
    }

    /// One request, its full response object.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send_raw(format!("{msg}\n").as_bytes());
        loop {
            let line = self.read_line();
            let reply: Value =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"));
            if reply["id"] == json!(id) {
                assert_eq!(reply["jsonrpc"], "2.0");
                return reply;
            }
        }
    }

    fn read_line(&mut self) -> String {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).expect("read reply");
        assert!(n > 0, "mysh mcp closed stdout");
        line
    }

    /// `result` of a request that must succeed at the JSON-RPC level.
    fn call(&mut self, method: &str, params: Value) -> Value {
        let reply = self.request(method, params);
        assert!(
            reply.get("error").is_none(),
            "{method} failed: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    /// The JSON-RPC error of a request that must fail.
    fn call_err(&mut self, method: &str, params: Value) -> Value {
        let reply = self.request(method, params);
        assert!(reply.get("result").is_none(), "{method} succeeded: {reply}");
        reply["error"].clone()
    }

    /// `initialize` + `notifications/initialized`; returns the result.
    fn init(&mut self) -> Value {
        let result = self.call(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }),
        );
        self.notify("notifications/initialized", json!({}));
        result
    }

    /// A tool call that must produce a result (either outcome); returns the
    /// `tools/call` result object.
    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.call("tools/call", json!({"name": name, "arguments": arguments}));
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().expect("text content"))
                .expect("content text is JSON");
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(
            text, result["structuredContent"],
            "{name}: text and structuredContent differ"
        );
        result
    }

    /// A successful tool call's `structuredContent`.
    fn tool_ok(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.tool(name, arguments);
        assert_eq!(result["isError"], false, "{name} failed: {result}");
        result["structuredContent"].clone()
    }

    /// A failing tool call's mysh error code.
    fn tool_code(&mut self, name: &str, arguments: Value) -> String {
        let result = self.tool(name, arguments);
        assert_eq!(result["isError"], true, "{name} succeeded: {result}");
        result["structuredContent"]["error"]["code"]
            .as_str()
            .expect("error code")
            .to_owned()
    }

    /// Close stdin and wait for the exit status (bounded).
    fn finish(mut self) -> i32 {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status.code().unwrap_or(-1);
            }
            assert!(
                Instant::now() < deadline,
                "mysh mcp did not exit after stdin EOF"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("base64")
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_lists_tools_and_exits_on_eof() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let mut mcp = Mcp::standard(&server);

    let init = mcp.init();
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["capabilities"]["tools"]["listChanged"], false);
    assert_eq!(init["capabilities"]["resources"]["subscribe"], false);
    assert_eq!(init["capabilities"]["resources"]["listChanged"], false);
    assert_eq!(init["serverInfo"]["name"], "mysh");
    assert_eq!(init["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let instructions = init["instructions"].as_str().expect("instructions");
    assert!(instructions.contains(&server.host_arg()), "{instructions}");
    assert!(instructions.contains("accept-new"), "{instructions}");

    assert_eq!(mcp.call("ping", json!({})), json!({}));

    let tools = mcp.call("tools/list", json!({}));
    let tools = tools["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOLS);
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "{name}"
        );
        assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
        assert_eq!(tool["outputSchema"]["type"], "object", "{name}");
        // One host: `host` is optional everywhere.
        let required = tool["inputSchema"]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !required.iter().any(|r| r == "host"),
            "{name} requires host"
        );
    }

    // An older client gets its own version back.
    let again = mcp.call("initialize", json!({"protocolVersion": "2024-11-05"}));
    assert_eq!(again["protocolVersion"], "2024-11-05");
    let unknown = mcp.call("initialize", json!({"protocolVersion": "2000-01-01"}));
    assert_eq!(unknown["protocolVersion"], "2025-06-18");

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_and_file_tools() {
    let server = common::start_server(common::ServerOpts {
        accept_env: vec!["MYSH_X".to_owned()],
        ..common::ServerOpts::default()
    })
    .await;
    let mut mcp = Mcp::standard(&server);
    mcp.init();

    let out = mcp.tool_ok("exec", json!({"command": "echo hi"}));
    assert_eq!(out["stdout"], "hi\n");
    assert_eq!(out["stderr"], "");
    assert_eq!(out["exit"], 0);
    assert_eq!(out["timed_out"], false);

    let out = mcp.tool_ok(
        "exec",
        json!({"command": ["sh", "-c", "echo err >&2; exit 3"]}),
    );
    assert_eq!(out["exit"], 3, "{out}");
    assert_eq!(out["stderr"], "err\n");

    let out = mcp.tool_ok("exec", json!({"command": "cat", "stdin": "a\nb\n"}));
    assert_eq!(out["stdout"], "a\nb\n");

    let out = mcp.tool_ok(
        "exec",
        json!({"command": "pwd; printf %s \"$MYSH_X\"", "cwd": "/", "env": {"MYSH_X": "y"}}),
    );
    assert_eq!(out["stdout"], "/\ny");

    let out = mcp.tool_ok("exec", json!({"command": "sleep 5", "timeout_ms": 300}));
    assert_eq!(out["timed_out"], true, "{out}");

    let dir = server.home.join("mcp");
    std::fs::create_dir_all(&dir).unwrap();
    let text_path = dir.join("t.txt").display().to_string();
    let out = mcp.tool_ok(
        "write_file",
        json!({"path": text_path, "content": "héllo\n"}),
    );
    assert_eq!(out["written"], "héllo\n".len());
    let out = mcp.tool_ok("read_file", json!({"path": text_path}));
    assert_eq!(out["content"], "héllo\n");
    assert_eq!(out["encoding"], "utf-8");
    assert_eq!(out["size"], "héllo\n".len());
    assert_eq!(out["truncated"], false);

    let out = mcp.tool_ok(
        "write_file",
        json!({"path": text_path, "content": "more\n", "append": true}),
    );
    assert_eq!(out["written"], 5);
    assert_eq!(
        std::fs::read_to_string(dir.join("t.txt")).unwrap(),
        "héllo\nmore\n"
    );

    // Offsets and caps.
    let out = mcp.tool_ok(
        "read_file",
        json!({"path": text_path, "offset": 7, "max_bytes": 2}),
    );
    assert_eq!(out["content"], "mo");
    assert_eq!(out["offset"], 7);
    assert_eq!(out["truncated"], true);

    // Binary round trip.
    let bin_path = dir.join("b.bin").display().to_string();
    let bytes = [0xffu8, 0x00, 0x01, 0xfe];
    let out = mcp.tool_ok(
        "write_file",
        json!({"path": bin_path, "content": b64(&bytes), "encoding": "base64", "mode": "600"}),
    );
    assert_eq!(out["written"], 4);
    let out = mcp.tool_ok("read_file", json!({"path": bin_path}));
    assert_eq!(out["encoding"], "base64");
    assert_eq!(unb64(out["content"].as_str().unwrap()), bytes);

    let out = mcp.tool_ok("list_dir", json!({"path": dir.display().to_string()}));
    let names: Vec<&str> = out["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["b.bin", "t.txt"]);
    assert_eq!(out["entries"][0]["kind"], "file");
    assert_eq!(out["entries"][0]["mode"], "0600");

    let out = mcp.tool_ok("stat", json!({"path": text_path}));
    assert_eq!(out["kind"], "file");
    assert_eq!(out["size"], "héllo\nmore\n".len());
    assert_eq!(out["path"], text_path);
    let out = mcp.tool_ok("stat", json!({"path": "~"}));
    assert_eq!(out["kind"], "dir");

    assert_eq!(
        mcp.tool_code(
            "stat",
            json!({"path": dir.join("missing").display().to_string()})
        ),
        "not_found"
    );
    assert_eq!(
        mcp.tool_code(
            "read_file",
            json!({"path": dir.join("missing").display().to_string()})
        ),
        "not_found"
    );

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_tools() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let mut mcp = Mcp::standard(&server);
    mcp.init();

    let out = mcp.tool_ok("session_new", json!({"command": ["cat"]}));
    let id = out["id"].as_u64().expect("id");
    assert!(out["pid"].as_u64().unwrap() > 0);

    assert_eq!(
        mcp.tool_ok("session_send", json!({"id": id, "data": "hello\n"})),
        json!({"ok": true})
    );
    let out = mcp.tool_ok("session_read", json!({"id": id, "wait_ms": 3000}));
    assert_eq!(out["offset"], 0);
    assert_eq!(out["chunks"][0]["stream"], "stdout");
    assert_eq!(out["chunks"][0]["data"], "hello\n");
    assert_eq!(out["next"], 6);
    assert!(out["exited"].is_null());

    // The same offset is idempotent; `next` continues.
    let again = mcp.tool_ok("session_read", json!({"id": id, "offset": 0}));
    assert_eq!(again["chunks"], out["chunks"]);
    mcp.tool_ok(
        "session_send",
        json!({"id": id, "data": b64(b"\xff\n"), "encoding": "base64"}),
    );
    let out = mcp.tool_ok(
        "session_read",
        json!({"id": id, "offset": 6, "wait_ms": 3000}),
    );
    assert_eq!(out["chunks"][0]["data"], json!({"base64": b64(b"\xff\n")}));

    let list = mcp.tool_ok("session_list", json!({}));
    let row = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(id))
        .expect("session listed");
    assert_eq!(row["kind"], "cat");
    assert_eq!(row["pty"], false);

    assert_eq!(
        mcp.tool_ok("session_kill", json!({"id": id})),
        json!({"ok": true})
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let exited = loop {
        let out = mcp.tool_ok(
            "session_read",
            json!({"id": id, "offset": 8, "wait_ms": 500}),
        );
        if !out["exited"].is_null() {
            break out["exited"].clone();
        }
        assert!(Instant::now() < deadline, "session did not exit");
    };
    assert_eq!(exited["signal"], 15, "{exited}");

    // A PTY session and an unknown signal name.
    let pty = mcp.tool_ok(
        "session_new",
        json!({"command": "stty size; exit", "pty": true}),
    );
    let pid = pty["id"].as_u64().unwrap();
    let out = mcp.tool_ok("session_read", json!({"id": pid, "wait_ms": 3000}));
    let text = out["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["data"].as_str().unwrap_or(""))
        .collect::<String>();
    assert!(text.contains("24 80"), "{text:?}");
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "session_kill", "arguments": {"id": pid, "signal": "BOGUS"}}),
    );
    assert_eq!(err["code"], -32602);

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn put_get_info_and_hosts() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let local = server.dir.join("local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("up.txt"), b"up and away\n").unwrap();
    let mut mcp = Mcp::standard(&server);
    mcp.init();

    let hosts = mcp.tool_ok("hosts", json!({}));
    assert_eq!(hosts["hosts"][0]["host"], server.host_arg());
    assert_eq!(hosts["hosts"][0]["target"], server.host_arg());
    assert_eq!(hosts["hosts"][0]["connected"], false);
    assert!(hosts["hosts"][0]["connection"].is_null());

    let remote = server.home.join("down.txt").display().to_string();
    let out = mcp.tool_ok(
        "put",
        json!({"local": local.join("up.txt").display().to_string(), "remote": remote}),
    );
    assert_eq!(out["files"], 1);
    assert_eq!(out["bytes"], 12);
    assert_eq!(
        std::fs::read_to_string(server.home.join("down.txt")).unwrap(),
        "up and away\n"
    );
    // `checksum`: identical content is skipped.
    let out = mcp.tool_ok(
        "put",
        json!({"local": local.join("up.txt").display().to_string(), "remote": remote, "checksum": true}),
    );
    assert_eq!(out["files"], 0);
    assert_eq!(out["skipped"], 1);

    let out = mcp.tool_ok(
        "get",
        json!({"remote": remote, "local": local.join("back.txt").display().to_string()}),
    );
    assert_eq!(out["files"], 1);
    assert_eq!(
        std::fs::read_to_string(local.join("back.txt")).unwrap(),
        "up and away\n"
    );
    // Relative local paths resolve against the server process's cwd.
    let out = mcp.tool_ok("get", json!({"remote": remote, "local": "local/rel.txt"}));
    assert_eq!(out["files"], 1);
    assert!(local.join("rel.txt").is_file());

    let info = mcp.tool_ok("info", json!({}));
    assert_eq!(info["server"]["platform"]["os"], std::env::consts::OS);
    assert_eq!(info["server"]["platform"]["arch"], std::env::consts::ARCH);
    assert_eq!(info["connection"]["port"], server.port());
    assert_eq!(info["connection"]["trusted_via"], "accept-new");

    let hosts = mcp.tool_ok("hosts", json!({}));
    assert_eq!(hosts["hosts"][0]["connected"], true);
    assert_eq!(hosts["hosts"][0]["connection"]["port"], server.port());

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn error_mapping() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let dead = "127.0.0.1:1";
    let hosts = format!("{},{dead}", server.host_arg());
    let mut mcp = Mcp::spawn(&server, &hosts, &["--accept-new"]);
    let init = mcp.init();
    assert!(init["instructions"].as_str().unwrap().contains("denied"));

    let err = mcp.call_err("no/such", json!({}));
    assert_eq!(err["code"], -32601);

    // Two hosts: `host` is required and validated.
    let tools = mcp.call("tools/list", json!({}));
    let exec = &tools["tools"][0];
    assert_eq!(exec["name"], "exec");
    assert!(
        exec["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "host")
    );
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "exec", "arguments": {"command": "true"}}),
    );
    assert_eq!(err["code"], -32602);
    assert!(err["message"].as_str().unwrap().contains("host"), "{err}");
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "exec", "arguments": {"host": "nowhere", "command": "true"}}),
    );
    assert_eq!(err["code"], -32602);

    // Bad arguments: a missing field, an unknown field, a wrong type.
    let host = server.host_arg();
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "stat", "arguments": {"host": host}}),
    );
    assert_eq!(err["code"], -32602);
    assert!(err["message"].as_str().unwrap().contains("path"), "{err}");
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "stat", "arguments": {"host": host, "path": "/", "bogus": 1}}),
    );
    assert_eq!(err["code"], -32602);
    let err = mcp.call_err(
        "tools/call",
        json!({"name": "exec", "arguments": {"host": host, "command": 42}}),
    );
    assert_eq!(err["code"], -32602);
    let err = mcp.call_err("tools/call", json!({"name": "nope", "arguments": {}}));
    assert_eq!(err["code"], -32602);
    let err = mcp.call_err("tools/call", json!({}));
    assert_eq!(err["code"], -32602);

    // A failing command is a result; an unreachable host is a tool error.
    let out = mcp.tool_ok("exec", json!({"host": host, "command": "exit 3"}));
    assert_eq!(out["exit"], 3);
    assert_eq!(
        mcp.tool_code("exec", json!({"host": dead, "command": "true"})),
        "connect_failed"
    );
    let hosts = mcp.tool_ok("hosts", json!({}));
    assert_eq!(hosts["hosts"][1]["host"], dead);
    assert_eq!(hosts["hosts"][1]["connected"], false);

    // No `--allow-local-paths`: put and get are denied before any I/O.
    assert_eq!(
        mcp.tool_code("put", json!({"host": host, "local": "x", "remote": "y"})),
        "denied"
    );
    assert_eq!(
        mcp.tool_code("get", json!({"host": host, "remote": "x", "local": "y"})),
        "denied"
    );

    // Garbage in: a parse error, then service continues.
    mcp.send_raw(b"{not json\n");
    let line = mcp.read_line();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    assert!(reply["id"].is_null());
    assert_eq!(mcp.call("ping", json!({})), json!({}));

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_unknown_without_accept_new() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let mut mcp = Mcp::spawn(&server, &server.host_arg(), &[]);
    let init = mcp.init();
    assert!(
        init["instructions"]
            .as_str()
            .unwrap()
            .contains("trust_unknown")
    );
    assert_eq!(
        mcp.tool_code("exec", json!({"command": "true"})),
        "trust_unknown"
    );
    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resources() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let dir = server.home.join("res");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), "alpha\n").unwrap();
    std::fs::write(dir.join("b.bin"), [0xffu8, 0x00]).unwrap();
    let mut mcp = Mcp::standard(&server);
    mcp.init();
    let host = server.host_arg();

    let list = mcp.call("resources/list", json!({}));
    assert_eq!(list["resources"].as_array().unwrap().len(), 1);
    assert_eq!(list["resources"][0]["uri"], format!("mysh://{host}/"));
    assert_eq!(list["resources"][0]["name"], host);
    assert_eq!(list["resources"][0]["mimeType"], "inode/directory");

    let templates = mcp.call("resources/templates/list", json!({}));
    assert_eq!(
        templates["resourceTemplates"][0]["uriTemplate"],
        "mysh://{host}/{path}"
    );

    let uri = format!("mysh://{host}{}", dir.join("a.txt").display());
    let read = mcp.call("resources/read", json!({"uri": uri}));
    assert_eq!(read["contents"][0]["uri"], uri);
    assert_eq!(read["contents"][0]["mimeType"], "text/plain");
    assert_eq!(read["contents"][0]["text"], "alpha\n");

    let uri = format!("mysh://{host}{}", dir.join("b.bin").display());
    let read = mcp.call("resources/read", json!({"uri": uri}));
    assert_eq!(read["contents"][0]["mimeType"], "application/octet-stream");
    assert_eq!(
        unb64(read["contents"][0]["blob"].as_str().unwrap()),
        [0xff, 0x00]
    );

    // Home-relative and directory reads.
    let read = mcp.call(
        "resources/read",
        json!({"uri": format!("mysh://{host}/~/res")}),
    );
    assert_eq!(read["contents"][0]["mimeType"], "application/json");
    let listing: Value =
        serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    let names: Vec<&str> = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["a.txt", "b.bin"]);
    let read = mcp.call("resources/read", json!({"uri": format!("mysh://{host}/")}));
    assert_eq!(read["contents"][0]["mimeType"], "application/json");

    let err = mcp.call_err(
        "resources/read",
        json!({"uri": format!("mysh://{host}/~/res/none")}),
    );
    assert_eq!(err["code"], -32002);
    assert_eq!(err["data"]["code"], "not_found");
    let err = mcp.call_err("resources/read", json!({"uri": "file:///etc/hosts"}));
    assert_eq!(err["code"], -32602);
    let err = mcp.call_err("resources/read", json!({"uri": "mysh://other/x"}));
    assert_eq!(err["code"], -32602);

    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn content_length_framing_is_answered_in_kind() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let mut mcp = Mcp::standard(&server);
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}).to_string();
    mcp.send_raw(format!("Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
    let header = mcp.read_line();
    let len: usize = header
        .trim()
        .strip_prefix("Content-Length: ")
        .expect("header reply")
        .parse()
        .unwrap();
    assert_eq!(mcp.read_line(), "\r\n");
    let mut reply = vec![0u8; len];
    mcp.stdout.read_exact(&mut reply).unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"], json!({}));
    // Line framing keeps working afterwards.
    assert_eq!(mcp.call("ping", json!({})), json!({}));
    assert_eq!(mcp.finish(), 0);
    server.stop().await;
}
