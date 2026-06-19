//! CLI for pinning and verifying MCP tool-definition integrity.
//!
//! Usage:
//!   ais-tool-integrity pin    [--in tools.json] [--out tools.lock.json]
//!   ais-tool-integrity verify  --lock tools.lock.json [--in tools.json]
//!
//! Input is an MCP `tools/list` response (`{"tools":[...]}`) or a bare tool
//! array. With no `--in`, input is read from stdin; with no `--out`, the
//! manifest is written to stdout.
//!
//! Exit codes: 0 = clean, 2 = drift detected, 1 = usage or I/O error.

use std::io::{self, Read};
use std::process::ExitCode;

use ais_tool_integrity::{extract_tools, pin, verify, Manifest};
use serde_json::Value;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let command = args.first().map(String::as_str);
    match command {
        Some("pin") => cmd_pin(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        _ => Err(usage()),
    }
}

fn cmd_pin(args: &[String]) -> Result<ExitCode, String> {
    let opts = parse_opts(args)?;
    if opts.lock.is_some() {
        return Err("`--lock` is not valid for `pin`".into());
    }
    let tools = read_tools(opts.input.as_deref())?;
    let manifest = pin(&tools).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    match opts.output {
        Some(path) => std::fs::write(&path, json).map_err(|e| format!("{path}: {e}"))?,
        None => println!("{json}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode, String> {
    let opts = parse_opts(args)?;
    let lock = opts.lock.ok_or("`verify` requires `--lock <manifest>`")?;
    let manifest: Manifest = {
        let text = std::fs::read_to_string(&lock).map_err(|e| format!("{lock}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{lock}: {e}"))?
    };
    let tools = read_tools(opts.input.as_deref())?;
    let report = verify(&manifest, &tools).map_err(|e| e.to_string())?;

    if report.is_clean() {
        println!("OK: {} tool(s) match the pinned manifest.", manifest.tools.len());
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("DRIFT DETECTED:");
    for name in &report.changed {
        eprintln!("  changed (definition tampered): {name}");
    }
    for name in &report.added {
        eprintln!("  added (not in manifest):       {name}");
    }
    for name in &report.removed {
        eprintln!("  removed (was pinned):          {name}");
    }
    Ok(ExitCode::from(2))
}

struct Opts {
    input: Option<String>,
    output: Option<String>,
    lock: Option<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts { input: None, output: None, lock: None };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--in" => opts.input = Some(next_value(&mut it, "--in")?),
            "--out" => opts.output = Some(next_value(&mut it, "--out")?),
            "--lock" => opts.lock = Some(next_value(&mut it, "--lock")?),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(opts)
}

fn next_value(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next().cloned().ok_or_else(|| format!("{flag} requires a value"))
}

fn read_tools(path: Option<&str>) -> Result<Vec<Value>, String> {
    let text = match path {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("stdin: {e}"))?;
            buf
        }
    };
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    extract_tools(&value).map_err(|e| e.to_string())
}

fn usage() -> String {
    "usage:\n  ais-tool-integrity pin    [--in tools.json] [--out tools.lock.json]\n  \
     ais-tool-integrity verify --lock tools.lock.json [--in tools.json]"
        .into()
}
