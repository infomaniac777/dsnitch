use std::process::Command;
use anyhow::Context;
use clap::Parser;

#[derive(Parser, Debug)]
enum CommandType {
    BuildEbpf {
        #[clap(long)]
        release: bool,
    },
    Run {
        #[clap(long)]
        release: bool,
        #[clap(trailing_var_arg = true)]
        run_args: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cmd = CommandType::parse();
    match cmd {
        CommandType::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
        CommandType::Run { release, run_args } => {
            build_ebpf(release)?;
            run_userspace(release, run_args)?;
        }
    }
    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    println!("[INFO] Building dsnitch-ebpf target (bpfel-unknown-none)...");
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
        "build",
        "--manifest-path",
        "dsnitch-ebpf/Cargo.toml",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("failed to build eBPF bytecode")?;
    if !status.success() {
        anyhow::bail!("eBPF build failed with exit status: {}", status);
    }
    println!("[SUCCESS] eBPF bytecode build completed successfully.");
    Ok(())
}

fn run_userspace(release: bool, run_args: Vec<String>) -> anyhow::Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--package", "dsnitch"]);
    if release {
        cmd.arg("--release");
    }
    if !run_args.is_empty() {
        cmd.arg("--");
        cmd.args(run_args);
    }
    let status = cmd.status().context("failed to run userspace binary")?;
    if !status.success() {
        anyhow::bail!("dsnitch exited with status: {}", status);
    }
    Ok(())
}
