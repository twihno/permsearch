use clap::Parser;
use permsearch::{cli::Args, run, util::exit_with_error};

#[cfg(unix)]
fn main() {
    let args = Args::parse();

    if !args.base_dir.exists() {
        exit_with_error(&format!("Base directory {:?} doesn't exist", args.base_dir));
    }

    if let Err(err) = run(&args) {
        eprintln!("{err}");
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("This program only works on unixoid systems")
}
