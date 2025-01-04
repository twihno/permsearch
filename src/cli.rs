use std::path::PathBuf;

use clap::Parser;

use crate::input_parser::FilterSet;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "Simple search for finding mistakes in owner and permission settings"
)]
pub struct Args {
    /// List of allowed directory types
    #[arg(short, long)]
    pub directory_filter: Option<FilterSet>,

    /// List of allowed file types
    #[arg(short, long)]
    pub file_filter: Option<FilterSet>,

    /// Remove active config from output
    #[arg(short, long)]
    pub silent: bool,

    /// Ignores symlinks
    #[arg(short, long)]
    pub ignore_symlinks: bool,

    /// Base directory to work upon
    #[arg()]
    pub base_dir: PathBuf,
}
