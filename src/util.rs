use std::process::exit;

use clap::builder::styling::{AnsiColor, Color, Style};

pub fn exit_with_error(msg: &str) -> ! {
    print_error(msg);
    exit(1);
}

pub fn print_error(msg: &str) {
    let style = Style::new()
        .bold()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)));

    eprintln!("{style}error{style:#}: {msg}");
}

pub fn print_access_error(msg: &str) {
    let style = Style::new()
        .bold()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)));

    eprintln!("{style}Error{style:#} {msg}");
}
