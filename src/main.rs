mod cli;
mod common;
mod rsh;
mod sh;
mod signal;

use cli::*;

fn main() {
    let mut client = Cli::new();
    client.go();
}
