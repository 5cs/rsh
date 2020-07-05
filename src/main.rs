mod sh;

fn main() {
    let mut client = sh::Cli::new();
    client.go();
}
