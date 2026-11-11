use clap::Parser;

fn main() {
    let cli = cemi::cli::Cli::parse();
    match cemi::cmd::run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
