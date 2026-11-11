use clap::{CommandFactory, Parser};

/// The command line is large; Windows gives the main thread only 1 MiB of
/// stack, which debug builds outgrow. Run everything on a thread with room.
const STACK: usize = 8 * 1024 * 1024;

fn main() {
    let worker = std::thread::Builder::new()
        .name("cemi".into())
        .stack_size(STACK)
        .spawn(|| {
            // `COMPLETE=<shell> cemi …` answers the shell and exits here.
            clap_complete::CompleteEnv::with_factory(cemi::cli::Cli::command).complete();
            let cli = cemi::cli::Cli::parse();
            match cemi::cmd::run(cli) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    1
                }
            }
        })
        .expect("cannot start the main thread");
    let code = worker.join().unwrap_or(101);
    std::process::exit(code);
}
