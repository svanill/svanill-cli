extern crate rpassword;

use anyhow::Result;
use atty::Stream;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use structopt::StructOpt;
use svanill::crypto::{decrypt, encrypt};
use svanill::proc_utils::attempt_to_lock_memory;

#[cfg(not(debug_assertions))]
use svanill::proc_utils::disable_core_dump;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "svanill",
    about = "An easily auditable tool to encrypt/decrypt your sensitive data."
)]
struct Opt {
    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,
    /// Input file
    #[structopt(name = "input file", parse(from_os_str))]
    input: PathBuf,
    /// Output file, stdout if not present
    #[structopt(short = "o", parse(from_os_str))]
    output: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
    #[structopt(short = "p")]
    /// Password file (useful if you run Svanill without a TTY")
    pw_filepath: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
enum Command {
    ENC {
        /// How many iterations should we do to derive the key
        #[structopt(short = "t", long = "iterations", default_value = "100000")]
        iterations: u32,
    },
    DEC {},
}

fn main() -> Result<()> {
    let is_memory_locked = attempt_to_lock_memory();

    #[cfg(not(debug_assertions))]
    disable_core_dump().unwrap();

    let opt = Opt::from_args();

    if opt.debug && !is_memory_locked {
        eprintln!("WARN: Couldn't lock memory, it could potentially end up in swap file");
    }

    if !atty::is(Stream::Stdin) && opt.pw_filepath.is_none() {
        eprintln!("ERROR: Not a TTY, you must pass the password as command option");
        std::process::exit(1);
    }

    let mut f = File::open(opt.input)?;
    let mut content = Vec::new();
    f.read_to_end(&mut content)
        .unwrap_or_else(|e: std::io::Error| {
            eprintln!("Couldn't read the input file: error was: {}", e);
            std::process::exit(1);
        });

    let mut got_pw_from_file = false;
    let pass1 = if let Some(pw_path) = opt.pw_filepath {
        let pw_f = File::open(pw_path)?;
        let pw_f = BufReader::new(pw_f);
        got_pw_from_file = true;
        rpassword::read_password_with_reader(Some(pw_f)).unwrap()
    } else {
        rpassword::read_password_from_tty(Some("Password: ")).unwrap()
    };

    match opt.cmd {
        Command::ENC { iterations } => {
            if pass1.is_empty() {
                eprintln!("Error: the password cannot be empty");
                std::process::exit(1);
            }

            if !got_pw_from_file {
                let pass2: String = rpassword::read_password_from_tty(Some("Confirm Password: "))?;

                if pass1 != pass2 {
                    eprintln!("Error: the two passwords do not match.");
                    std::process::exit(2);
                }
            }

            let b_encrypted_data = encrypt(&content, &pass1, iterations)?.into_bytes();
            match opt.output {
                Some(path) => File::create(path)?.write_all(&b_encrypted_data)?,
                None => std::io::stdout().write_all(&b_encrypted_data)?,
            }
        }
        Command::DEC {} => match decrypt(&content, &pass1) {
            Ok(b_plaintext) => {
                match opt.output {
                    Some(path) => File::create(path)?.write_all(&b_plaintext)?,
                    None => std::io::stdout().write_all(&b_plaintext)?,
                };
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        },
    };

    Ok(())
}
