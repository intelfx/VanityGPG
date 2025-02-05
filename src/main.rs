//! # VanityGPG (default binary)
//!
//! A simple tool for generating and filtering vanity GPG keys, c0nCurr3nt1Y.
//! (a.k.a. OpenPGP key fingerprint collision tool)

extern crate backtrace;
extern crate clap;
extern crate colored;
extern crate indicatif;
extern crate log;
extern crate mimalloc;
extern crate rayon;
extern crate fancy_regex as regex;

extern crate vanity_gpg;

mod logger;

use anyhow::Error;
use backtrace::Backtrace;
use clap::{Parser, ValueEnum};
use log::{debug, info, warn, Level};
use rayon::ThreadPoolBuilder;
use regex::Regex;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vanity_gpg::{Backend, CipherSuite, DefaultBackend, UserID};
use vanity_gpg::Match;
use vanity_gpg::score;

use logger::{IndicatifBackend, ProgressLogger, ProgressLoggerBackend};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Constants
/// Default log level
const PKG_LOG_LEVEL_DEFAULT: Level = Level::Warn;
/// Log level with `-v`
const PKG_LOG_LEVEL_VERBOSE_1: Level = Level::Info;
/// Log level with `-vv` and beyond
const PKG_LOG_LEVEL_VERBOSE_2: Level = Level::Debug;
/// Log level with `-vvv` and beyond
const PKG_LOG_LEVEL_VERBOSE_3: Level = Level::Trace;
/// Program version (from `Cargo.toml`)
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Program description (from `Cargo.toml`)
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Program repository (from `Cargo.toml`)
const PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Key reshuffle limit
const KEY_RESHUFFLE_LIMIT: usize = 60 * 60 * 24 * 30; // One month ago at worst
/// Counter threshold
const COUNTER_THRESHOLD: usize = 133331; // Just a random number

/// Possible values for CipherSuite
#[derive(ValueEnum, Clone, Debug)]
enum CipherSuiteValues {
    Ed25519,
    RSA2048,
    RSA3072,
    RSA4096,
    NISTP256,
    NISTP384,
    NISTP521,
}

/// Commandline option parser with `Clap`
#[derive(Parser, Debug)]
#[clap(version = PKG_VERSION, about = PKG_DESCRIPTION)]
struct Opts {
    /// Concurrent key generation jobs
    #[clap(
        short = 'j',
        long = "jobs",
        help = "Number of threads",
        default_value = "8"
    )]
    jobs: usize,
    /// Regex pattern for matching fingerprints
    #[clap(
        short = 'p',
        long = "pattern",
        help = "Regex pattern for matching fingerprints"
    )]
    pattern: Option<String>,
    #[clap(
    short = 'm',
    long = "min-score",
    help = "Minimum score (according to user scoring function) to match"
    )]
    min_score: Option<u32>,
    /// Cipher suite
    #[clap(
        short = 'c',
        long = "cipher-suite",
        help = "Cipher suite",
    )]
    cipher_suite: CipherSuiteValues,
    /// User ID
    #[clap(short = 'u', long = "user-id", help = "OpenPGP compatible user ID")]
    user_id: Option<String>,
    #[clap(
        short = 'd',
        long = "dry-run",
        help = "Dry run (does not save matched keys)"
    )]
    dry_run: bool,
    /// Verbose level
    #[clap(
        short = 'v',
        long = "verbose",
        help = "Verbose level",
        action = clap::ArgAction::Count
    )]
    verbose: u8,
}

/// Counter for statistics
#[derive(Debug)]
struct Counter {
    total: AtomicUsize,
    success: AtomicUsize,
}

/// Wrapper for the backends
#[derive(Debug)]
struct Key<B: Backend> {
    backend: B,
}

/// Save string to file
fn save_file(file_name: String, content: &str) -> Result<(), Error> {
    let mut file = File::create(file_name)?;
    Ok(file.write_all(content.as_bytes())?)
}

/// Set panic hook with repository information
fn setup_panic_hook() {
    panic::set_hook(Box::new(move |panic_info: &panic::PanicInfo| {
        if let Some(info) = panic_info.payload().downcast_ref::<&str>() {
            println!("Panic occurred: {:?}", info);
        } else {
            println!("Panic occurred");
        }
        if let Some(location) = panic_info.location() {
            println!(
                r#"In file "{}" at line "{}""#,
                location.file(),
                location.line()
            );
        }
        println!("Traceback:");
        println!("{:#?}", Backtrace::new());
        println!();
        println!("Please report this error to {}/issues", PKG_REPOSITORY);
    }));
}

/// Setup logger and return a `ProgressBar` that can be shared between threads
fn setup_logger<B: 'static + ProgressLoggerBackend>(
    verbosity: u8,
    backend: B,
) -> Result<Arc<Mutex<B>>, Error> {
    let level = match verbosity {
        0 => PKG_LOG_LEVEL_DEFAULT,
        1 => PKG_LOG_LEVEL_VERBOSE_1,
        2 => PKG_LOG_LEVEL_VERBOSE_2,
        _ => PKG_LOG_LEVEL_VERBOSE_3,
    };
    let logger = ProgressLogger::new(level, backend);
    debug!("Logger initialized");
    let cloned_backend = logger.get_backend();
    logger.setup()?;
    Ok(cloned_backend)
}

/// Sub-thread that display status summary
fn setup_summary<B: ProgressLoggerBackend>(logger_backend: Arc<Mutex<B>>, counter: Arc<Counter>) {
    let start = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(100));
        debug!("Updating counter information");
        let secs_elapsed = start.elapsed().as_secs();
        logger_backend.lock().unwrap().set_message(&format!(
            "Summary: {} (avg. {:.2} hash/s)",
            &counter,
            counter.get_total() as f64 / secs_elapsed as f64
        ));
    }
}

impl Default for CipherSuiteValues {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl From<&CipherSuiteValues> for CipherSuite {
    fn from(value: &CipherSuiteValues) -> Self {
        match &value {
            CipherSuiteValues::Ed25519 => CipherSuite::Curve25519,
            CipherSuiteValues::RSA2048 => CipherSuite::RSA2048,
            CipherSuiteValues::RSA3072 => CipherSuite::RSA3072,
            CipherSuiteValues::RSA4096 => CipherSuite::RSA4096,
            CipherSuiteValues::NISTP256 => CipherSuite::NistP256,
            CipherSuiteValues::NISTP384 => CipherSuite::NistP384,
            CipherSuiteValues::NISTP521 => CipherSuite::NistP521,
        }
    }
}

impl Counter {
    /// Create new instance
    fn new() -> Self {
        Self {
            total: AtomicUsize::new(0),
            success: AtomicUsize::new(0),
        }
    }

    /// Count towards total numbers of fingerprints generated
    fn count_total(&self, accumulated_counts: usize) {
        self.total.fetch_add(accumulated_counts, Ordering::SeqCst);
    }

    /// Count towards total numbers of fingerprints matched
    fn count_success(&self) {
        self.success.fetch_add(1, Ordering::SeqCst);
    }

    /// Get number of total fingerprints generated
    fn get_total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    /// Get number of total fingerprints matched
    fn get_success(&self) -> usize {
        self.success.load(Ordering::SeqCst)
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} matched, {} total",
            self.get_success(),
            self.get_total(),
        )
    }
}

impl<B: Backend> Key<B> {
    /// Create new instance
    fn new(backend: B) -> Key<B> {
        Key { backend }
    }

    /// Get fingerprint
    fn get_fingerprint(&self) -> String {
        self.backend.fingerprint()
    }

    /// Rehash the key
    fn shuffle(&mut self) -> Result<(), Error> {
        Ok(self.backend.shuffle()?)
    }

    /// Save armored keys
    fn save_key(self, user_id: &UserID, dry_run: bool, score: u32) -> Result<(), Error> {
        if dry_run {
            return Ok(());
        }
        let fingerprint = self.get_fingerprint();
        let fingerprint0 = &fingerprint[0..fingerprint.len()-8];
        let fingerprint8 = &fingerprint[fingerprint.len()-8..];
        info!("saving [{} {}] (score={})", &fingerprint0, &fingerprint8, score);
        let armored_keys = self.backend.get_armored_results(user_id)?;
        save_file(
            format!("score{}-{}_{}-private.asc", score, &fingerprint0, &fingerprint8),
            armored_keys.get_private_key(),
        )?;
        save_file(
            format!("score{}-{}_{}-public.asc", score, &fingerprint0, &fingerprint8),
            armored_keys.get_public_key(),
        )?;
        Ok(())
    }
}

fn do_match(fingerprint: &str, pattern: &Option<Regex>, min_score: Option<u32>) -> Result<Match<u32>, regex::Error> {
    pattern
        .as_ref()
        .map_or(Ok(true), |pattern| pattern.is_match(fingerprint))
        .map(|is_match| if is_match { score(fingerprint) } else { Match::No })
        .map(|score| {
            if let (Some(min_score), Match::Yes(score)) = (min_score, score) {
                if score < min_score {
                    return Match::No;
                }
            }
            score
        })
}

/// Start the program
fn main() -> Result<(), Error> {
    // Setup panic hook
    setup_panic_hook();

    // Parse commandline options
    let opts: Opts = Opts::parse();

    // Setup logger and show some messages
    let logger_backend = setup_logger(opts.verbose, IndicatifBackend::init())?;
    warn!("Staring VanityGPG version v{}", PKG_VERSION);
    warn!("(So fast, such concurrency, wow)");
    warn!(
        "if you met any issue, please file an issue report to \"{}\"",
        PKG_REPOSITORY
    );
    let counter = Arc::new(Counter::new());

    let pool = ThreadPoolBuilder::new()
        .num_threads(opts.jobs + 1)
        .build()?;
    let user_id = UserID::from(opts.user_id);
    let pattern = opts.pattern.as_ref().map_or(Ok(None), |s| Regex::new(s).map(Some))?;

    for thread_id in 0..opts.jobs {
        let user_id = user_id.clone();
        let pattern = pattern.clone();
        let cipher_suite = CipherSuite::from(&opts.cipher_suite);
        let counter = Arc::clone(&counter);
        info!("({}): Spawning thread", thread_id);
        pool.spawn(move || {
            let mut key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
            let mut reshuffle_counter: usize = KEY_RESHUFFLE_LIMIT;
            let mut report_counter: usize = 0;
            loop {
                let fingerprint = key.get_fingerprint();
                if let Match::Yes(score) = do_match(&fingerprint, &pattern, opts.min_score).unwrap() {
                    let fingerprint0 = &fingerprint[0..fingerprint.len()-8];
                    let fingerprint8 = &fingerprint[fingerprint.len()-8..];
                    warn!("({}): [{} {}] matched (score={})", thread_id, &fingerprint0, &fingerprint8, score);
                    counter.count_success();
                    key.save_key(&user_id, opts.dry_run, score).unwrap_or(());
                    key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
                    reshuffle_counter = KEY_RESHUFFLE_LIMIT;
                } else if reshuffle_counter == 0 {
                    info!(
                        "({}): Reshuffle limit reached, generating new primary key",
                        thread_id
                    );
                    key = Key::new(DefaultBackend::new(cipher_suite.clone()).unwrap());
                    reshuffle_counter = KEY_RESHUFFLE_LIMIT;
                } else {
                    info!("({}): [{}] is not a match", thread_id, fingerprint);
                    reshuffle_counter -= 1;
                    key.shuffle().unwrap_or(());
                }
                report_counter += 1;
                if report_counter >= COUNTER_THRESHOLD {
                    counter.count_total(report_counter);
                    report_counter = 0;
                }
            }
        });
    }

    // Setup summary
    let logger_backend_cloned = Arc::clone(&logger_backend);
    let counter_cloned = Arc::clone(&counter);
    pool.install(move || setup_summary(logger_backend_cloned, counter_cloned));

    Ok(())
}
