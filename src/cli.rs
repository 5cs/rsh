extern crate nix;

use nix::sys::signal::{self, SigHandler, Signal};
use std::collections::HashMap;
use std::io::{self, Write};
use std::process;

use crate::common::*;
use crate::rsh::Rsh;
use crate::sh::Shell;
use crate::signal::*;

pub struct Cli<'a> {
    builtins: HashMap<String, Box<dyn Fn(&mut dyn Shell, &[&str]) -> CliResult + 'a>>,
}

impl<'a> Cli<'a> {
    pub fn new() -> Cli<'a> {
        // setup signal handler
        {
            let handler = SigHandler::Handler(handle_sigint);
            unsafe { signal::signal(Signal::SIGINT, handler) }.unwrap();
            let handler = SigHandler::Handler(handle_sigchld);
            unsafe { signal::signal(Signal::SIGCHLD, handler) }.unwrap();
            let handler = SigHandler::Handler(handle_sigtstp);
            unsafe { signal::signal(Signal::SIGTSTP, handler) }.unwrap();
            let handler = SigHandler::Handler(handle_sigquit);
            unsafe { signal::signal(Signal::SIGQUIT, handler) }.unwrap();
        }

        let mut cli = Cli {
            builtins: HashMap::new(),
        };
        // register builtins
        {
            cli.builtin("prompt", |sh, _| sh.prompt());
            cli.builtin("quit", |_, _| process::exit(0));
            cli.builtin("exit", |_, _| process::exit(0));
            cli.builtin("jobs", |sh, _| sh.list_job());
            cli.builtin("bg", |sh, args| sh.bg(args));
            cli.builtin("fg", |sh, args| sh.fg(args));
            cli.builtin("cd", |sh, args| sh.cd(args));
        }
        cli
    }

    fn builtin<F>(&mut self, name: &str, builtin: F)
    where
        F: Fn(&mut dyn Shell, &[&str]) -> CliResult + 'a,
    {
        self.builtins.insert(name.to_owned(), Box::new(builtin));
    }

    fn dispatch(&mut self, line: &str) -> CliResult {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() == 0 {
            return ok("".to_owned());
        }
        let res = match self.builtins.get(parts[0]) {
            Some(f) => Rsh::run_builtin(f, &parts[1..]),
            None => Rsh::run_non_builtin(line, &parts),
        };
        // wait fg job to finish
        let pid = Rsh::get_fg_pid();
        if pid > 0 {
            loop {
                let pid1 = Rsh::get_fg_pid();
                if pid1 != pid {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        res
    }

    pub fn go(&mut self) {
        let mut buf = String::new();
        loop {
            self.dispatch("prompt").unwrap();
            buf.clear();
            if io::stdin().read_line(&mut buf).expect("error") <= 0 {
                break;
            }
            {
                let line = buf.trim_start();
                let res = self.dispatch(line);
                match res {
                    Ok(o) => print!("{}", o),
                    Err(e) => print!("{}", e),
                };
                io::stdout().flush().unwrap();
            }
        }
    }
}
