extern crate libc;
extern crate nix;

use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::convert::TryFrom;
use std::io::{self, Write};
use std::process;

use crate::rsh::Rsh;

pub extern "C" fn handle_sigint(signal: libc::c_int) {
    let _signal = Signal::try_from(signal).unwrap();
    let pid = Rsh::get_fg_pid();
    if pid != 0 {
        if let Err(e) = signal::kill(Pid::from_raw(-pid), Signal::SIGINT) {
            println!("{}: {}", "kill", e.to_string());
            io::stdout().flush().unwrap();
        }
    }
}

pub extern "C" fn handle_sigchld(signal: libc::c_int) {
    let _signal = Signal::try_from(signal).unwrap();
    loop {
        match wait::waitpid(
            Pid::from_raw(-1),
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED),
        ) {
            Ok(n) => {
                if n.pid().is_none() || n.pid().unwrap().as_raw() == -1 {
                    break;
                }
                let pid = n.pid().unwrap();
                if n == WaitStatus::Stopped(pid, Signal::SIGTSTP) {
                    let jid = { Rsh::set_job_stopped(pid.as_raw()) };
                    println!("Job [{}] ({}) stopped by signal 20", jid, pid.as_raw());
                } else {
                    if n == WaitStatus::Signaled(pid, Signal::SIGINT, false) {
                        let jid = { Rsh::get_jid_by_pid(pid.as_raw()) };
                        println!("Job [{}] ({}) terminated by signal 2", jid, pid.as_raw())
                    }
                    Rsh::delete_job_by_pid(pid.as_raw())
                }
            }
            Err(_e) => break,
        };
    }
}

pub extern "C" fn handle_sigtstp(signal: libc::c_int) {
    let _signal = Signal::try_from(signal).unwrap();
    let pid = Rsh::get_fg_pid();
    if pid != 0 {
        if let Err(e) = signal::kill(Pid::from_raw(-pid), Signal::SIGTSTP) {
            println!("{}: {}", "kill", e.to_string());
            io::stdout().flush().unwrap();
        }
    }
}

pub extern "C" fn handle_sigquit(signal: libc::c_int) {
    let _signal = Signal::try_from(signal).unwrap();
    {
        write!(
            io::stdout(),
            "Terminating after receipt of SIGQUIT signal\n"
        )
    }
    .unwrap();
    process::exit(1);
}
