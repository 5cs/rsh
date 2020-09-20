extern crate lazy_static;
extern crate libc;
extern crate nix;

use lazy_static::lazy_static;
use nix::errno::Errno;
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};
use nix::unistd::{self, ForkResult, Pid};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::*;
use std::process;
use std::sync::{Arc, Mutex};

use crate::common::*;
use crate::sh::Shell;

#[derive(Debug, PartialEq)]
enum State {
    UNDEF,
    BG,
    FG,
    ST,
}

type FdCmd = (i32, String);

#[derive(Debug)]
struct Job {
    pid: i32,
    jid: i32,
    state: State,
    cmdline: String,
}

#[derive(Debug)]
pub struct Rsh {
    emit_prompt: bool,
    prompt: String,
    verbose: bool,
    next_jid: i32,
    jobs: Vec<Box<Job>>,
}

lazy_static! {
    static ref SH: Arc<Mutex<Rsh>> = Arc::new(Mutex::new(Rsh::default()));
}

impl Default for Rsh {
    fn default() -> Self {
        Rsh {
            emit_prompt: true,
            prompt: "rsh> ".to_owned(),
            verbose: false,
            next_jid: 1,
            jobs: Vec::new(),
        }
    }
}

impl Shell for Rsh {
    fn prompt(&self) -> CliResult {
        if self.emit_prompt {
            print!("{}", self.prompt);
            io::stdout().flush().unwrap();
        }
        ok("")
    }

    fn bg(&mut self, args: &[&str]) -> CliResult {
        if args.len() == 0 {
            return err("bg command requires PID or %%jobid argument\n");
        }
        self.do_bgfg(args, true)
    }

    fn fg(&mut self, args: &[&str]) -> CliResult {
        if args.len() == 0 {
            return err("fg command requires PID or %%jobid argument\n");
        }
        self.do_bgfg(args, false)
    }

    fn list_job(&self) -> CliResult {
        for job in self.jobs.iter() {
            if job.pid != 0 {
                print!("[{}] ({}) ", job.jid, job.pid);
                match job.state {
                    State::BG => print!("Running "),
                    State::FG => print!("Foreground "),
                    State::ST => print!("Stopped "),
                    _ => print!(
                        "listjobs: Internal error: job[{}].state={:?} ",
                        job.jid, job.state
                    ),
                }
                print!("{}", job.cmdline);
            }
        }
        ok("")
    }

    fn cd(&self, args: &[&str]) -> CliResult {
        if args.len() > 1 {
            { write!(io::stderr(), "cd: too many argument\n") }.unwrap();
            io::stderr().flush().unwrap();
        } else if args.len() == 0 {
            std::env::set_current_dir(dirs::home_dir().unwrap()).unwrap();
        } else {
            let target = args[0].trim().to_owned();
            // TODO: cd -
            let mut path = if target.starts_with("/") {
                std::path::PathBuf::new().join("/")
            } else {
                std::env::current_dir().unwrap()
            };
            for part in target.split("/") {
                if part == ".." {
                    if !path.pop() {
                        path = path.join("/");
                    }
                    continue;
                }
                if part != "." {
                    path = path.join(part);
                }
            }
            if let Err(e) = std::env::set_current_dir(path) {
                println!("cd: {}", e.to_string());
                io::stdout().flush().unwrap();
            }
        }
        ok("")
    }

    fn run(&mut self, cmdline: &str, parts: &[&str]) -> CliResult {
        let mut set = SigSet::empty();
        set.add(Signal::SIGCHLD);
        if let Err(e) = signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), None) {
            println!("{}: {}", "sigprocmask", e.to_string());
            process::exit(1);
        }
        match unistd::fork() {
            Ok(ForkResult::Child) => {
                if let Err(e) = signal::sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&set), None) {
                    println!("{}: {}", "sigprocmask", e.to_string());
                    process::exit(1);
                }
                // new job belongs to 1 process group
                if let Err(e) = unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
                    println!("{}: {}", "setpgid", e.to_string());
                    process::exit(1);
                }

                // pipe command
                // example 0: ls -l | wc
                // example 1: tee < input.txt | grep cargo | wc > output.txt
                // example 2: tee < input.txt > output.txt
                // example 3: tee > output.txt < input.txt
                let mut cmds: Vec<_> = cmdline.split('|').map(|x| x.trim()).collect();
                // reverse order, let last command's process run as child of shell process
                cmds.reverse();

                let mut last_cmd = String::new();
                last_cmd.push_str(cmds.first().unwrap_or(&""));
                let (output_fd, cmd): FdCmd =
                    Rsh::create_fd_and_truncate_redirect_pattern(&mut last_cmd, true);
                cmds[0] = &cmd;
                Rsh::process(&cmds, output_fd);
            }
            Ok(ForkResult::Parent { child, .. }) => {
                let bg = match parts.last() {
                    Some(&"&") => true,
                    _ => false,
                };
                let state = if bg { State::BG } else { State::FG };
                self.add_job(child.as_raw(), state, cmdline);
                signal::sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&set), None).unwrap();
                if bg {
                    print!(
                        "[{}] ({}) {}",
                        self.pid_to_jid(child.as_raw()),
                        child.as_raw(),
                        cmdline
                    );
                }
            }
            Err(_) => println!("fork failed!"),
        };
        ok("")
    }
}

impl Rsh {
    pub fn run_builtin<F>(f: F, args: &[&str]) -> CliResult
    where
        F: Fn(&mut dyn Shell, &[&str]) -> CliResult,
    {
        let tmp = SH.clone();
        let mut sh = tmp.lock().unwrap();
        f(&mut *sh, args)
    }

    pub fn run_non_builtin(cmdline: &str, args: &[&str]) -> CliResult {
        let tmp = SH.clone();
        let mut sh = tmp.lock().unwrap();
        sh.run(cmdline, args)
    }

    pub fn get_fg_pid() -> i32 {
        let tmp = SH.clone();
        let sh = tmp.lock().unwrap();
        sh.fg_pid()
    }

    pub fn get_jid_by_pid(pid: i32) -> i32 {
        let tmp = SH.clone();
        let sh = tmp.lock().unwrap();
        match sh.jobs.iter().find(|job| job.pid == pid) {
            Some(ref job) => job.jid,
            None => 0,
        }
    }

    pub fn set_job_stopped(pid: i32) -> i32 {
        let tmp = SH.clone();
        let mut sh = tmp.lock().unwrap();
        match sh.jobs.iter_mut().find(|job| job.pid == pid) {
            Some(job) => {
                job.state = State::ST;
                job.jid
            }
            None => 0,
        }
    }

    pub fn delete_job_by_pid(pid: i32) {
        let tmp = SH.clone();
        let mut sh = tmp.lock().unwrap();
        if pid < 1 {
            return;
        }
        match sh.jobs.iter_mut().find(|job| job.pid == pid) {
            Some(ref mut job) => {
                job.pid = 0;
                job.jid = 0;
                job.state = State::UNDEF;
                job.cmdline = "".to_string();
                sh.next_jid = sh.get_next_jid();
            }
            None => return,
        }
    }

    fn do_bgfg(&mut self, args: &[&str], bg: bool) -> CliResult {
        let mut arg = args[0].to_owned();
        let mut is_jid = false;
        if arg.starts_with("%") {
            is_jid = true;
            arg = arg.chars().skip(1).collect();
        }
        let typ = if bg { "bg" } else { "fg" };
        let id = match arg.parse::<i32>() {
            Ok(n) => n,
            Err(_) => {
                return err(format!("{}: argument must be a PID or %jobid\n", typ));
            }
        };
        let mut _job = if is_jid {
            self.jobs.iter_mut().find(|job| job.jid == id)
        } else {
            self.jobs.iter_mut().find(|job| job.pid == id)
        };
        let job = match _job {
            Some(j) => j,
            None => {
                if is_jid {
                    return err(format!("{}: No such job\n", typ));
                } else {
                    return err(format!("({}): No such process\n", typ));
                }
            }
        };
        if job.state == State::ST {
            unsafe {
                if libc::kill(-job.pid, libc::SIGCONT) == -1 {
                    println!("{}", "kill");
                    process::exit(1);
                }
            }
        }
        job.state = if bg { State::BG } else { State::FG };
        if bg {
            print!("[{}] ({}) {}", job.jid, job.pid, job.cmdline);
        }
        ok("")
    }

    fn add_job(&mut self, pid: i32, state: State, cmdline: &str) {
        if pid < 0 {
            return;
        }
        for job in self.jobs.iter_mut() {
            // reuse empty slot
            if job.pid == 0 {
                job.pid = pid;
                job.jid = self.next_jid;
                job.state = state;
                job.cmdline = cmdline.to_string();
                self.next_jid += 1;
                if self.verbose {
                    print!("Added job [{}] {} {}", job.jid, job.pid, job.cmdline);
                    io::stdout().flush().unwrap();
                }
                return;
            }
        }
        // create job
        let job = Job {
            pid,
            jid: self.next_jid,
            state,
            cmdline: cmdline.to_string(),
        };
        if self.verbose {
            print!("Added job [{}] {} {}", job.jid, job.pid, job.cmdline);
            io::stdout().flush().unwrap();
        }
        self.jobs.push(Box::new(job));
        self.next_jid += 1;
    }

    fn pid_to_jid(&self, pid: i32) -> i32 {
        if let Some(e) = self.jobs.iter().find(|job| job.pid == pid) {
            e.pid
        } else {
            0
        }
    }

    fn fg_pid(&self) -> i32 {
        if let Some(e) = self.jobs.iter().find(|job| job.state == State::FG) {
            e.pid
        } else {
            0
        }
    }

    fn get_next_jid(&self) -> i32 {
        self.jobs.iter().max_by_key(|job| job.jid).unwrap().jid + 1
    }

    fn process(cmds: &[&str], pipe_write: i32) {
        if cmds.len() <= 1 {
            let mut first_cmd = String::new();
            first_cmd.push_str(cmds.first().unwrap_or(&""));
            let (input_fd, cmd): FdCmd =
                Rsh::create_fd_and_truncate_redirect_pattern(&mut first_cmd, false);
            Rsh::exec(&cmd, input_fd, pipe_write);
        } else {
            let (read_end, write_end) = unistd::pipe().unwrap();
            match unistd::fork().unwrap() {
                ForkResult::Parent { .. } => {
                    unistd::close(write_end).unwrap();
                    Rsh::exec(cmds.first().unwrap(), read_end, pipe_write);
                }
                ForkResult::Child => {
                    unistd::close(read_end).unwrap();
                    Rsh::process(&cmds[1..], write_end);
                }
            }
        }
    }

    fn exec(cmd: &str, input_fd: i32, output_fd: i32) {
        unistd::dup2(input_fd, 0).unwrap();
        unistd::dup2(output_fd, 1).unwrap();
        let parts: Vec<_> = cmd
            .split_whitespace()
            .filter(|&x| x != "&")
            .map(|x| x.trim())
            .collect();
        let array: Vec<_> = parts
            .iter()
            .map(|x| CString::new(x.as_bytes()).unwrap())
            .collect();
        let parts: Vec<&CStr> = array.iter().map(|x| x.as_c_str()).collect();
        if let Err(e) = unistd::execvp(&array[0], &parts) {
            if e.as_errno().unwrap() == Errno::ENOENT {
                { write!(io::stderr(), "{}: Command not found\n", cmd) }.unwrap();
                io::stderr().flush().unwrap();
                process::exit(1);
            } else {
                { write!(io::stdout(), "{}: {}\n", "execvp", e.to_string()) }.unwrap();
                io::stdout().flush().unwrap();
                process::exit(0);
            }
        }
    }

    fn create_fd_and_truncate_redirect_pattern(cmd: &mut str, is_output: bool) -> FdCmd {
        let mut modified_cmd = cmd.to_string();
        let pattern = if is_output { '>' } else { '<' };

        let raw_fd = match cmd.find(pattern) {
            Some(start) => {
                modified_cmd = "".to_string();
                modified_cmd.push_str(&cmd[..start]);
                let path = cmd[start + 1..].trim().to_string();
                let end = path.find(' ').unwrap_or(path.len());
                modified_cmd.push_str(&path[end..]);

                let res = if is_output {
                    File::create(path[..end].trim().to_string())
                } else {
                    File::open(path[..end].trim().to_string())
                };
                match res {
                    Ok(f) => f.into_raw_fd(),
                    Err(e) => {
                        println!("rsh: {}", e.to_string());
                        process::exit(1);
                    }
                }
            }
            None => {
                if is_output {
                    1
                } else {
                    0
                }
            }
        };

        (raw_fd, modified_cmd)
    }
}
