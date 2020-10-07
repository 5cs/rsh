use crate::common::CliResult;

pub trait Shell {
    fn prompt(&self) -> CliResult;
    fn bg(&mut self, args: &[&str]) -> CliResult;
    fn fg(&mut self, args: &[&str]) -> CliResult;
    fn jobs(&self) -> CliResult;
    fn cd(&self, args: &[&str]) -> CliResult;
    fn run(&mut self, cmdline: &str, args: &[&str]) -> CliResult;
}
