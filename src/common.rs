pub type CliResult = Result<String, String>;

pub fn ok<T: ToString>(s: T) -> CliResult {
    Ok(s.to_string())
}

pub fn err<T: ToString>(s: T) -> CliResult {
    Err(s.to_string())
}
