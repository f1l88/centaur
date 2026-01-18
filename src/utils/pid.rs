use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub fn write_pid<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let pid = std::process::id();
    let mut file = fs::File::create(path)?;
    writeln!(file, "{pid}")?;
    Ok(())
}

pub fn read_pid<P: AsRef<Path>>(path: P) -> io::Result<u32> {
    let content = fs::read_to_string(path)?;
    Ok(content.trim().parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid PID")
    })?)
}
