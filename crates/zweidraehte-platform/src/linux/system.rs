use crate::traits::SystemControl;

/// Linux system control implementation.
///
/// Restarts the application by re-executing the current process using `exec()`.
/// All file descriptors except stdin/stdout/stderr are closed before exec to
/// avoid leaking sockets, serial ports, etc. to the new process.
pub struct LinuxSystem;

impl SystemControl for LinuxSystem {
    type Error = std::io::Error;

    async fn restart(&mut self) -> Result<!, Self::Error> {
        let exe = std::env::current_exe()?;
        let args: Vec<_> = std::env::args().collect();

        // Close all file descriptors except stdin/stdout/stderr (0, 1, 2)
        // to avoid leaking sockets, serial ports, etc. to the new process.
        unsafe {
            let max_fd = nix::libc::sysconf(nix::libc::_SC_OPEN_MAX) as i32;
            for fd in 3..max_fd {
                nix::libc::close(fd);
            }
        }

        // Use exec to replace the current process with a fresh instance
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(exe).args(&args[1..]).exec();

        // exec() only returns on error
        Err(err)
    }
}
