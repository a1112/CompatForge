use crate::ProbeCommandFailure;
use std::process::Child;

pub(crate) struct ProcessGroup {
    process_group_id: i32,
}

impl ProcessGroup {
    pub(crate) fn for_child(child: &Child) -> Result<Self, ProbeCommandFailure> {
        let process_group_id = i32::try_from(child.id()).map_err(|_| ProbeCommandFailure::Spawn)?;
        if process_group_id <= 1 {
            return Err(ProbeCommandFailure::Spawn);
        }
        Ok(Self { process_group_id })
    }

    pub(crate) fn force_kill(&self) -> Result<(), ProbeCommandFailure> {
        // SAFETY: the negative PID names the isolated process group created for
        // this exact live probe transaction. `kill` does not access Rust memory.
        let result = unsafe { libc::kill(-self.process_group_id, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(ProbeCommandFailure::Cleanup)
        }
    }

    pub(crate) fn is_absent(&self) -> Result<bool, ProbeCommandFailure> {
        group_is_absent(self.process_group_id)
    }
}

pub(crate) fn group_is_absent(process_group_id: i32) -> Result<bool, ProbeCommandFailure> {
    if process_group_id <= 1 {
        return Err(ProbeCommandFailure::Cleanup);
    }
    // SAFETY: signal zero performs existence/permission checking only. The
    // negative PID addresses the known process group and touches no Rust memory.
    let result = unsafe { libc::kill(-process_group_id, 0) };
    if result == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        Some(libc::EPERM) => Ok(false),
        _ => Err(ProbeCommandFailure::Cleanup),
    }
}
