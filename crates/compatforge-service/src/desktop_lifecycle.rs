//! Admission and completion tracking for a desktop-owned service.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub const CLOSING: &str = "桌面正在退出，已拒绝新的运行请求";

#[derive(Default)]
struct State {
    closing: bool,
    generation: u64,
    workers: usize,
    cleanup_complete: bool,
    cleanup_running: bool,
}

#[derive(Default)]
pub struct DesktopLifecycle {
    state: Mutex<State>,
    drained: Condvar,
    dispatch: Mutex<()>,
}

pub struct WorkerPermit {
    lifecycle: Arc<DesktopLifecycle>,
    generation: u64,
}

impl DesktopLifecycle {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub fn admit(self: &Arc<Self>) -> Result<WorkerPermit, &'static str> {
        let mut state = self.state();
        if state.closing {
            return Err(CLOSING);
        }
        state.workers += 1;
        Ok(WorkerPermit {
            lifecycle: Arc::clone(self),
            generation: state.generation,
        })
    }

    pub fn begin_close(&self) -> bool {
        let mut state = self.state();
        if state.cleanup_running || state.cleanup_complete {
            return false;
        }
        state.closing = true;
        state.generation += 1;
        state.cleanup_running = true;
        true
    }

    pub fn wait_for_workers(&self) {
        let mut state = self.state();
        while state.workers != 0 {
            state = self.drained.wait(state).unwrap_or_else(|error| error.into_inner());
        }
    }

    pub fn complete_cleanup(&self) {
        let mut state = self.state();
        state.cleanup_complete = true;
        state.cleanup_running = false;
    }
    pub fn cleanup_failed(&self) {
        self.state().cleanup_running = false;
    }
    pub fn cleanup_complete(&self) -> bool {
        self.state().cleanup_complete
    }
}

impl WorkerPermit {
    /// Execute on a background worker only. Bootstrap and service mutations use
    /// this shared serial dispatcher and recheck closing after waiting for it.
    pub fn dispatch<T>(&self, operation: impl FnOnce() -> T) -> Result<T, &'static str> {
        let _dispatch = self.lifecycle.dispatch.lock().map_err(|_| "应用服务队列状态锁已损坏")?;
        self.ensure_open()?;
        Ok(operation())
    }

    pub fn ensure_open(&self) -> Result<(), &'static str> {
        self.check(&self.lifecycle.state())
    }

    /// Keep publication short: never run probes, service calls or resource cleanup
    /// while holding this gate.
    pub fn publish<T>(&self, publish: impl FnOnce() -> T) -> Result<T, &'static str> {
        let state = self.lifecycle.state();
        self.check(&state)?;
        Ok(publish())
    }

    fn check(&self, state: &State) -> Result<(), &'static str> {
        if state.closing || state.generation != self.generation {
            Err(CLOSING)
        } else {
            Ok(())
        }
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut state = self.lifecycle.state();
        state.workers -= 1;
        if state.workers == 0 {
            self.lifecycle.drained.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::thread;

    #[test]
    fn two_dispatch_requests_do_not_overlap() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        let first = lifecycle.admit().unwrap();
        let second = lifecycle.admit().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let first_events = events.clone();
        let second_events = events.clone();
        let (entered, entered_rx) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (queued, queued_rx) = mpsc::channel();
        let first_worker = thread::spawn(move || {
            first.dispatch(|| {
                first_events.lock().unwrap().push("first-start");
                entered.send(()).unwrap();
                released.recv().unwrap();
                first_events.lock().unwrap().push("first-end");
            })
        });
        entered_rx.recv().unwrap();
        let protected = lifecycle.dispatch.try_lock().is_err();
        let second_worker = thread::spawn(move || {
            queued.send(()).unwrap();
            second.dispatch(|| second_events.lock().unwrap().push("second"))
        });
        queued_rx.recv().unwrap();
        release.send(()).unwrap();
        first_worker.join().unwrap().unwrap();
        second_worker.join().unwrap().unwrap();
        assert!(protected, "active dispatch did not own the shared serialization lock");
        assert_eq!(*events.lock().unwrap(), ["first-start", "first-end", "second"]);
    }

    #[test]
    fn dispatch_waiter_rechecks_close_before_executing() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        let first = lifecycle.admit().unwrap();
        let second = lifecycle.admit().unwrap();
        let (entered, entered_rx) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (queued, queued_rx) = mpsc::channel();
        let executed = Arc::new(AtomicBool::new(false));
        let second_executed = executed.clone();
        let first_worker = thread::spawn(move || {
            first.dispatch(|| {
                entered.send(()).unwrap();
                released.recv().unwrap();
            })
        });
        entered_rx.recv().unwrap();
        let second_worker = thread::spawn(move || {
            queued.send(()).unwrap();
            second.dispatch(|| second_executed.store(true, Ordering::SeqCst))
        });
        queued_rx.recv().unwrap();
        assert!(lifecycle.begin_close());
        release.send(()).unwrap();
        first_worker.join().unwrap().unwrap();
        assert_eq!(second_worker.join().unwrap(), Err(CLOSING));
        assert!(!executed.load(Ordering::SeqCst));
        lifecycle.wait_for_workers();
    }

    #[test]
    fn close_during_bootstrap_prevents_late_publication() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        let permit = lifecycle.admit().unwrap();
        let (started, start) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let published = Arc::new(AtomicBool::new(false));
        let published_worker = published.clone();
        let worker = thread::spawn(move || {
            permit.ensure_open().unwrap();
            started.send(()).unwrap();
            resumed.recv().unwrap();
            permit.publish(|| published_worker.store(true, Ordering::SeqCst))
        });
        start.recv().unwrap();
        assert!(lifecycle.begin_close());
        resume.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), Err(CLOSING));
        assert!(!published.load(Ordering::SeqCst));
        lifecycle.wait_for_workers();
    }

    #[test]
    fn queued_call_cannot_dispatch_after_close_and_new_admission_is_rejected() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        let queued = lifecycle.admit().unwrap();
        assert!(lifecycle.begin_close());
        assert!(!lifecycle.begin_close());
        assert_eq!(queued.ensure_open(), Err(CLOSING));
        assert!(lifecycle.admit().is_err());
        drop(queued);
        lifecycle.wait_for_workers();
    }

    #[test]
    fn cleanup_failure_keeps_admission_closed_and_allows_explicit_retry() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        assert!(lifecycle.begin_close());
        lifecycle.cleanup_failed();
        assert!(!lifecycle.cleanup_complete());
        assert!(lifecycle.admit().is_err());
        assert!(lifecycle.begin_close());
        assert!(!lifecycle.begin_close());
        lifecycle.complete_cleanup();
        assert!(!lifecycle.begin_close());
    }

    #[test]
    fn cleanup_waits_for_active_worker_and_runs_on_cleanup_thread() {
        let lifecycle = Arc::new(DesktopLifecycle::default());
        let permit = lifecycle.admit().unwrap();
        let (active, active_rx) = mpsc::channel();
        let (finish, finish_rx) = mpsc::channel();
        let (cleaned, cleaned_rx) = mpsc::channel();
        let caller = thread::current().id();
        let worker = thread::spawn(move || {
            permit.ensure_open().unwrap();
            active.send(()).unwrap();
            finish_rx.recv().unwrap();
            drop(permit);
        });
        active_rx.recv().unwrap();
        lifecycle.begin_close();
        let closing = lifecycle.clone();
        let cleanup = thread::spawn(move || {
            closing.wait_for_workers();
            cleaned.send(thread::current().id()).unwrap();
            closing.complete_cleanup();
        });
        assert!(!lifecycle.cleanup_complete());
        assert!(cleaned_rx.try_recv().is_err());
        finish.send(()).unwrap();
        assert_ne!(cleaned_rx.recv().unwrap(), caller);
        worker.join().unwrap();
        cleanup.join().unwrap();
        assert!(lifecycle.cleanup_complete());
    }
}
