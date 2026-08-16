//! The timer service: retransmissions, recv timeouts, pauses, timewait.
//!
//! Split for testability: [`TimerQueue`] is a pure data structure
//! (arm/cancel/`pop_due`) unit-tested without sleeping, and [`TimerService`]
//! is a thin thread driver that waits on a condvar until the next deadline
//! and delivers fired events into an `mpsc::Sender` — the engine's single
//! event loop selects nothing; everything funnels into one channel
//! (docs/ARCHITECTURE.md §2, std-only note).

use std::collections::BinaryHeap;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Handle used to cancel an armed timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(u64);

struct Entry<E> {
    deadline: Instant,
    id: TimerId,
    event: E,
}

// BinaryHeap is a max-heap; invert the ordering to pop earliest first.
impl<E> PartialEq for Entry<E> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}
impl<E> Eq for Entry<E> {}
impl<E> PartialOrd for Entry<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<E> Ord for Entry<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.id.0.cmp(&self.id.0))
    }
}

/// Pure timer queue: a min-heap of deadlines with tombstone cancellation.
#[derive(Default)]
pub struct TimerQueue<E> {
    heap: BinaryHeap<Entry<E>>,
    cancelled: std::collections::HashSet<TimerId>,
    next_id: u64,
}

impl<E> TimerQueue<E> {
    /// Empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            cancelled: std::collections::HashSet::new(),
            next_id: 0,
        }
    }

    /// Arm a timer firing `event` at `deadline`.
    pub fn arm(&mut self, deadline: Instant, event: E) -> TimerId {
        self.next_id += 1;
        let id = TimerId(self.next_id);
        self.heap.push(Entry {
            deadline,
            id,
            event,
        });
        id
    }

    /// Cancel a previously armed timer. Cancelling twice (or after firing)
    /// is a no-op.
    pub fn cancel(&mut self, id: TimerId) {
        if self.heap.is_empty() {
            // Nothing pending: a tombstone would leak forever.
            self.cancelled.clear();
        } else {
            self.cancelled.insert(id);
        }
    }

    /// Pop every timer due at `now`, skipping cancelled ones.
    pub fn pop_due(&mut self, now: Instant) -> Vec<E> {
        let mut fired = Vec::new();
        while let Some(top) = self.heap.peek() {
            if top.deadline > now {
                break;
            }
            let Some(entry) = self.heap.pop() else { break };
            if !self.cancelled.remove(&entry.id) {
                fired.push(entry.event);
            }
        }
        fired
    }

    /// Deadline of the next live timer, if any.
    #[must_use]
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(top) = self.heap.peek() {
            if self.cancelled.contains(&top.id) {
                let Some(entry) = self.heap.pop() else { break };
                self.cancelled.remove(&entry.id);
                continue;
            }
            return Some(top.deadline);
        }
        None
    }

    /// Number of live timers (cancelled-but-unpopped excluded).
    ///
    /// Saturating: a tombstone for an already-fired timer must not underflow.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len().saturating_sub(self.cancelled.len())
    }

    /// True when no live timers remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct Shared<E> {
    queue: Mutex<QueueState<E>>,
    wake: Condvar,
}

struct QueueState<E> {
    queue: TimerQueue<E>,
    shutdown: bool,
}

/// Threaded driver delivering fired timer events into an mpsc channel.
pub struct TimerService<E: Send + 'static> {
    shared: Arc<Shared<E>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl<E: Send + 'static> TimerService<E> {
    /// Start the timer thread; fired events go to `sink`.
    #[must_use]
    pub fn start(sink: Sender<E>) -> Self {
        let shared = Arc::new(Shared {
            queue: Mutex::new(QueueState {
                queue: TimerQueue::new(),
                shutdown: false,
            }),
            wake: Condvar::new(),
        });
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("sipr-timers".into())
            .spawn(move || run(&thread_shared, &sink))
            .ok();
        Self { shared, thread }
    }

    /// Arm a timer firing `event` after `delay`.
    pub fn arm(&self, delay: Duration, event: E) -> TimerId {
        self.arm_at(Instant::now() + delay, event)
    }

    /// Arm a timer firing `event` at `deadline`.
    pub fn arm_at(&self, deadline: Instant, event: E) -> TimerId {
        let mut state = lock(&self.shared.queue);
        let id = state.queue.arm(deadline, event);
        drop(state);
        self.shared.wake.notify_one();
        id
    }

    /// Cancel an armed timer (no-op if already fired).
    pub fn cancel(&self, id: TimerId) {
        lock(&self.shared.queue).queue.cancel(id);
        self.shared.wake.notify_one();
    }
}

impl<E: Send + 'static> Drop for TimerService<E> {
    fn drop(&mut self) {
        lock(&self.shared.queue).shutdown = true;
        self.shared.wake.notify_one();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Mutex lock that survives a poisoned peer thread (a panicking test thread
/// must not cascade).
fn lock<'a, E>(m: &'a Mutex<QueueState<E>>) -> std::sync::MutexGuard<'a, QueueState<E>> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn run<E: Send>(shared: &Shared<E>, sink: &Sender<E>) {
    let mut state = lock(&shared.queue);
    loop {
        if state.shutdown {
            return;
        }
        let now = Instant::now();
        for event in state.queue.pop_due(now) {
            if sink.send(event).is_err() {
                return; // receiver gone: engine shut down
            }
        }
        state = match state.queue.next_deadline() {
            Some(deadline) => {
                let timeout = deadline.saturating_duration_since(now);
                match shared.wake.wait_timeout(state, timeout) {
                    Ok((g, _)) => g,
                    Err(poisoned) => poisoned.into_inner().0,
                }
            }
            None => match shared.wake.wait(state) {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn pops_in_deadline_order() {
        let base = t0();
        let mut q = TimerQueue::new();
        q.arm(base + Duration::from_millis(30), "c");
        q.arm(base + Duration::from_millis(10), "a");
        q.arm(base + Duration::from_millis(20), "b");
        assert_eq!(
            q.pop_due(base + Duration::from_millis(5)),
            Vec::<&str>::new()
        );
        assert_eq!(q.pop_due(base + Duration::from_millis(25)), vec!["a", "b"]);
        assert_eq!(q.pop_due(base + Duration::from_millis(35)), vec!["c"]);
        assert!(q.is_empty());
    }

    #[test]
    fn cancel_suppresses_delivery() {
        let base = t0();
        let mut q = TimerQueue::new();
        let keep = q.arm(base + Duration::from_millis(10), "keep");
        let drop_ = q.arm(base + Duration::from_millis(10), "drop");
        q.cancel(drop_);
        assert_eq!(q.len(), 1);
        let fired = q.pop_due(base + Duration::from_millis(20));
        assert_eq!(fired, vec!["keep"]);
        q.cancel(keep); // cancelling after fire is a no-op
        assert!(q.is_empty());
    }

    #[test]
    fn next_deadline_skips_cancelled() {
        let base = t0();
        let mut q = TimerQueue::new();
        let early = q.arm(base + Duration::from_millis(10), 1);
        q.arm(base + Duration::from_millis(50), 2);
        q.cancel(early);
        assert_eq!(q.next_deadline(), Some(base + Duration::from_millis(50)));
    }

    #[test]
    fn same_deadline_preserves_arm_order() {
        let base = t0();
        let mut q = TimerQueue::new();
        let d = base + Duration::from_millis(10);
        q.arm(d, 1);
        q.arm(d, 2);
        q.arm(d, 3);
        assert_eq!(q.pop_due(d), vec![1, 2, 3]);
    }

    #[test]
    fn service_delivers_and_cancels() {
        let (tx, rx) = mpsc::channel();
        let svc = TimerService::start(tx);
        let cancelled = svc.arm(Duration::from_millis(30), "cancelled");
        svc.arm(Duration::from_millis(10), "fired");
        svc.cancel(cancelled);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).ok(), Some("fired"));
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "cancelled timer must not fire"
        );
        drop(svc);
    }
}
