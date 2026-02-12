//! In-memory session store with TTL-based expiration.
//!
//! Uses [`DashMap`] for concurrent access and a background task for
//! periodic eviction of expired sessions.

use std::time::{Duration, Instant};

use dashmap::mapref::one::RefMut;
use dashmap::DashMap;
use uuid::Uuid;

use security_compass_orchestrator::Session;

/// A stored session with its last-accessed timestamp.
pub struct SessionEntry {
    /// The orchestrator session.
    pub session: Session,
    /// When this entry was last accessed (for TTL checks).
    pub last_accessed: Instant,
}

/// Thread-safe in-memory session store with TTL expiration.
///
/// Sessions are indexed by UUID and automatically expire after the
/// configured TTL. The [`evict_expired`](SessionStore::evict_expired)
/// method should be called periodically from a background task.
pub struct SessionStore {
    /// Concurrent hash map of active sessions.
    sessions: DashMap<Uuid, SessionEntry>,
    /// Time-to-live for each session entry.
    ttl: Duration,
}

impl SessionStore {
    /// Creates a new empty session store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            ttl,
        }
    }

    /// Retrieves a mutable reference to a session by ID.
    ///
    /// Returns `None` if the session does not exist or has expired.
    /// If the session exists and is still valid, its `last_accessed`
    /// timestamp is refreshed.
    pub fn get_mut(&self, id: &Uuid) -> Option<RefMut<'_, Uuid, SessionEntry>> {
        // Check if the session exists.
        let entry = self.sessions.get_mut(id);
        match entry {
            Some(mut e) => {
                // Check TTL expiration.
                if e.last_accessed.elapsed() > self.ttl {
                    // Drop the reference before removing to avoid deadlock.
                    drop(e);
                    self.sessions.remove(id);
                    None
                } else {
                    // Refresh the last-accessed timestamp.
                    e.last_accessed = Instant::now();
                    Some(e)
                }
            }
            None => None,
        }
    }

    /// Inserts a new session into the store and returns its UUID.
    pub fn insert(&self, session: Session) -> Uuid {
        let id = session.id();
        self.sessions.insert(
            id,
            SessionEntry {
                session,
                last_accessed: Instant::now(),
            },
        );
        id
    }

    /// Removes all sessions that have exceeded their TTL.
    ///
    /// This should be called periodically from a background task.
    pub fn evict_expired(&self) {
        let ttl = self.ttl;
        self.sessions
            .retain(|_, entry| entry.last_accessed.elapsed() <= ttl);
    }

    /// Returns the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns `true` if the store has no active sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
