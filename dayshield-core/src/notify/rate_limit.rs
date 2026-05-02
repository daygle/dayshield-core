//! Token-bucket rate limiter for outgoing notification emails.

use std::time::Instant;

/// A simple token-bucket rate limiter.
///
/// Tokens are refilled to `max_per_minute` every 60 seconds.  Each
/// call to [`RateLimiter::check`] attempts to consume one token; it
/// returns `true` when a token was available (call allowed) or `false`
/// when the bucket is empty (call should be suppressed).
pub struct RateLimiter {
    /// Maximum number of emails allowed per 60-second window.
    pub max_per_minute: u32,
    /// Current number of available tokens.
    pub tokens: u32,
    /// Timestamp of the last token refill.
    pub last_refill: Instant,
}

impl RateLimiter {
    /// Create a new [`RateLimiter`] starting with a full bucket.
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            tokens: max_per_minute,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token.
    ///
    /// Refills the bucket first if 60 seconds have elapsed since the last
    /// refill.  Returns `true` if a token was available (proceed), `false`
    /// if the bucket is empty (rate-limited).
    pub fn check(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_refill).as_secs() >= 60 {
            self.tokens = self.max_per_minute;
            self.last_refill = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.check());
        assert!(rl.check());
        assert!(rl.check());
        // Bucket should now be empty.
        assert!(!rl.check());
    }

    #[test]
    fn zero_max_always_blocks() {
        let mut rl = RateLimiter::new(0);
        // Starts with 0 tokens; check should block without panicking.
        assert!(!rl.check());
    }
}
