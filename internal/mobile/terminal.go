package mobile

// Interaction with device terminal/console
// TODO(mobile-term-shell-abstraction): Provide platform-specific shell execution abstraction with allowlist.
// TODO(mobile-term-security): Enforce command allowlist to prevent arbitrary execution from UI.
// TODO(mobile-term-logging): Stream command output to structured log channel with truncation.
// TODO(mobile-term-audit): Emit AUDIT events for privileged console actions.
// TODO(mobile-term-timeout): Add execution timeout + cancellation context.
// TODO(mobile-term-sandbox): Evaluate sandbox restrictions (no network / filesystem writes) if feasible.
// TODO(mobile-term-rate-limit): Rate limit commands per minute to mitigate abuse.
// TODO(mobile-term-metrics): Capture execution latency & success/failure counts.
