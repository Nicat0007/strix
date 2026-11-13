"""Targeted rate-limit / anti-automation executor driven by a selected hypothesis
(BLACKBOX improvement #10). Explicitly invoked per hypothesis: replays ONE stored
request a bounded number of times (identical — a rate-limit PRESENCE test, not a
brute-force of different passwords/OTPs) to see if and when throttling fires, then
tests an IP-rotation-header bypass. Detection only; a positive is needs_validation,
never confirmed, and the agent escalates to an actual (authorized) brute-force
separately."""
