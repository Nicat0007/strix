"""Targeted open-redirect test executor driven by a selected hypothesis from the
worklist (BLACKBOX improvement #8). Explicitly invoked per hypothesis — injects a
uniquely-marked off-origin redirect target at one location, replays once, and
classifies the response's redirect behaviour (Location / meta-refresh / JS).
Detection only; a positive is needs_validation, never confirmed."""
