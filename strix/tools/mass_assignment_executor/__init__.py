"""Targeted mass-assignment / auto-binding executor driven by a selected
hypothesis (BLACKBOX improvement #14). Explicitly invoked per hypothesis: injects
privileged field names the client shouldn't control into a captured create/update
request, replays once, and checks (in the response and an optional re-read)
whether any injected field was bound. Detection only; a positive is
needs_validation, never confirmed."""
