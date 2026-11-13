"""Targeted server-side template injection (SSTI) executor driven by a selected
hypothesis from the worklist (BLACKBOX improvement #9). Explicitly invoked per
hypothesis — injects distinct arithmetic polyglots for several template engines,
replays once, and distinguishes real evaluation (the product appears, the literal
expression does not) from mere reflection. Detection only; a positive is
needs_validation, never confirmed."""
