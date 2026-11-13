"""Targeted race-condition executor driven by a selected hypothesis (BLACKBOX
improvement #11). Explicitly invoked per hypothesis: fires a bounded number of
copies of ONE stored request as concurrently as the transport allows and reports
how many succeeded — the signal for a TOCTOU / limit-overrun race (double-spend,
one-time-coupon reuse, balance/quantity overrun). Detection only; a positive is
needs_validation, never confirmed."""
