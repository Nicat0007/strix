"""Targeted web-cache-poisoning executor driven by a selected hypothesis (BLACKBOX
improvement #16). Explicitly invoked per hypothesis: injects unkeyed headers
(X-Forwarded-Host and friends) carrying a unique marker, checks reflection, then
sends a CLEAN request to see if the poisoned response was cached and served back.
Detection only; a confirmed cache-served poison is needs_validation, never
confirmed-outright."""
