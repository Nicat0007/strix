"""Targeted GraphQL exposure executor driven by a selected hypothesis (BLACKBOX
improvement #15). Explicitly invoked per hypothesis: sends a small set of bounded
probes (introspection, field-suggestion leakage, query batching) against a
captured GraphQL request and reports which are enabled. Detection only; a positive
is needs_validation, never confirmed."""
