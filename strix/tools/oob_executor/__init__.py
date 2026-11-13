"""Targeted out-of-band (OAST) interaction executor driven by a selected
hypothesis from the worklist (BLACKBOX improvement #7). Explicitly invoked per
hypothesis to confirm BLIND / out-of-band egress (blind SSRF, XXE, RCE, OOB
SQLi, SSTI, deserialization) via a uniquely-correlated interactsh callback — not
an automatic scanner."""
