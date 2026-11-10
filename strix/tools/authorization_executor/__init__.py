"""Evidence-backed authorization replay executor (BLACKBOX improvement #5).

Turns an IDOR/BOLA/BFLA hypothesis into a bounded, actor-aware replay comparison
with real ownership/privilege evidence — explicitly invoked per hypothesis, not
an automatic scanner.
"""
