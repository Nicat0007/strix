---
name: trust-boundary-mapping
description: Builds trust_boundaries.md — the role hierarchy and object-ownership graph derived from provisioned accounts and (when available) an observed actor×action matrix — purely descriptive, no vulnerability judgment; feeds Layer B's Actor Replay pair selection
---

# Trust Boundary Mapping

`account_provisioning.md` produces authenticated actors; `analysis/parameter_mutation_testing.md`'s "Actor Replay (Differential Authorization)" section consumes an arbitrary pair of them. In between, a testing agent currently has to decide by hand which two actors and which object are worth pairing up — this skill formalizes that decision into one artifact, `/workspace/recon/trust_boundaries.md`, built once and read by every subsequent hunting agent instead of re-derived per candidate.

**This is descriptive extraction only, the same discipline as `custom/source_aware_sast.md`'s Attack Surface Compiler — it makes no vulnerability judgment and generates no hypotheses, scores, or predictions.** It states who exists, what they own, and which roles have *evidenced* rank versus none at all. Whether a given actor pair actually leaks is still decided entirely by Layer B's `signal_class`/`owner_scope_verdict` computation and `counterevidence.md`'s closure discipline — this skill only decides which pair is worth asking that question about first.

Run this once, after `account_provisioning.md` has provisioned accounts (2+ for it to produce anything useful) and — when `broken_function_level_authorization.md`'s actor×action sweep has also run — after that matrix exists. It does not block on the matrix: hierarchy evidence is optional, and its absence is reported honestly rather than guessed at.

## Prerequisites and What Each One Buys

- **`/workspace/recon/auth_accounts.jsonl`** (required — see `account_provisioning.md`'s "Saving Tokens for Reuse"). The flat `auth_tokens.txt` form has none of the structure this skill needs; if only that exists, this skill has nothing to build and says so rather than guessing at roles or ownership from token strings.
- **`/workspace/recon/actor_action_matrix.jsonl`** (optional — see `broken_function_level_authorization.md`'s Testing Methodology step 1). Without it, every role is reported as an unordered set — **never** inferred from role names. "org-creator" sounding senior to "invited-member" is not evidence; a role only outranks another once an actual action was tried under both and one succeeded where the other was denied.

## Building `trust_boundaries.md`

```bash
mkdir -p /workspace/recon
python3 - <<'PY'
import json
from collections import defaultdict
from pathlib import Path

recon = Path("/workspace/recon")
accounts_path = recon / "auth_accounts.jsonl"
matrix_path = recon / "actor_action_matrix.jsonl"


def normalize_type(t: str) -> str:
    t = t.strip().lower()
    return t[:-1] if t.endswith("s") and len(t) > 3 else t


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


actors = load_jsonl(accounts_path)
lines_out = ["# Trust Boundaries", ""]

if not actors:
    lines_out.append(
        "No `auth_accounts.jsonl` found (or it is empty) - trust boundaries require the "
        "structured account_provisioning.md output, not the flat `auth_tokens.txt` form. "
        "Nothing to build."
    )
else:
    lines_out.append("## Actors")
    lines_out.append("")
    for a in sorted(actors, key=lambda a: str(a.get("principal", ""))):
        owned = ", ".join(
            f"{o.get('type')}:{o.get('id')}"
            for o in a.get("owned_objects", [])
            if isinstance(o, dict)
        ) or "(none recorded)"
        lines_out.append(
            f"- {a.get('principal')} - role: {a.get('role')}, tenant: {a.get('tenant')}, "
            f"owned_objects: {owned}"
        )
    lines_out.append("")

    # ---- Role Relationships: derived ONLY from observed actor x action
    # results, never from role names. Four honest buckets, not two, so a
    # pair the evidence doesn't actually order never gets silently folded
    # into "peers" or a fabricated hierarchy.
    lines_out.append("## Role Relationships")
    lines_out.append("")
    matrix_rows = load_jsonl(matrix_path)
    roles = sorted({a.get("role", "") for a in actors if a.get("role")})

    role_action_result: dict[str, dict[str, str]] = defaultdict(dict)
    for row in matrix_rows:
        role, action, result = row.get("role"), row.get("action"), row.get("result")
        if role and action and result in ("allowed", "denied"):
            existing = role_action_result[role].get(action)
            role_action_result[role][action] = (
                "inconsistent" if existing and existing != result else result
            )

    edges: list[tuple[str, str, int]] = []
    if not matrix_rows or len(roles) < 2:
        lines_out.append(
            f"No hierarchy evidence available - {len(roles)} role(s) treated as an "
            f"unordered set: {roles}"
        )
    else:
        peers: list[tuple[str, str]] = []
        divergent: list[tuple[str, str]] = []
        insufficient: list[tuple[str, str]] = []

        for i, ra in enumerate(roles):
            for rb in roles[i + 1 :]:
                common = {
                    act
                    for act in set(role_action_result[ra]) & set(role_action_result[rb])
                    if role_action_result[ra][act] != "inconsistent"
                    and role_action_result[rb][act] != "inconsistent"
                }
                if not common:
                    insufficient.append((ra, rb))
                    continue
                a_allowed = {act for act in common if role_action_result[ra][act] == "allowed"}
                b_allowed = {act for act in common if role_action_result[rb][act] == "allowed"}
                if a_allowed == b_allowed:
                    peers.append((ra, rb))
                elif a_allowed > b_allowed:
                    edges.append((ra, rb, len(common)))
                elif b_allowed > a_allowed:
                    edges.append((rb, ra, len(common)))
                else:
                    divergent.append((ra, rb))

        for hi, lo, n in edges:
            lines_out.append(
                f"- {hi} is a superset of {lo}: confirmed via actor x action matrix over {n} "
                f"commonly-tested action(s) - {hi} succeeded somewhere {lo} was denied, "
                f"{lo} succeeded nowhere {hi} was denied"
            )
        for ra, rb in peers:
            lines_out.append(f"- {ra} and {rb}: peers (identical results on every commonly-tested action)")
        for ra, rb in divergent:
            lines_out.append(
                f"- {ra} and {rb}: divergent evidence - each succeeded where the other was "
                "denied on at least one tested action; not a hierarchy, not peers, needs a closer read"
            )
        for ra, rb in insufficient:
            lines_out.append(f"- {ra} and {rb}: insufficient data - no action tested against both roles yet")
    lines_out.append("")

    # ---- Object Type -> Owner Map ----
    lines_out.append("## Object Type -> Owner Map")
    lines_out.append("")
    object_owners: dict[str, list[dict]] = defaultdict(list)
    for a in actors:
        for obj in a.get("owned_objects", []):
            if not isinstance(obj, dict) or "type" not in obj or "id" not in obj:
                continue
            object_owners[normalize_type(str(obj["type"]))].append(
                {"principal": a.get("principal"), "role": a.get("role"), "object_id": obj["id"]}
            )

    lower_role_of: dict[str, set[str]] = defaultdict(set)
    for hi, lo, _n in edges:
        lower_role_of[hi].add(lo)

    actor_by_role: dict[str, list[str]] = defaultdict(list)
    for a in actors:
        if a.get("role"):
            actor_by_role[a["role"]].append(a.get("principal"))

    for obj_type, owners in sorted(object_owners.items()):
        by_role: dict[str, list[dict]] = defaultdict(list)
        for o in owners:
            by_role[o["role"]].append(o)
        peer_roles = [r for r, members in by_role.items() if len(members) >= 2]
        other_roles = [r for r in by_role if r not in peer_roles]
        lines_out.append(
            f"- {obj_type}: owners = {[o['principal'] for o in owners]}; "
            f"same-role peer group(s) = {peer_roles or 'none'}; "
            f"different-role owner(s) = {other_roles or 'none'}"
        )
    lines_out.append("")

    # ---- Test Pairs: horizontal from same-role co-ownership, vertical
    # ONLY from a confirmed superset edge above - direction matters, the
    # lower-privileged actor is always the one replaying.
    lines_out.append("## Test Pairs")
    lines_out.append("")
    test_pairs: list[str] = []
    for obj_type, owners in sorted(object_owners.items()):
        by_role = defaultdict(list)
        for o in owners:
            by_role[o["role"]].append(o)
        for role, members in by_role.items():
            if len(members) >= 2:
                test_pairs.append(
                    f"- horizontal (BOLA) on '{obj_type}': {members[0]['principal']} vs "
                    f"{members[1]['principal']} (both role {role}; {members[0]['principal']} "
                    f"owns {members[0]['object_id']})"
                )
        for o in owners:
            for lo_role in lower_role_of.get(o["role"], ()):
                for lo_principal in actor_by_role.get(lo_role, ()):
                    test_pairs.append(
                        f"- vertical (BFLA) on '{obj_type}': lower-privileged {lo_principal} "
                        f"(role {lo_role}) replays {o['principal']}'s (role {o['role']}) "
                        f"request/object {o['object_id']}"
                    )
    lines_out.extend(
        test_pairs
        or [
            "(no test pairs derivable yet - fewer than 2 accounts share an object type, or "
            "no hierarchy evidence exists for a vertical pair)"
        ]
    )

(recon / "trust_boundaries.md").write_text("\n".join(lines_out) + "\n", encoding="utf-8")
print(f"trust_boundaries.md written -> {recon / 'trust_boundaries.md'}")
PY
```

Re-run this whenever `auth_accounts.jsonl` or `actor_action_matrix.jsonl` gains new rows (a third account provisioned mid-scan, more BFLA matrix cells filled in) — it's a full rebuild each time, not an incremental append, and cheap enough that re-running costs nothing.

## Reading the Output

- **Actors** — one row per provisioned account: principal, role (as captured, verbatim — never reworded or ranked here), tenant, and what it owns.
- **Role Relationships** — four honest outcomes, never forced into a single ordering: a confirmed superset edge (real evidence, cited to the matrix), peers (tied on everything tested), divergent (each beats the other somewhere — genuinely incomparable, not a data gap), or insufficient data (nothing tested against both roles yet). Absent any matrix at all, every role is an explicit unordered set.
- **Object Type → Owner Map** — per object type, who owns an instance, which owners share a role (the horizontal/BOLA candidate pool), and which owners differ by role (the vertical/BFLA candidate pool).
- **Test Pairs** — the actual worklist: horizontal pairs from same-role co-ownership, vertical pairs *only* where a real superset edge justifies one, always phrased as the lower-privileged actor replaying the higher one's request — the interesting direction, since the reverse (a senior role reaching a junior's object) is frequently by design, not a bug.

## Feeding Actor Replay's Pair Selection

`analysis/parameter_mutation_testing.md`'s "Actor Replay (Differential Authorization)" subsection already mandates one always-run representative-member replay per family. When `trust_boundaries.md` exists, that section reads this file's Test Pairs to choose *which* actors to use for that replay — a same-role pair for an `item`/`collection` kind family, a vertical pair for an `action` kind family — instead of an arbitrary two accounts. This does not add a tier or change the cost bound (still one representative per family); it only improves which pair fills that slot. Piece 3's behavior is fully unchanged when this file doesn't exist yet.

## What This Does Not Do

- No prediction of which pair is "likely" to leak — every pair in Test Pairs is equally a candidate; ranking them is the calling skill's job via `signal_class`/`owner_scope_verdict`, not this one's.
- No numeric confidence, no severity, no invented role order. A role pair with no matrix evidence stays an honest "insufficient data," not a guess rounded up to "probably peers" or "probably ordered."
- No modification of `auth_accounts.jsonl` or `actor_action_matrix.jsonl` — read-only relative to both.

## Cross-References

- `reconnaissance/account_provisioning.md` — the source of `auth_accounts.jsonl`; see its "Saving Tokens for Reuse" for the `owned_objects` field this skill requires.
- `vulnerabilities/broken_function_level_authorization.md` — the source of `actor_action_matrix.jsonl`, optional but the only source of real hierarchy evidence.
- `analysis/parameter_mutation_testing.md` — the consumer, via "Actor Replay (Differential Authorization)".
- `vulnerabilities/idor.md` — the horizontal/BOLA reader of Test Pairs.
