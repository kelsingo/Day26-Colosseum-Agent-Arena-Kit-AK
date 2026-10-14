"""agent/gateway.py — YOUR control plane. CONTRACTS.md section 4, exactly.

READ agent/README.md FIRST — it maps all five files in this directory to what
each is scored on. This file is the one CONTRACTS.md calls "the trusted
envelope's untrusted half": every single MCP / A2A / DISCOVER command your
agent's model wants to make passes through `Gateway.decide` before it is
allowed to happen.

WHY THERE IS NO `execute()` METHOD ON `GatewayContext` (read this before you
go looking for one — there isn't one, and that is not an oversight)
----------------------------------------------------------------------------
CONTRACTS.md section 4's trusted envelope, reproduced here because it is the
one diagram worth memorising:

    [ trusted ]   loop emits a raw action line
         v
    [ trusted ]   INTERCEPT + CANONICALISE -> Command        (kit/loop/agent.py)
         v
    [ UNTRUSTED ] Gateway.decide(cmd) -> Decision             <- THIS FILE
         v
    [ trusted ]   ENFORCE: honour the Decision, meter it,
                  apply the active mutation, execute the
                  ToolCall or refuse it                       (the arena)
         v
    [ trusted ]   RECORD the authoritative L1 event, then
                  RENDER the Observation                      (the arena)
         v
    [ trusted ]   the model sees the Observation

`decide()` returns a *decision*, never a *result*. You cannot reach a tool
server, a file, a socket, or a clock from in here — there is nothing to
call. Two things follow from that, and both matter more than they look:

  1. YOUR TRACE CANNOT BE FORGED. Every `command` / `decision` / `enforced`
     / `tool_call` / `tool_result` L1 event (CONTRACTS.md 5.2) is written by
     the arena, from what the arena itself actually did — never from
     anything you claimed happened. A student gateway that wanted to lie
     about having blocked an attack ("I totally denied that, trust me")
     simply has no channel to lie through: the only thing you ever hand
     back is this one small `Decision` value, and the arena is the one that
     turns it into history.
  2. NOBODY CAN ACCUSE YOU OF A CALL YOU DID NOT AUTHORISE, either. Because
     `decide()` is the ONLY door a command can walk through on its way to
     actually running, a prosecutor's `enforcement_failure` claim against
     you has exactly one thing to point at: the `Decision` you returned for
     that specific `cmd_id`. There is no ambiguity about "maybe the loop
     called the tool directly" — CONTRACTS.md 4.2 removed that path on
     purpose, and kit/loop/agent.py's own module docstring names the same
     invariant from the other side (the loop never imports this module,
     never sees a `Decision`, never executes anything itself).

The cost of that guarantee is that this file is PURE: synchronous, no I/O,
no threads, no `sleep`, 250 ms wall-clock deadline (RULES.md section 3).
Raising anything, returning something that is not a valid `Decision`, or
missing the deadline is treated by the arena as a DENIED command PLUS a 2
credit penalty PLUS an `integrity` event that hands the prosecutor a free
`enforcement_failure` — CONTRACTS.md 4.1's charging table, reproduced in
agent/README.md's own table. Getting this file to just plainly return valid
`Decision` values, every time, is worth more than getting it clever.

THE IMPLEMENTED POLICY
----------------------------------------------------------------------------
`decide()` is structured as four named jobs — ROUTE, ADMIT, AUTHORIZE,
BUDGET.  It routes replicas through headers, rejects calls that are known
to be invalid before spending, derives authority from `ctx.act` and
`ctx.scopes`, and narrows objectively expensive wildcard/catalog masks.
The policy uses `agent/strategy.py` for replica/successor/catalog decisions
and the kit's executable specs for tool metadata and cost estimates.

ONE THING WORTH INTERNALISING BEFORE YOU WRITE YOUR FIRST REAL CHECK:
`verdict="deny"` costs the CALLER (your own team) **zero credits** —
CONTRACTS.md 4.1's charging table has exactly one $0 row, and it is this
one. Refusing to make a call you cannot justify is FREE. That makes
abstention a real strategy, not a luxury you can't afford: a `deny` you can
defend beats a `forward` you can't, every time a prosecutor is watching.

Stdlib only. No network, no randomness, no wall-clock reads, no sleeping —
none of that would even survive the kernel sandbox (CONTRACTS.md 12), but
the point is this file has no reason to want any of it in the first place.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Protocol, runtime_checkable

# kit.mcp.types is a collaborator's file (workspace hard rule 2: import it,
# degrade gracefully). It is present as of this writing and is core, stable
# infrastructure (CONTRACTS.md 3.1) — but this module must still not fail to
# IMPORT if a concurrent edit ever breaks it transiently. When it is
# unavailable, `Decision.call` type-checking is skipped (not enforced), and
# `Gateway.decide` falls back to a minimal local dict-shaped stand-in so the
# rest of this file — everything that does not need a *real* ToolCall — still
# runs.
try:
    from kit.mcp.types import ToolCall
    _TOOLCALL_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    ToolCall = Any  # type: ignore[assignment, misc]
    _TOOLCALL_AVAILABLE = False

# kit.loop.agent is also a collaborator's file, used only by this module's
# own __main__ demo (to build real Commands the same way the arena's trusted
# canonicaliser would) — never by decide() itself, which never touches the
# loop. Degraded the same way.
try:
    from kit.loop.agent import canonicalise_action as _canonicalise_action
except ImportError:  # pragma: no cover - collaborator file
    _canonicalise_action = None

from agent.telemetry import RecordingGatewayContext, Telemetry
from agent.strategy import is_catalog_trap, pick_replica, successor_of

try:
    from kit.mcp.a2a import verify_delegation
except ImportError:  # pragma: no cover - collaborator file
    verify_delegation = None  # type: ignore[assignment]

try:
    from kit.mcp.specs import A2A_PEERS, TOOL_SPECS, cost as _spec_cost
except ImportError:  # pragma: no cover - collaborator file
    A2A_PEERS = frozenset({"curriculum-analyst", "citation-checker", "roster"})
    TOOL_SPECS = {}

    def _spec_cost(server: str, tool: str, fields: tuple[str, ...] = (), n_rows: int = 1) -> int:
        return 5

__all__ = [
    "COMMAND_KINDS",
    "DECISION_VERDICTS",
    "Command",
    "Decision",
    "GatewayContext",
    "Gateway",
]

# CONTRACTS.md 4.1: `Command.kind` — "mcp" | "a2a" | "discover". An "answer"
# action is NEVER a Command (kit/loop/agent.py's own module docstring: "an
# answer is not a tool call routed to a server, so it never becomes a
# Command at all") — it is handled entirely by the loop/arena and never
# reaches `Gateway.decide`.
COMMAND_KINDS: frozenset[str] = frozenset({"mcp", "a2a", "discover"})

# CONTRACTS.md 4.1: `Decision.verdict` — the closed three-member set.
DECISION_VERDICTS: frozenset[str] = frozenset({"forward", "deny", "rewrite"})

WRITE_TOOLS: frozenset[tuple[str, str]] = frozenset(
    {
        ("content", "flag_stale_slide"),
        ("content", "file_content_bug"),
        ("progress", "record_mastery"),
    }
)

WRITE_SCOPES: Mapping[tuple[str, str], str] = {
    ("content", "flag_stale_slide"): "wiki.write:content",
    ("content", "file_content_bug"): "wiki.write:content",
    ("progress", "record_mastery"): "wiki.write:progress",
}

# Empty masks use the tool's declared default.  These explicit masks are only
# for the two catalogue traps whose declared default is intentionally the full,
# expensive dump.
CATALOG_MASKS: Mapping[tuple[str, str], tuple[str, ...]] = {
    ("registry", "list_servers"): ("name",),
    ("glossary", "list_terms"): ("term",),
}

_INSTRUCTION_MARKERS: tuple[str, ...] = (
    "ignore all previous",
    "ignore previous instruction",
    "system override",
    "bỏ qua mọi hướng dẫn",
    "you must now",
    "also record this for",
    "reveal the act",
)


@dataclass(frozen=True, slots=True)
class Command:
    """CONTRACTS.md 4.1, field for field — "canonicalised by the arena
    BEFORE the student sees it". You never build one of these from your own
    agent's raw text; the arena's canonicaliser (kit/loop/agent.py's
    `canonicalise_action`, run inside the trusted envelope) already did that
    work and minted `cmd_id` by the time `decide()` sees it. The
    `from_action_dict` classmethod below exists only so this file's own demo
    (and your local tests, if you write any) can build a realistic `Command`
    without duplicating the arena's canonicalisation logic."""

    cmd_id: str
    kind: str  # "mcp" | "a2a" | "discover" — see COMMAND_KINDS
    raw: str
    server: str
    tool: str
    args: dict
    fields: tuple[str, ...]
    headers: dict
    lease_id: str | None
    call_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.cmd_id, str) or not self.cmd_id:
            raise ValueError(f"Command.cmd_id must be a non-empty str, got {self.cmd_id!r}")
        if self.kind not in COMMAND_KINDS:
            raise ValueError(f"Command.kind must be one of {sorted(COMMAND_KINDS)}, got {self.kind!r}")
        if not isinstance(self.server, str) or not self.server:
            raise ValueError(f"Command.server must be a non-empty str, got {self.server!r}")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError(f"Command.tool must be a non-empty str, got {self.tool!r}")
        if not isinstance(self.args, dict):
            raise ValueError(f"Command.args must be a dict, got {type(self.args).__name__}")
        if not isinstance(self.headers, dict):
            raise ValueError(f"Command.headers must be a dict, got {type(self.headers).__name__}")
        if (
            not isinstance(self.call_index, int)
            or isinstance(self.call_index, bool)
            or self.call_index < 0
        ):
            raise ValueError(f"Command.call_index must be a non-negative int, got {self.call_index!r}")

    @classmethod
    def from_action_dict(cls, action: Mapping[str, Any], *, cmd_id: str) -> "Command":
        """Build a `Command` from the dict shape `kit.loop.agent.canonicalise_action`
        returns (`kind, raw, server, tool, args, fields, headers, lease_id,
        call_index` — everything except the arena-minted `cmd_id`, supplied
        here as a keyword). Raises `ValueError` if `action["kind"] ==
        "answer"` — an answer is never a Command (see the module docstring).
        This is a convenience for tests/demos, not something the real arena
        calls: the trusted envelope mints `cmd_id` itself and constructs the
        real `Command` on its own side of the boundary."""
        kind = action.get("kind")
        if kind == "answer":
            raise ValueError(
                "an 'answer' action never becomes a Command (kit/loop/agent.py: "
                "\"an answer is not a tool call routed to a server\") — do not "
                "route it through Gateway.decide at all"
            )
        return cls(
            cmd_id=cmd_id,
            kind=kind,
            raw=action["raw"],
            server=action["server"],
            tool=action["tool"],
            args=dict(action.get("args", {})),
            fields=tuple(action.get("fields", ())),
            headers=dict(action.get("headers", {})),
            lease_id=action.get("lease_id"),
            call_index=action.get("call_index", 0),
        )

    def to_dict(self) -> dict:
        return {
            "cmd_id": self.cmd_id,
            "kind": self.kind,
            "raw": self.raw,
            "server": self.server,
            "tool": self.tool,
            "args": dict(self.args),
            "fields": list(self.fields),
            "headers": dict(self.headers),
            "lease_id": self.lease_id,
            "call_index": self.call_index,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """CONTRACTS.md 4.1, field for field.

    Validated strictly (`__post_init__`) because a *structurally* invalid
    `Decision` is charged exactly like a raised exception — CONTRACTS.md
    4.1's charging table: "malformed Decision (schema-invalid) -> 2 cr
    penalty, command denied." Failing loudly HERE, in your own process
    during development, is strictly better than discovering it live in a
    duel as an unexplained penalty.

    `verdict == "deny"` requires a non-empty `reason` (CONTRACTS.md 4.1:
    "required when verdict == 'deny'; shown in the combat log") and
    forbids `call` — a real denial has nothing left to carry out.
    `verdict` in `("forward", "rewrite")` requires `call` to be set — the
    arena executes exactly that `ToolCall`, nothing else, per the trusted
    envelope's whole point (see the module docstring)."""

    verdict: str  # "forward" | "deny" | "rewrite" — see DECISION_VERDICTS
    reason: str | None = None
    call: "ToolCall | None" = None
    quarantine: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in DECISION_VERDICTS:
            raise ValueError(
                f"Decision.verdict must be one of {sorted(DECISION_VERDICTS)}, got {self.verdict!r}"
            )
        if self.verdict == "deny":
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise ValueError("Decision.verdict=='deny' requires a non-empty 'reason'")
            if self.call is not None:
                raise ValueError("Decision.verdict=='deny' must not carry a 'call' — there is nothing to run")
        else:  # forward | rewrite
            if self.call is None:
                raise ValueError(f"Decision.verdict=={self.verdict!r} requires 'call' to be set")
            if _TOOLCALL_AVAILABLE and not isinstance(self.call, ToolCall):
                raise ValueError(
                    f"Decision.call must be a kit.mcp.types.ToolCall instance, got {type(self.call).__name__}"
                )
        if not isinstance(self.quarantine, bool):
            raise ValueError(f"Decision.quarantine must be a bool, got {self.quarantine!r}")
        if self.note is not None and not isinstance(self.note, str):
            raise ValueError(f"Decision.note must be a str or None, got {self.note!r}")

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "call": self.call.to_dict() if self.call is not None and hasattr(self.call, "to_dict") else self.call,
            "quarantine": self.quarantine,
            "note": self.note,
        }


@runtime_checkable
class GatewayContext(Protocol):
    """CONTRACTS.md 4.2 — "read-only, arena-provided". Note what this is
    NOT: unlike `Command`/`Decision` above, CONTRACTS.md writes this as a
    plain `class`, not a `@dataclass(frozen=True, ...)`. That is a real
    signal, not an inconsistency — a `GatewayContext` is a LIVE VIEW the
    arena owns and updates as the duel actually progresses (credits get
    spent, rounds advance, leases mint and expire), not a frozen snapshot
    you receive once. This file therefore models it as a structural
    `Protocol`: the arena hands your `Gateway.__init__` some object shaped
    like this (see `agent/telemetry.py`'s `RecordingGatewayContext` for a
    concrete example your own tests/demos can build), and you read
    `self.ctx.<field>` fresh every time `decide()` runs — NEVER cache a
    context field into a local variable across calls; if you need memory
    that persists across the duel (a cache, a budget tracker, drift notes),
    keep it on YOUR OWN `Gateway` instance attributes instead (CONTRACTS.md
    4.3: "Gateway is instantiated once per duel... persists across the 10
    rounds").

    There is deliberately no `execute` method here — see the module
    docstring's "WHY THERE IS NO execute() METHOD" section. `emit` is the
    ONE thing you can do that has any side effect at all, and it writes to
    `own_telemetry` only: your own side, never scored, never shown to the
    opponent (`agent/telemetry.py` wraps it)."""

    act: str  # "learner:sv-0417" — WHOM YOU SERVE. Authority derives from this.
    sub: str  # "agent:vlearn-tutor" — what you are. NOT authority.
    scopes: frozenset[str]  # {"wiki.read"}; writes need "wiki.write:progress" etc.
    credits: int  # remaining this duel
    round: int
    call_index: int
    leases: tuple[str, ...]  # live lease ids, arena-tracked
    history: tuple[Mapping[str, Any], ...]  # YOUR OWN prior (Command, Decision, outcome) triples this duel

    def emit(self, name: str, **payload: Any) -> None: ...


class Gateway:
    """The control plane. One instance per duel (CONTRACTS.md 4.3) — built
    once at duel start with a `GatewayContext`, then asked to `decide()` on
    every MCP/A2A/DISCOVER command either side of the duel makes for all 10
    rounds. See the module docstring for the trusted-envelope diagram and
    why there is no `execute()` to call instead.

    Instance attributes below are the gateway's per-duel memory: admitted
    cards/delegations, provenance etags, exactly-once write keys, rate
    windows, and accounting.  The arena-owned context remains the source
    of truth for live credits, rounds, leases, and scopes.
    """

    def __init__(self, ctx: GatewayContext) -> None:
        self.ctx = ctx
        self._telemetry = Telemetry(ctx)

        # --- per-duel memory, unused by the naive starter below ---------
        # A cache of anchor -> body-ish data you have already paid for this
        # duel (agent/strategy.py's ResultCache is a ready-made version of
        # this). Populating it needs the *result* of a call, which decide()
        # never sees (it only sees the outgoing Command) — you would fill
        # this from whatever the arena hands back to your agent loop AFTER
        # a call executes, then consult it here on the NEXT decide() call
        # for the same anchor.
        self._seen_anchors: dict[str, Any] = {}
        # Credits you have personally authorised so far this duel — your
        # own running total, independent of (and a cross-check against)
        # `ctx.credits`, which the arena maintains authoritatively.
        self._credits_authorised: int = 0
        # Command ids you have already denied, in case a later job wants to
        # know "have I already said no to this once".
        self._denied_cmd_ids: set[str] = set()
        self._admitted_cards: dict[str, dict[str, Any]] = {}
        self._seen_delegation_ids: set[str] = set()
        self._etags: dict[str, str] = {}
        self._completed_writes: set[tuple[str, str, str]] = set()
        self._used_idempotency_keys: set[str] = set()
        self._rate_calls: dict[tuple[str, str], list[int]] = {}

    def decide(self, cmd: Command) -> Decision:
        """SYNCHRONOUS. PURE. NO I/O. 250 ms wall (RULES.md section 3).
        Raising anything, or returning a `Decision` `__post_init__` rejects,
        is treated by the arena exactly like an explicit deny PLUS a 2
        credit penalty PLUS a scored `integrity` event (CONTRACTS.md 4.1's
        charging table) — so the one thing this method must never do is
        blow up or wander off into I/O, no matter how tempting a "quick
        check" against something external looks. Everything you need to
        decide is already sitting in `cmd` and `self.ctx`.

        The policy runs four ordered jobs: ROUTE, ADMIT, AUTHORIZE, and
        BUDGET.  Every rejection is fail-closed and free to the caller;
        every allowed mutation is represented by a real rewrite Decision."""
        try:
            self._telemetry.decision_seen(cmd)

            # JOB 1 — ROUTE.  A route is an envelope property; accepting it
            # from args is precisely the header-spoof/replica-flip failure.
            if any(cmd.args.get(k) not in (None, "") for k in ("route", "_route", "replica")):
                return self.deny(cmd, "replica route must be selected by the gateway header, not request args")
            if str(cmd.headers.get("x-server-fingerprint", "")).lower() in {"invalid", "unvouched"}:
                return self.deny(cmd, "server identity is not vouched for by the registry")
            if str(cmd.headers.get("x-card-signature", "")).lower() in {"invalid", "unvouched"}:
                return self.deny(cmd, "agent card signature is not registry-vouched")

            routed = cmd
            changed = False
            successor = successor_of(cmd.server, cmd.tool)
            if successor is not None:
                successor_fields = routed.fields
                if successor == ("slides", "query"):
                    successor_fields = tuple(
                        sorted({"body" if f == "snippet" else f for f in routed.fields} - {"anchor"})
                    )
                routed = replace(
                    routed,
                    server=successor[0],
                    tool=successor[1],
                    fields=successor_fields,
                )
                changed = True

            if routed.kind == "mcp":
                path_id = self._path_id(routed)
                choice = pick_replica(path_id=path_id, known_drifting=False)
                headers = {str(k).lower(): v for k, v in routed.headers.items()}
                if headers.get("mcp-replica") != choice.replica:
                    headers["mcp-replica"] = choice.replica
                    routed = replace(routed, headers=headers)
                    changed = True

            # JOB 2 — ADMIT.  Unknown calls, dead leases, undeclared A2A
            # skills, exceeded rate windows, and instruction-shaped command
            # arguments are all calls known to be unsafe before spending.
            key = (routed.server, routed.tool)
            if TOOL_SPECS and key not in TOOL_SPECS:
                return self.deny(cmd, f"unknown tool {routed.server}.{routed.tool}")
            if key == ("slides", "get_frame"):
                if not routed.lease_id or routed.lease_id not in set(self.ctx.leases):
                    return self.deny(cmd, "slides.get_frame requires a live lease from this exchange")
            if self._contains_instruction(routed.args):
                return self.deny(cmd, "instruction-shaped content in command arguments")

            a2a_denial = self._admit_a2a(routed)
            if a2a_denial is not None:
                return self.deny(cmd, a2a_denial)
            rate_denial = self._rate_limit_denial(routed)
            if rate_denial is not None:
                return self.deny(cmd, rate_denial)

            # JOB 3 — AUTHORIZE.  Authority derives from ctx.act, never
            # ctx.sub.  Learner-looking targets must match the served act.
            target = self._target_learner(routed)
            served = self._learner_identity(getattr(self.ctx, "act", None))
            if target is not None and served is not None and target != served:
                return self.deny(cmd, f"target learner {target} is outside served act {served}")
            if key in WRITE_TOOLS:
                scope = WRITE_SCOPES[key]
                if not self._has_scope(scope):
                    return self.deny(cmd, f"missing required scope {scope}")
                write_denial, routed, write_changed = self._prepare_write(routed)
                if write_denial is not None:
                    return self.deny(cmd, write_denial)
                changed = changed or write_changed
            elif not self._has_read_scope():
                return self.deny(cmd, "missing required scope wiki.read")

            # JOB 4 — BUDGET.  Narrow only masks that are objectively full
            # catalogue dumps/wildcards; arbitrary narrowing could make the
            # eventual answer ungrounded.
            fields = routed.fields
            if is_catalog_trap(routed.server, routed.tool, fields):
                fields = CATALOG_MASKS[key]
            elif fields == ("*",) and TOOL_SPECS and key in TOOL_SPECS:
                fields = tuple(TOOL_SPECS[key].default_fields)
            if fields != routed.fields:
                routed = replace(routed, fields=fields)
                changed = True

            estimated_cost = _spec_cost(routed.server, routed.tool, routed.fields, 1)
            if estimated_cost > max(0, int(self.ctx.credits)):
                return self.deny(cmd, f"call costs about {estimated_cost} credits with only {self.ctx.credits} left")

            call = self._to_tool_call(routed)
            decision = Decision(verdict="rewrite" if changed else "forward", call=call)
            self._credits_authorised += estimated_cost
            self._record_admitted_call(routed)
            self._telemetry.budget_snapshot(
                round=int(self.ctx.round),
                credits_left=int(self.ctx.credits),
                spent_this_round=estimated_cost,
            )
            self._telemetry.decision_made(cmd, decision)
            return decision
        except Exception as exc:
            # Fail closed while still returning a schema-valid Decision.  A
            # policy bug must not become the scored `decide raised` path.
            return Decision(
                verdict="deny",
                reason=f"gateway policy could not safely evaluate command: {type(exc).__name__}",
            )

    @staticmethod
    def _path_id(cmd: Command) -> str | None:
        value = cmd.args.get("path_id") or cmd.args.get("anchor") or cmd.args.get("concept")
        if not isinstance(value, str) or not value:
            return None
        head = value.split("#", 1)[0].split("/", 1)[0]
        return head.split(":", 1)[1] if ":" in head else head

    @staticmethod
    def _contains_instruction(args: Mapping[str, Any]) -> bool:
        text = " ".join(str(v) for v in args.values()).lower()
        return any(marker in text for marker in _INSTRUCTION_MARKERS)

    @staticmethod
    def _learner_identity(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normal = value.strip().lower()
        if normal.startswith("learner:"):
            return normal
        if normal.startswith("sv-"):
            return f"learner:{normal}"
        return None

    def _target_learner(self, cmd: Command) -> str | None:
        for name in ("learner", "learner_id", "target", "subject"):
            target = self._learner_identity(cmd.args.get(name))
            if target is not None:
                return target
        if (cmd.server, cmd.tool) == ("progress", "record_mastery"):
            return self._learner_identity(cmd.args.get("anchor"))
        return None

    def _has_scope(self, required: str) -> bool:
        scopes = {str(s).lower() for s in getattr(self.ctx, "scopes", ())}
        return required in scopes or "wiki.write" in scopes or "wiki.write:*" in scopes or "*" in scopes

    def _has_read_scope(self) -> bool:
        scopes = {str(s).lower() for s in getattr(self.ctx, "scopes", ())}
        return "wiki.read" in scopes or "*" in scopes

    def _admit_a2a(self, cmd: Command) -> str | None:
        if cmd.kind != "a2a" and cmd.server not in A2A_PEERS:
            return None
        card = self._admitted_cards.get(cmd.server)
        if card is not None:
            if not card.get("verified"):
                return "peer card was not verified by the registry"
            if cmd.tool not in set(card.get("skills") or ()):
                return "requested skill is not declared by the admitted peer card"

        aud = cmd.headers.get("aud")
        if aud is not None and aud not in (cmd.server, f"a2a:{cmd.server}", f"mcp:{cmd.server}"):
            return "delegation audience does not match the peer being called"

        token = cmd.args.get("delegation_token") or cmd.args.get("delegation")
        if token is not None and verify_delegation is not None:
            admission = verify_delegation(
                token,
                aud=f"a2a:{cmd.server}",
                call_index=cmd.call_index,
                expected_act=self.ctx.act,
                seen_token_ids=self._seen_delegation_ids,
            )
            if not admission.admitted:
                detail = admission.detail or str(admission.reason)
                return f"delegation rejected: {detail}"
        return None

    def _rate_limit_denial(self, cmd: Command) -> str | None:
        spec = TOOL_SPECS.get((cmd.server, cmd.tool)) if TOOL_SPECS else None
        if spec is None or spec.rate_limit is None:
            return None
        allowed, per_rounds = spec.rate_limit
        current = int(self.ctx.round)
        recent = [r for r in self._rate_calls.get((cmd.server, cmd.tool), ())
                  if r >= current - per_rounds + 1]
        if len(recent) >= allowed:
            return f"rate window exhausted for {cmd.server}.{cmd.tool}"
        return None

    def _prepare_write(self, cmd: Command) -> tuple[str | None, Command, bool]:
        headers = {str(k).lower(): v for k, v in cmd.headers.items()}
        anchor = str(cmd.args.get("anchor") or cmd.args.get("learner") or "")
        cached_etag = self._etags.get(anchor)
        changed = False
        if cached_etag is not None and headers.get("if-match") != cached_etag:
            headers["if-match"] = cached_etag
            changed = True
        if not headers.get("if-match"):
            return "write has no fresh If-Match from registry.provenance", cmd, False
        if not headers.get("idempotency-key"):
            return "write has no Idempotency-Key", cmd, False
        if str(headers["idempotency-key"]) in self._used_idempotency_keys:
            return "Idempotency-Key was already used this duel", cmd, False
        write_key = (cmd.server, cmd.tool, anchor)
        if write_key in self._completed_writes:
            return "write target/tool pair was already authorised this duel", cmd, False
        if headers != cmd.headers:
            cmd = replace(cmd, headers=headers)
            changed = True
        return None, cmd, changed

    def _record_admitted_call(self, cmd: Command) -> None:
        key = (cmd.server, cmd.tool)
        spec = TOOL_SPECS.get(key) if TOOL_SPECS else None
        if spec is not None and spec.rate_limit is not None:
            self._rate_calls.setdefault(key, []).append(int(self.ctx.round))
        if key in WRITE_TOOLS:
            anchor = str(cmd.args.get("anchor") or cmd.args.get("learner") or "")
            self._completed_writes.add((cmd.server, cmd.tool, anchor))
            idem = {str(k).lower(): v for k, v in cmd.headers.items()}.get("idempotency-key")
            if idem is not None:
                self._used_idempotency_keys.add(str(idem))
        token = cmd.args.get("delegation_token") or cmd.args.get("delegation")
        if isinstance(token, Mapping):
            token_id = token.get("token_id")
            if isinstance(token_id, str) and token_id:
                self._seen_delegation_ids.add(token_id)

    def note_provenance(self, anchor: str, etag: str) -> None:
        """Record a provenance result supplied by the trusted loop."""
        if isinstance(anchor, str) and anchor and isinstance(etag, str) and etag:
            self._etags[anchor] = etag
            self._completed_writes = {key for key in self._completed_writes if key[2] != anchor}

    def note_result(self, anchor: str, etag: str) -> None:
        """Compatibility alias used by the practice harness/operator API."""
        self.note_provenance(anchor, etag)

    def note_card(self, server: str, card: Mapping[str, Any]) -> None:
        """Record an Agent Card already checked by the trusted registry path."""
        if isinstance(server, str) and server and isinstance(card, Mapping):
            self._admitted_cards[server] = dict(card)

    def deny(self, cmd: Command, reason: str) -> Decision:
        """Build a valid, zero-credit denial and record it consistently."""
        self._denied_cmd_ids.add(cmd.cmd_id)
        decision = Decision(verdict="deny", reason=reason)
        self._telemetry.decision_made(cmd, decision)
        return decision

    def _to_tool_call(self, cmd: Command) -> "ToolCall":
        """`Command` -> the `ToolCall` (CONTRACTS.md 3.1) the arena will
        actually execute on a `forward`/`rewrite` verdict. When
        `kit.mcp.types` is unavailable (see the module-level import guard),
        falls back to a plain dict carrying the identical fields — `Decision`
        accepts it either way (the `ToolCall` isinstance check inside
        `Decision.__post_init__` only runs when the real class loaded)."""
        fields = {
            "server": cmd.server,
            "tool": cmd.tool,
            "args": dict(cmd.args),
            "fields": cmd.fields,
            "headers": dict(cmd.headers),
            "lease_id": cmd.lease_id,
            "call_index": cmd.call_index,
        }
        if _TOOLCALL_AVAILABLE:
            return ToolCall(**fields)
        return fields  # type: ignore[return-value]


if __name__ == "__main__":
    print("=== agent.gateway: Command / Decision validation ===\n")

    good_cmd = Command(
        cmd_id="cmd:0000",
        kind="mcp",
        raw="MCP slides.get_frame anchor=Frame:3f2a9c11/w/041 fields=title,body lease=lse_7f21",
        server="slides",
        tool="get_frame",
        args={"anchor": "Frame:3f2a9c11/w/041"},
        fields=("body", "title"),
        headers={},
        lease_id="lse_7f21",
        call_index=0,
    )
    print(f"  Command constructed: {good_cmd}")
    assert good_cmd.kind == "mcp"

    print("\n  Rejection demo (each must raise ValueError):")

    def _expect_value_error(label: str, fn) -> None:
        try:
            fn()
        except ValueError as exc:
            print(f"    [{label:38}] -> ValueError: {exc}")
        else:
            raise AssertionError(f"expected ValueError for case {label!r}")

    _expect_value_error("Command.kind == 'answer'", lambda: Command(
        cmd_id="cmd:0001", kind="answer", raw="x", server="slides", tool="get_frame",
        args={}, fields=(), headers={}, lease_id=None, call_index=0,
    ))
    _expect_value_error("Decision verdict='deny' with no reason", lambda: Decision(verdict="deny"))
    _expect_value_error(
        "Decision verdict='forward' with no call", lambda: Decision(verdict="forward")
    )
    _expect_value_error(
        "Decision verdict='deny' carrying a call",
        lambda: Decision(verdict="deny", reason="nope", call={"server": "x", "tool": "y"}),
    )
    _expect_value_error("Decision verdict='?' unknown", lambda: Decision(verdict="???"))

    print("\n=== Command.from_action_dict — real canonicaliser integration ===\n")
    if _canonicalise_action is None:
        print("  kit.loop.agent not importable yet — skipping the live canonicaliser demo")
        demo_commands: list[Command] = [good_cmd]
    else:
        raw_actions = [
            "MCP registry.provenance anchor=Frame:3f2a9c11/w/041 fields=etag",
            'MCP slides.query q="streamable http replaces http+sse" fields=title,body',
            "A2A curriculum-analyst.which_days_cover concept=Concept:streamable-http fields=anchor,course_day,track",
            "DISCOVER registry.list_servers fields=name",
        ]
        demo_commands = []
        for i, raw in enumerate(raw_actions):
            action = _canonicalise_action(raw, call_index=i)
            cmd = Command.from_action_dict(action, cmd_id=f"cmd:{i:04d}")
            print(f"  {raw!r}\n    -> {cmd.kind}: {cmd.server}.{cmd.tool} fields={cmd.fields}")
            demo_commands.append(cmd)
        assert {c.kind for c in demo_commands} == {"mcp", "a2a", "discover"}

        answer_action = _canonicalise_action(
            'ANSWER {"text": "day 26, track P2T2"}', call_index=None
        )
        try:
            Command.from_action_dict(answer_action, cmd_id="cmd:9999")
        except ValueError as exc:
            print(f"\n  an 'answer' action correctly refuses to become a Command: {exc}")
        else:
            raise AssertionError("expected ValueError for an 'answer' action")

    print("\n=== Gateway.decide — route/admit/authorize/budget policy ===\n")
    ctx = RecordingGatewayContext(
        act="learner:sv-0401",
        sub="agent:demo-team",
        scopes=frozenset({"wiki.read"}),
        credits=100,
        round=1,
        call_index=0,
        leases=(),
        history=(),
    )
    assert isinstance(ctx, GatewayContext), "RecordingGatewayContext must structurally satisfy GatewayContext"
    gw = Gateway(ctx)
    for cmd in demo_commands:
        decision = gw.decide(cmd)
        print(f"  decide({cmd.server}.{cmd.tool}) -> verdict={decision.verdict!r} quarantine={decision.quarantine}")
        assert decision.verdict in {"forward", "rewrite"}
        assert decision.call is not None
        call_dict = decision.call.to_dict() if hasattr(decision.call, "to_dict") else decision.call
        assert call_dict["server"] == cmd.server
        assert call_dict["tool"] == cmd.tool
        assert tuple(call_dict["fields"]) == cmd.fields

    print(f"\n=== Gateway.deny — the unused-by-default free-abstention path ===\n")
    denial = gw.deny(demo_commands[0], reason="demo: withholding pending a fresher registry.provenance read")
    print(f"  gw.deny(...) -> verdict={denial.verdict!r} reason={denial.reason!r} call={denial.call!r}")
    assert denial.verdict == "deny"
    assert denial.call is None
    assert demo_commands[0].cmd_id in gw._denied_cmd_ids

    print(f"\n=== own_telemetry — recorded on YOUR side only, never shown to the opponent ===\n")
    print(f"  {len(ctx.events)} events recorded on this ctx this run:")
    for ev in ctx.events:
        print(f"    {ev['name']}: {sorted(ev['payload'].keys())}")
    assert len(ctx.events) >= len(demo_commands) * 2 + 1  # decision_seen + decision_made per call, plus the deny

    print("\nAll agent/gateway.py demos passed.")
