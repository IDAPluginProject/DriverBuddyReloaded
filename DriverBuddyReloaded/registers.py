"""
registers.py: x86/x64 general-purpose register helpers for the dataflow heuristics.

Pure string logic with no IDA import, so it is unit-testable under plain CPython
and shared by the register-tracking checks (use-after-free).  The key operations:

  * aliases(reg)        -- every name that shares physical storage with `reg`
                           (rcx/ecx/cx/cl/ch), so a write to any alias clears the
                           whole group (fixes the x64 zero-extension case where
                           `mov ecx, ..` overwrites rcx).
  * memory_base(op)     -- the BASE register of a memory operand, distinguished
                           from a scaled index, so `[rdx+rcx*8]` reports rdx (a
                           freed rcx used only as an index is not a dereference).
  * dest_register(op)   -- the register an operand names when it is a bare
                           register (not a memory reference).
"""

from __future__ import annotations

import re

# Canonical 64-bit register -> every narrower name that aliases the same storage.
# Writing any member overwrites the tracked value, so kills must clear the group.
_ALIAS_GROUPS = (
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
    ("r8", "r8d", "r8w", "r8b"),
    ("r9", "r9d", "r9w", "r9b"),
    ("r10", "r10d", "r10w", "r10b"),
    ("r11", "r11d", "r11w", "r11b"),
    ("r12", "r12d", "r12w", "r12b"),
    ("r13", "r13d", "r13w", "r13b"),
    ("r14", "r14d", "r14w", "r14b"),
    ("r15", "r15d", "r15w", "r15b"),
)

_ALIAS_OF = {}
for _grp in _ALIAS_GROUPS:
    _frozen = frozenset(_grp)
    for _r in _grp:
        _ALIAS_OF[_r] = _frozen


def is_register(name: str) -> bool:
    """True if `name` (case-insensitive) is a known GP register."""
    return bool(name) and name.strip().lower() in _ALIAS_OF


def aliases(reg: str) -> frozenset:
    """Every register name sharing physical storage with `reg` (including itself).
    An unknown name returns just {reg} lower-cased."""
    reg = (reg or "").strip().lower()
    return _ALIAS_OF.get(reg, frozenset({reg}))


def dest_register(op_text: str):
    """The register an operand names, when the operand is a bare register (no
    memory brackets); otherwise None.  Used to detect a destination-register
    write that kills a tracked value."""
    if not op_text:
        return None
    t = op_text.strip().lower()
    return t if t in _ALIAS_OF else None


def memory_base(op_text: str):
    """The BASE register of a memory operand `[base(+index*scale)(+disp)]`, or None.

    The base is the unscaled register term; a term containing '*' is the scaled
    index and is skipped.  So `[rcx+8]` -> 'rcx', `[rdx+rcx*8]` -> 'rdx' (rcx is
    the index, not the base), `[rcx]` -> 'rcx', and a non-memory operand -> None.
    """
    if not op_text or "[" not in op_text:
        return None
    start = op_text.index("[") + 1
    end = op_text.rindex("]") if "]" in op_text else len(op_text)
    inner = op_text[start:end]
    for part in inner.split("+"):
        part = part.strip().lower()
        if not part or "*" in part or "-" in part:
            continue  # scaled index or a displacement term, not the base
        if part in _ALIAS_OF:
            return part
    return None
