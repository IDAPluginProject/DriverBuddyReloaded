"""
settings_ui.py: scan-settings dialog for Driver Buddy Reloaded.

Two implementations of the same dialog, chosen at runtime:

* Primary -- a PyQt5 dialog (`_SettingsDialog`).  Preferred because its
  layout/tooltips are far nicer than ida_kernwin.Form, which has fragile
  format-string semantics.
* Fallback -- an ida_kernwin.Form (`_show_settings_kernwin`).  Used only when
  PyQt5 cannot be imported.  This happens on IDA installs whose bundled PyQt5
  was compiled for a different Python than the interpreter idapyswitch selected
  (e.g. IDA 7.6's python38 PyQt5 running under Python 3.10 -> `ImportError: DLL
  load failed while importing sip`), and on IDA 9.x which ships PySide6 rather
  than PyQt5.  Without this fallback the Qt ImportError was swallowed and
  auto-analysis ran with no settings dialog at all.

Both paths expose the same feature flags and tuning constants and enforce the
same coherence rules via `config.Feature.validate()`.

Importing this module outside IDA is safe; PyQt5 imports are deferred inside the
Qt path and `import ida_kernwin` is deferred inside the fallback, so the
pure-Python test harness can import it without side effects.
"""

from __future__ import annotations

from DriverBuddyReloaded import config

# ---------------------------------------------------------------------------
# Metadata tables -- keep in sync with config.py
# ---------------------------------------------------------------------------

# Groups of (Feature class attribute, display label, tooltip).
# Tooltip is shown on hover; use "" to suppress it for self-explanatory items.
_FEATURE_GROUPS = [
    ("IOCTL", [
        ("IOCTL_SCAN",
         "IOCTL scan",
         "Primary IOCTL discovery: dispatcher scan plus immediate-operand search"),
        ("IOCTL_DECOMPILER",
         "IOCTL decompiler (HexRays)",
         "Use HexRays ctree to recover codes from switch-case labels and comparison "
         "constants; required to handle jump-table and binary-search dispatch patterns"),
    ]),
    ("Deep Analysis", [
        ("CALLCHAIN",
         "Callchain tracing",
         "Trace call paths from each IOCTL handler to dangerous sinks; requires IOCTL scan"),
        ("HEURISTICS",
         "Heuristics",
         "Structural checks: copy-validation, IRQL, MDL, alloca, pool-alloc-trust, "
         "write-primitives, and privileged instructions"),
        ("TOCTOU_CHECK",
         "TOCTOU / double-fetch",
         "Flag double-fetch of a user-mode pointer within a single dispatch path "
         "(time-of-check / time-of-use race condition); gated on METHOD_NEITHER IOCTLs"),
        ("UAF_DETECT",
         "Use-after-free",
         "Detect use-after-free patterns via per-register CFG walk and a backward "
         "global instruction scan"),
        ("RISK_SCORING",
         "Risk scoring",
         "Assign a severity level to each IOCTL based on reachable dangerous sinks "
         "and heuristic hits"),
    ]),
    ("Audit & Discovery", [
        ("EXPORTS_AUDIT",
         "Exports audit",
         "Report exported functions with zero cross-references "
         "(dead or unexplained entry points)"),
        ("ACL_AUDIT",
         "ACL audit",
         "Flag DeviceCreate calls that pass an open (world-accessible) security descriptor"),
        ("SYMLINK_TRACK",
         "Symbolic link tracking",
         "Trace symbolic link registrations to map device aliases reachable from user mode"),
        ("SEGMENT_OPCODE_SCAN",
         "Segment opcode scan (slow)",
         "Scan every code segment for opcode patterns of interest; "
         "can be slow on large binaries -- disabled by default"),
    ]),
    ("Annotation", [
        ("IRP_MJ_ENUM",
         "IRP_MJ enum annotation",
         "Annotate the decompiler output so MajorFunction[IRP_MJ_CREATE] appears "
         "instead of MajorFunction[0]"),
        ("POOLTAG_FALLBACK",
         "Pool-tag fallback",
         "When no import-annotated tags are found, scan backward from each pool-alloc "
         "call site for immediate operands staged in registers that IDA does not annotate automatically"),
    ]),
    ("Output", [
        ("JSON_EXPORT",
         "JSON export",
         "Write findings to a .json file next to the IDB"),
        ("HTML_REPORT",
         "HTML report",
         "Write findings to a browsable .html report next to the IDB"),
        ("RESULTS_WINDOW",
         "Results window",
         "Open the findings chooser window inside IDA after analysis completes"),
    ]),
]

# Flat list derived from groups -- used for defaults capture and _checks order.
_FEATURES = [(attr, label) for _, items in _FEATURE_GROUPS for attr, label, _ in items]

# (config module attribute, display label, tooltip)
_TUNING = [
    ("CALLCHAIN_MAX_DEPTH",
     "Callchain max depth",
     "Maximum recursion depth when following call chains from IOCTL handlers to sinks"),
    ("HANDLER_SEED_DEPTH",
     "Handler seed depth",
     "Call levels expanded from the IOCTL handler when seeding deep heuristics "
     "(double-fetch, UAF, pool-alloc-trust, etc.)"),
    ("POOLTAG_LOOKBACK",
     "Pool-tag lookback (instrs)",
     "Instructions scanned backward from a pool allocation to find the tag constant"),
    ("COPY_VALIDATION_LOOKBACK",
     "Copy validation lookback (instrs)",
     "Instructions scanned backward from a copy sink to find a size validation check"),
    ("COPY_VALIDATION_LOOKAHEAD",
     "Copy validation lookahead (instrs)",
     "Instructions scanned forward from a copy sink to find a size validation check"),
    ("UAF_GLOBAL_BACKWALK",
     "UAF global back-walk (instrs)",
     "Instructions scanned backward in the function when searching for a free before a use"),
    ("SYMLINK_DECODE_LOOKBACK",
     "Symlink decode lookback (instrs)",
     "Instructions scanned backward from a symlink registration to decode the device path"),
]

# Captured once at import time (before any runtime mutations) so "Reset to
# Defaults" always means the values shipped in config.py.
_FEATURE_DEFAULTS = {attr: bool(getattr(config.Feature, attr)) for attr, _ in _FEATURES}
_TUNING_DEFAULTS  = {attr: int(getattr(config, attr))          for attr, label, _ in _TUNING}


class _SettingsDialog:
    """
    PyQt5 modal dialog. Constructed lazily so the module can be imported in
    environments where Qt is unavailable (e.g. the pure-Python test harness).
    """

    def __init__(self):
        from PyQt5 import QtCore, QtWidgets

        dlg = QtWidgets.QDialog()
        dlg.setWindowTitle("Driver Buddy Reloaded - Settings")
        dlg.setWindowFlags(
            dlg.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint
        )
        dlg.setMinimumWidth(560)
        self._dlg = dlg

        root = QtWidgets.QVBoxLayout(dlg)

        # --- Analysis stages (one QGroupBox per logical group, 2-column grid) --
        self._checks = {}
        for group_name, items in _FEATURE_GROUPS:
            grp = QtWidgets.QGroupBox(group_name)
            grid = QtWidgets.QGridLayout(grp)
            grid.setColumnStretch(0, 1)
            grid.setColumnStretch(1, 1)
            for i, (attr, label, tip) in enumerate(items):
                cb = QtWidgets.QCheckBox(label)
                cb.setChecked(bool(getattr(config.Feature, attr)))
                if tip:
                    cb.setToolTip(tip)
                self._checks[attr] = cb
                grid.addWidget(cb, i // 2, i % 2)
            root.addWidget(grp)

        # --- Tuning constants (labelled spinboxes) ---------------------------
        tuning_group = QtWidgets.QGroupBox("Tuning")
        tuning_form = QtWidgets.QFormLayout(tuning_group)
        tuning_form.setLabelAlignment(QtCore.Qt.AlignLeft)

        self._spins = {}
        for attr, label, tip in _TUNING:
            spin = QtWidgets.QSpinBox()
            spin.setRange(1, 9999)
            spin.setValue(int(getattr(config, attr)))
            spin.setFixedWidth(80)
            if tip:
                spin.setToolTip(tip)
            self._spins[attr] = spin
            lbl = QtWidgets.QLabel(label + ":")
            if tip:
                lbl.setToolTip(tip)
            tuning_form.addRow(lbl, spin)

        root.addWidget(tuning_group)

        # --- Buttons ---------------------------------------------------------
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        # Validate before accepting so the dialog stays open on invalid input.
        ok_btn = buttons.button(QtWidgets.QDialogButtonBox.Ok)
        ok_btn.clicked.connect(self._on_ok)
        buttons.rejected.connect(dlg.reject)

        reset_btn = QtWidgets.QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self._on_reset)
        buttons.addButton(reset_btn, QtWidgets.QDialogButtonBox.ResetRole)

        root.addWidget(buttons)

    def _on_ok(self):
        """Validate proposed feature-flag combination; accept only when coherent.

        Delegates to config.Feature.validate() so the dialog enforces exactly the
        same coherence rules as the startup check -- no duplicated rule list to
        drift out of sync (B19).
        """
        from PyQt5 import QtWidgets
        proposed = {attr: cb.isChecked() for attr, cb in self._checks.items()}
        try:
            config.Feature.validate(proposed)
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(
                self._dlg, "Driver Buddy Reloaded", str(exc))
            return
        self._dlg.accept()

    def _on_reset(self):
        """Restore all controls to the config.py defaults (does not save until OK)."""
        for attr, cb in self._checks.items():
            cb.setChecked(_FEATURE_DEFAULTS[attr])
        for attr, spin in self._spins.items():
            spin.setValue(_TUNING_DEFAULTS[attr])

    def exec_(self) -> int:
        return self._dlg.exec_()

    def apply(self) -> None:
        """Write dialog values to config. Only called after accept() -- always valid."""
        for attr, cb in self._checks.items():
            setattr(config.Feature, attr, cb.isChecked())
        for attr, spin in self._spins.items():
            setattr(config, attr, spin.value())


def _show_settings_qt() -> bool:
    """Show the PyQt5 settings dialog. Returns True to proceed, False on Cancel.

    Raises if the Qt stack cannot be loaded or run, so `show_settings()` can fall
    back to the ida_kernwin form. On OK the chosen values are written to config.
    """
    from PyQt5 import QtWidgets  # ImportError when the bundled PyQt5 targets a
                                 # different Python ABI, or on IDA 9.x (PySide6)
    dlg = _SettingsDialog()
    accepted = dlg.exec_() == QtWidgets.QDialog.Accepted
    if accepted:
        dlg.apply()
        return True
    return False


def _kernwin_format_string() -> str:
    """Build the ida_kernwin.Form format string from the shared metadata tables.

    Checkboxes are named ``c0..cN`` in ``_FEATURES`` order and grouped one
    QGroupBox-equivalent per ``_FEATURE_GROUPS`` entry; tuning fields are named
    ``i0..iM`` in ``_TUNING`` order. Pure (no IDA import) so it can be exercised
    offline; the control map that pairs with it is built by ``_kernwin_controls``.
    """
    lines = ["BUTTON YES* OK", "BUTTON CANCEL Cancel",
             "Driver Buddy Reloaded - Settings", ""]
    idx = 0
    for gi, (group_name, items) in enumerate(_FEATURE_GROUPS):
        last = len(items) - 1
        for j, (attr, label, _tip) in enumerate(items):
            head = "##{}##".format(group_name) if j == 0 else ""
            closer = "{{cg{}}}>".format(gi) if j == last else ""
            lines.append("<{}{}:{{c{}}}>{}".format(head, label, idx, closer))
            idx += 1
    lines.append("")
    lines.append("Tuning parameters (instruction / depth counts):")
    # ida_kernwin.Form lays widgets out on a character grid: the input box begins
    # at the column where "{iN}" appears, so uneven label lengths leave the boxes
    # ragged. Pad every label to the widest so the ":" (and the box after it) line
    # up -- the QFormLayout in the Qt dialog did this automatically.
    tune_label_w = max(len(label) for _attr, label, _tip in _TUNING)
    for k, (attr, label, _tip) in enumerate(_TUNING):
        lines.append("<{}:{{i{}}}>".format(label.ljust(tune_label_w), k))
    return "\n".join(lines) + "\n"


def _kernwin_controls(form_cls, tune_state):
    """Build the control map for the fallback form.

    ``form_cls`` is ``ida_kernwin.Form`` (passed in so this module needs no
    IDA import at load time). ``tune_state`` seeds the numeric fields.
    """
    controls = {}
    idx = 0
    for gi, (_group_name, items) in enumerate(_FEATURE_GROUPS):
        names = tuple("c{}".format(idx + j) for j in range(len(items)))
        controls["cg{}".format(gi)] = form_cls.ChkGroupControl(names)
        idx += len(items)
    for k, (attr, _label, _tip) in enumerate(_TUNING):
        controls["i{}".format(k)] = form_cls.NumericInput(
            tp=form_cls.FT_DEC, value=int(tune_state[attr]))
    return controls


def _show_settings_kernwin() -> bool:
    """Fallback settings dialog built on ida_kernwin.Form (no Qt required).

    Exposes the same feature flags and tuning constants as the Qt dialog and
    enforces the same coherence rules via ``config.Feature.validate()``. On an
    invalid combination it warns and re-opens the form (mirroring the Qt dialog's
    stay-open-on-invalid behaviour). Returns True to proceed, False on Cancel.
    """
    import ida_kernwin

    fmt = _kernwin_format_string()
    feat_state = {attr: bool(getattr(config.Feature, attr)) for attr, _ in _FEATURES}
    tune_state = {attr: int(getattr(config, attr)) for attr, _, _ in _TUNING}

    while True:
        form = ida_kernwin.Form(fmt, _kernwin_controls(ida_kernwin.Form, tune_state))
        form.Compile()
        for i, (attr, _) in enumerate(_FEATURES):
            getattr(form, "c{}".format(i)).checked = feat_state[attr]
        ok = form.Execute()
        if ok == 1:
            feat_state = {attr: bool(getattr(form, "c{}".format(i)).checked)
                          for i, (attr, _) in enumerate(_FEATURES)}
            tune_state = {attr: max(1, int(getattr(form, "i{}".format(k)).value))
                          for k, (attr, _, _) in enumerate(_TUNING)}
        form.Free()
        if ok != 1:
            return False
        try:
            config.Feature.validate(feat_state)
        except ValueError as exc:
            ida_kernwin.warning("Driver Buddy Reloaded\n\n{}".format(exc))
            continue
        for attr, val in feat_state.items():
            setattr(config.Feature, attr, val)
        for attr, val in tune_state.items():
            setattr(config, attr, val)
        return True


def show_settings() -> bool:
    """
    Show the scan-settings dialog. Returns True if analysis should proceed.

    Tries the PyQt5 dialog first (nicer layout); on any failure to load or run
    the Qt stack -- e.g. IDA 7.6 bundling a PyQt5 built for a different Python
    ABI, or IDA 9.x shipping PySide6 -- falls back to the ida_kernwin form so the
    user still gets a settings dialog instead of it being silently skipped.

    On OK the chosen values are written to config and True is returned; on Cancel
    False is returned so the caller aborts the run. Only if *both* dialogs are
    unavailable is a warning logged and True returned, so analysis proceeds with
    the current config rather than being silently disabled.
    """
    try:
        return _show_settings_qt()
    except Exception as qt_exc:
        print("[Driver Buddy Reloaded] PyQt settings dialog unavailable "
              "({}: {}); falling back to the built-in IDA form.".format(
                  type(qt_exc).__name__, qt_exc))

    try:
        return _show_settings_kernwin()
    except Exception as kw_exc:
        print("[Driver Buddy Reloaded] Settings form unavailable ({}: {}); "
              "proceeding with current settings.".format(
                  type(kw_exc).__name__, kw_exc))
        return True
