#!/usr/bin/env python3
"""
QML Plain-Text Gate (Omarchy plugin UI safety rule)

QML `Text` defaults to `Text.AutoText`, which renders markup-shaped input as
rich text: an item named `<img src="https://example.invalid/x">` would load a
remote resource inside the unsandboxed shell. OmarchyBitwarden.qml and
components/*.qml must therefore keep every text sink plain:

1. Every `Text`, `Label`, `TextEdit` and `TextArea` element declares
   `textFormat` in its own property block (a declaration on a nested child
   does not count for its parent).
2. Every `textFormat:` binding is the literal `Text.PlainText` or
   `TextEdit.PlainText`; a variable, an expression or any other format is
   refused. The one exception is a literal `RichText` (or `StyledText`)
   whose `textFormat:` line, or the line above it, carries the marker
       // text-format-exemption: RichText escaped by <functionName>
   and whose element calls `<functionName>(` in its own block: the plugin
   escapes that text itself (the password generator's coloured output).
3. `textFormat` is never assigned at runtime (`x.textFormat = ...`) and never
   named in a string (`Binding { property: "textFormat" }`, `x["textFormat"]`).
4. A `ToolTip` element whose text is not a single string literal sets a
   `contentItem` that is a `Text` or `Label` element (which rules 1 and 2
   keep plain): the default ToolTip content item is AutoText.
5. The attached `ToolTip.text:` and `ToolTip.show(...)` take a single string
   literal only: they display through the shared AutoText tooltip.

Strings, comments and JavaScript regular-expression literals are masked
before braces are matched, so braces or element names inside them neither
open nor close blocks; the marker of rule 2 and the literals of rules 4 and 5
are read from the unmasked source at the same offsets.

Exit codes:
- 0 when every rule holds.
- 1 when any rule is broken (CI blocks the change), or a self-test fails.
"""

import argparse
import glob
import os
import re
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

QUALIFIER = r"(?<![\w.])(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
GUARDED_ELEMENTS = ("Text", "Label", "TextEdit", "TextArea")
ELEMENT_PATTERN = re.compile(QUALIFIER + r"(" + "|".join(GUARDED_ELEMENTS) + r")\s*\{")
TOOLTIP_ELEMENT_PATTERN = re.compile(QUALIFIER + r"(ToolTip)\s*\{")
TEXT_FORMAT_KEY_PATTERN = re.compile(r"(?<![\w$])textFormat\s*:")
# `=` and every compound assignment, but not `==` / `===`.
TEXT_FORMAT_ASSIGNMENT_PATTERN = re.compile(r"(?<![\w$])textFormat\s*(?:\*\*|>>>|<<|>>|&&|\|\||\?\?|[-+*/%&|^])?=(?!=)")
TEXT_FORMAT_STRING_PATTERN = re.compile(r"""["'`]textFormat["'`]""")
PLAIN_TEXT_VALUE_PATTERN = re.compile(r"(?:Text|TextEdit)\.PlainText")
EXEMPTIBLE_VALUE_PATTERN = re.compile(r"(?:Text|TextEdit)\.(?:RichText|StyledText)")
EXEMPTION_MARKER_PATTERN = re.compile(r"text-format-exemption:\s*RichText escaped by\s+([A-Za-z_$][\w$]*)")
# A binding continues on the next line when that line starts with an operator.
CONTINUATION_PATTERN = re.compile(r"\n\s*[?:+\-*/%&|^.(\[,<>=!]")
OWN_KEY_PATTERN = r"(?<![\w$.]){}\s*:"
TOOLTIP_TEXT_KEY_PATTERN = re.compile(OWN_KEY_PATTERN.format("text"))
PLAIN_CONTENT_ITEM_PATTERN = re.compile(r"(?<![\w$.])contentItem\s*:\s*" + QUALIFIER + r"(?:Text|Label)\s*\{")
ATTACHED_TOOLTIP_TEXT_PATTERN = re.compile(r"(?<![\w$.])ToolTip\.text\s*:")
ATTACHED_TOOLTIP_SHOW_PATTERN = re.compile(r"(?<![\w$.])ToolTip\.show\s*\(")
# A single string literal, then the end of the binding (or of the argument).
STRING_LITERAL_BINDING_PATTERN = re.compile(r"""[ \t]*(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')[ \t]*(?:[;\n}]|//|$)""")
STRING_LITERAL_ARGUMENT_PATTERN = re.compile(r"""\s*(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')\s*[,)]""")
REMEDIATION = "  Remediation: plugins.md, Plugin UI Safety; rules in scripts/check-qml-text-format.py."

# A "/" after one of these (or at the start) begins a regular expression
# literal rather than a division.
REGEX_PRECEDING_CHARACTERS = set("(,=:[!&|?{};+-*%<>~^")
# ...and so does a "/" after one of these keywords.
REGEX_PRECEDING_KEYWORDS = {"return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else"}
PRECEDING_WORD_PATTERN = re.compile(r"([A-Za-z_$][\w$]*)\s*$")
QUOTE_CHARACTERS = "\"'`"


class SourceMasker:
    """Replaces comment, string and regex contents with spaces, keeping
    newlines and character offsets, so structural scanning sees only code."""

    def __init__(self, source: str):
        self.source = source
        self.output = list(source)
        self.position = 0
        self.last_significant = ""

    def blank(self, start: int, end: int) -> None:
        for index in range(start, end):
            if self.output[index] != "\n":
                self.output[index] = " "

    def skip_line_comment(self) -> None:
        end = self.source.find("\n", self.position)
        end = len(self.source) if end == -1 else end
        self.blank(self.position, end)
        self.position = end

    def skip_block_comment(self) -> None:
        end = self.source.find("*/", self.position + 2)
        end = len(self.source) if end == -1 else end + 2
        self.blank(self.position, end)
        self.position = end

    @staticmethod
    def character_class_state(character: str, closing: str, in_class: bool) -> bool:
        """Whether a regex literal is inside a `[...]` class after `character`;
        a "/" inside a class does not end the literal."""
        if closing != "/" or character not in "[]":
            return in_class
        return character == "["

    def skip_delimited(self, closing: str, allow_newline: bool) -> None:
        start = self.position
        index = start + 1
        in_class = False
        while index < len(self.source):
            character = self.source[index]
            if character == "\\":
                index += 2
                continue
            if character == "\n" and not allow_newline:
                break
            index += 1
            in_class = self.character_class_state(character, closing, in_class)
            if character == closing and not in_class:
                break
        self.blank(start, index)
        self.position = index
        self.last_significant = "a"

    def preceding_word(self) -> str:
        window = "".join(self.output[max(0, self.position - 32):self.position])
        match = PRECEDING_WORD_PATTERN.search(window)
        return match.group(1) if match else ""

    def starts_regex(self) -> bool:
        if self.last_significant == "" or self.last_significant in REGEX_PRECEDING_CHARACTERS:
            return True
        return self.preceding_word() in REGEX_PRECEDING_KEYWORDS

    def step(self) -> None:
        source, position = self.source, self.position
        pair = source[position:position + 2]
        character = source[position]
        if pair == "//":
            self.skip_line_comment()
        elif pair == "/*":
            self.skip_block_comment()
        elif character in QUOTE_CHARACTERS:
            self.skip_delimited(character, allow_newline=character == "`")
        elif character == "/" and self.starts_regex():
            self.skip_delimited("/", allow_newline=False)
        else:
            if not character.isspace():
                self.last_significant = character
            self.position += 1

    def mask(self) -> str:
        while self.position < len(self.source):
            self.step()
        return "".join(self.output)


def mask_source(source: str) -> str:
    return SourceMasker(source).mask()


def brace_visibility(character: str, depth: int) -> tuple[bool, int]:
    """Whether `character` stays visible in an own-block view at nesting
    `depth`, and the depth after it. The block's own text and the braces of
    its direct children stay visible; everything deeper is blanked."""
    if character == "{":
        return depth + 1 <= 2, depth + 1
    if character == "}":
        return depth <= 2, depth - 1
    return depth == 1, depth


def own_block_text(masked: str, open_brace: int) -> str:
    """Text of the block opened at `open_brace`, with the contents of nested
    blocks blanked. Character i of the result is masked[open_brace + i], so
    offsets map back to the source."""
    depth = 0
    own = []
    for index in range(open_brace, len(masked)):
        character = masked[index]
        visible, depth = brace_visibility(character, depth)
        own.append(character if visible or character == "\n" else " ")
        if depth == 0:
            break
    return "".join(own)


def enclosing_open_brace(masked: str, offset: int) -> int:
    """Offset of the innermost unclosed `{` before `offset`, or -1."""
    depth = 0
    for index in range(offset - 1, -1, -1):
        character = masked[index]
        if character == "}":
            depth += 1
        elif character == "{":
            if depth == 0:
                return index
            depth -= 1
    return -1


def binding_value(masked: str, start: int) -> tuple[str, bool]:
    """The value of a binding that starts at `start`, up to the end of its
    line, a `;` or a `}`, and whether it continues on the next line."""
    end = start
    while end < len(masked) and masked[end] not in "\n;}":
        end += 1
    return masked[start:end].strip(), bool(CONTINUATION_PATTERN.match(masked, end))


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def violation(label: str, source: str, offset: int, message: str) -> str:
    return f"{label}:{line_number(source, offset)}: {message}\n{REMEDIATION}"


class GateScan:
    """One file under the gate: the raw source and its masked copy."""

    def __init__(self, source: str, label: str):
        self.source = source
        self.masked = mask_source(source)
        self.label = label
        self.violations: list[str] = []

    def report(self, offset: int, message: str) -> None:
        self.violations.append(violation(self.label, self.source, offset, message))

    def check_declarations(self) -> None:
        for match in ELEMENT_PATTERN.finditer(self.masked):
            own = own_block_text(self.masked, match.end() - 1)
            if not TEXT_FORMAT_KEY_PATTERN.search(own):
                self.report(match.start(), f"{match.group(1)} element without an explicit textFormat")

    def exemption_function(self, offset: int) -> str:
        """The escaping function named by a marker on the line of `offset`
        or on the line above it, or ""."""
        line_start = self.source.rfind("\n", 0, offset) + 1
        previous_start = self.source.rfind("\n", 0, max(line_start - 1, 0)) + 1
        line_end = self.source.find("\n", offset)
        window = self.source[previous_start:len(self.source) if line_end == -1 else line_end]
        match = EXEMPTION_MARKER_PATTERN.search(window)
        return match.group(1) if match else ""

    def exemption_holds(self, offset: int) -> bool:
        function_name = self.exemption_function(offset)
        open_brace = enclosing_open_brace(self.masked, offset)
        if not function_name or open_brace == -1:
            return False
        own = own_block_text(self.masked, open_brace)
        return re.search(r"(?<![\w$])" + re.escape(function_name) + r"\s*\(", own) is not None

    def check_value(self, offset: int, value: str, continued: bool) -> None:
        if continued:
            self.report(offset, f"textFormat binding continues past `{value}`; bind the PlainText literal only")
        elif EXEMPTIBLE_VALUE_PATTERN.fullmatch(value):
            if not self.exemption_holds(offset):
                self.report(offset, f"textFormat: {value} without a text-format-exemption marker naming an escaping function called in this element")
        elif not PLAIN_TEXT_VALUE_PATTERN.fullmatch(value):
            self.report(offset, f"textFormat bound to `{value}`; only Text.PlainText or TextEdit.PlainText is allowed")

    def check_values(self) -> None:
        for match in TEXT_FORMAT_KEY_PATTERN.finditer(self.masked):
            value, continued = binding_value(self.masked, match.end())
            self.check_value(match.start(), value, continued)

    def check_runtime_changes(self) -> None:
        for match in TEXT_FORMAT_ASSIGNMENT_PATTERN.finditer(self.masked):
            self.report(match.start(), "textFormat assigned at runtime; declare Text.PlainText as a binding instead")
        for match in TEXT_FORMAT_STRING_PATTERN.finditer(self.source):
            if self.masked[match.start()] == " ":
                self.report(match.start(), "textFormat named in a string (dynamic property access or Binding)")

    def has_literal_binding(self, own: str, open_brace: int, key_pattern: re.Pattern) -> bool:
        match = key_pattern.search(own)
        return bool(match) and bool(STRING_LITERAL_BINDING_PATTERN.match(self.source, open_brace + match.end()))

    def check_tooltip_elements(self) -> None:
        for match in TOOLTIP_ELEMENT_PATTERN.finditer(self.masked):
            open_brace = match.end() - 1
            own = own_block_text(self.masked, open_brace)
            if self.has_literal_binding(own, open_brace, TOOLTIP_TEXT_KEY_PATTERN) or PLAIN_CONTENT_ITEM_PATTERN.search(own):
                continue
            self.report(match.start(), "ToolTip with dynamic text and no PlainText contentItem (the default content item is AutoText)")

    def check_attached_tooltips(self) -> None:
        for match in ATTACHED_TOOLTIP_TEXT_PATTERN.finditer(self.masked):
            if not STRING_LITERAL_BINDING_PATTERN.match(self.source, match.end()):
                self.report(match.start(), "attached ToolTip.text with dynamic text (shown through the AutoText tooltip)")
        for match in ATTACHED_TOOLTIP_SHOW_PATTERN.finditer(self.masked):
            if not STRING_LITERAL_ARGUMENT_PATTERN.match(self.source, match.end()):
                self.report(match.start(), "ToolTip.show() with dynamic text (shown through the AutoText tooltip)")

    def run(self) -> list[str]:
        self.check_declarations()
        self.check_values()
        self.check_runtime_changes()
        self.check_tooltip_elements()
        self.check_attached_tooltips()
        return self.violations


def find_violations(source: str, label: str) -> list[str]:
    return GateScan(source, label).run()


def scan_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        return find_violations(handle.read(), os.path.relpath(path, ROOT_DIR))


def target_files() -> list[str]:
    files = [os.path.join(ROOT_DIR, "OmarchyBitwarden.qml")]
    files.extend(sorted(glob.glob(os.path.join(ROOT_DIR, "components", "*.qml"))))
    return [path for path in files if os.path.isfile(path)]


SELF_TEST_CASES = [
    ("missing textFormat fails", "Item { Text { text: name } }", 1),
    ("explicit PlainText passes", "Item { Text { textFormat: Text.PlainText; text: name } }", 0),
    ("Label, TextEdit and TextArea are guarded", "Item { Label { text: a }\n TextEdit { text: b }\n TextArea { text: c } }", 3),
    ("TextInput and TextField are not guarded", "Item { TextInput { text: a }\n TextField { text: b } }", 0),
    ("qualified element is guarded", "Item { Controls.Label { text: a } }", 1),
    ("nested child textFormat does not count",
     "Text { text: a\n MouseArea { Text { textFormat: Text.PlainText } } }", 1),
    ("comments and strings are ignored",
     "Item {\n // Text { text: a }\n /* Label { } */\n property string s: \"Text { x }\" }", 0),
    ("regex literal with quotes does not derail matching",
     "Item {\n function f(s) { return s.replace(/(\"a\"|\"b\")\\s*:\\s*\"[^\"]*\"/g, '{') }\n"
     " Text { text: \"}\" }\n}", 1),
    ("textFormat after a nested block still counts",
     "Text { MouseArea { anchors.fill: parent }\n textFormat: Text.PlainText }", 0),
    ("enum reference is not an element", "Item { property int f: Text.PlainText }", 0),
    ("regex after return keeps its quotes masked",
     "Item {\n function f(s) { return /\"[^\"]*/.test(s) }\n Text { text: \"{\" }\n}", 1),
    ("division is not a regex", "Item {\n property real r: a / b / c\n Text { text: \"x\" } }", 1),
    ("slash inside a regex character class does not end the literal",
     "Item {\n function f(s) { return /[/]Text { /.test(s) }\n Text { textFormat: Text.PlainText }\n}", 0),
    # Rule 2: the value must be the PlainText literal.
    ("TextEdit.PlainText passes", "Item { TextEdit { textFormat: TextEdit.PlainText; text: a } }", 0),
    ("bound variable value fails", "Item { property int fmt: Text.PlainText\n Text { textFormat: fmt; text: a } }", 1),
    ("Text.AutoText fails", "Item { Text { textFormat: Text.AutoText; text: a } }", 1),
    ("TextArea with RichText fails", "Item { TextArea { textFormat: TextEdit.RichText; text: a } }", 1),
    ("Label with StyledText fails", "Item { Label { textFormat: Text.StyledText; text: a } }", 1),
    ("MarkdownText fails", "Item { Text { textFormat: Text.MarkdownText; text: a } }", 1),
    ("conditional value fails", "Item { Text { textFormat: rich ? Text.RichText : Text.PlainText } }", 1),
    ("value continued on the next line fails", "Item { Text { textFormat: Text.PlainText\n    + Text.RichText } }", 1),
    ("trailing comment after PlainText passes", "Item { Text { textFormat: Text.PlainText // plain\n text: a } }", 0),
    ("RichText with a marker naming an escaping function it calls passes",
     "Item { TextEdit {\n // text-format-exemption: RichText escaped by escapeMarkup\n textFormat: TextEdit.RichText\n"
     " text: escapeMarkup(value) } }", 0),
    ("RichText with a marker on the same line passes",
     "Item { TextEdit { textFormat: TextEdit.RichText // text-format-exemption: RichText escaped by escapeMarkup\n"
     " text: escapeMarkup(value) } }", 0),
    ("RichText with a marker naming a function it does not call fails",
     "Item { TextEdit {\n // text-format-exemption: RichText escaped by escapeMarkup\n textFormat: TextEdit.RichText\n"
     " text: value } }", 1),
    ("RichText whose escaping call is only in a nested child fails",
     "Item { TextEdit {\n // text-format-exemption: RichText escaped by escapeMarkup\n textFormat: TextEdit.RichText\n"
     " text: value\n Item { property string x: escapeMarkup(value) } } }", 1),
    ("RichText without a marker fails", "Item { TextEdit { textFormat: TextEdit.RichText; text: escapeMarkup(value) } }", 1),
    ("a marker two lines above does not count",
     "Item { TextEdit {\n // text-format-exemption: RichText escaped by escapeMarkup\n\n textFormat: TextEdit.RichText\n"
     " text: escapeMarkup(value) } }", 1),
    ("a marker does not exempt AutoText",
     "Item { Text {\n // text-format-exemption: RichText escaped by escapeMarkup\n textFormat: Text.AutoText\n"
     " text: escapeMarkup(value) } }", 1),
    # Rule 3: no runtime change, no dynamic property name.
    ("runtime assignment in onCompleted fails",
     "Item { Text { id: label; textFormat: Text.PlainText }\n Component.onCompleted: label.textFormat = Text.RichText }", 1),
    ("runtime assignment in a handler block fails",
     "Item { Text { textFormat: Text.PlainText\n Component.onCompleted: { textFormat = Text.RichText } } }", 1),
    ("compound assignment fails", "Item { function f() { label.textFormat |= 1 } }", 1),
    ("comparison is not an assignment", "Item { property bool rich: label.textFormat === Text.RichText }", 0),
    ("Binding on textFormat fails", "Item { Binding { target: label; property: \"textFormat\"; value: Text.RichText } }", 1),
    ("bracket access to textFormat fails", "Item { function f() { label[\"textFormat\"] = 1 } }", 1),
    ("textFormat inside a comment is ignored", "Item {\n // label.textFormat = Text.RichText\n}", 0),
    # Rules 4 and 5: tooltips.
    ("ToolTip with dynamic text fails", "Item { ToolTip { text: item.name } }", 1),
    ("ToolTip with literal text passes", "Item { ToolTip { text: \"Copy\" } }", 0),
    ("ToolTip with concatenated literal fails", "Item { ToolTip { text: \"Copy \" + item.name } }", 1),
    ("ToolTip without text fails", "Item { ToolTip { id: tip } }", 1),
    ("ToolTip with a PlainText contentItem passes",
     "Item { ToolTip { id: tip; text: item.name\n contentItem: Text { textFormat: Text.PlainText; text: tip.text } } }", 0),
    ("ToolTip with an AutoText contentItem fails",
     "Item { ToolTip { id: tip; text: item.name\n contentItem: Text { textFormat: Text.AutoText; text: tip.text } } }", 1),
    ("ToolTip with a non-text contentItem fails",
     "Item { ToolTip { text: item.name\n contentItem: Item { } } }", 1),
    ("qualified ToolTip is guarded", "Item { Controls.ToolTip { text: item.name } }", 1),
    ("attached ToolTip.text with dynamic text fails", "Item { ToolTip.visible: hovered\n ToolTip.text: item.name }", 1),
    ("attached ToolTip.text with a literal passes", "Item { ToolTip.visible: hovered\n ToolTip.text: \"Copy\" }", 0),
    ("ToolTip.show with dynamic text fails", "Item { function f() { ToolTip.show(item.name) } }", 1),
    ("ToolTip.show with a literal passes", "Item { function f() { ToolTip.show(\"Copied\", 1000) } }", 0),
]


def run_self_tests() -> bool:
    failures = 0
    for description, source, expected in SELF_TEST_CASES:
        found = len(find_violations(source, "fixture.qml"))
        if found != expected:
            failures += 1
            print(f"FAIL: {description}: expected {expected} violation(s), found {found}")
    if failures:
        print(f"FAILED: {failures} of {len(SELF_TEST_CASES)} check-qml-text-format self-tests.")
        return False
    print(f"PASS: check-qml-text-format self-tests ({len(SELF_TEST_CASES)} fixture checks succeeded).")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="QML Plain-Text Gate")
    parser.add_argument("--self-test", action="store_true", help="Run fixture test suite")
    args = parser.parse_args()

    if args.self_test:
        return 0 if run_self_tests() else 1

    print("=== Checking QML Text Sinks Are Plain Text (Plugin UI Safety) ===")
    files = target_files()
    violations = [violation for path in files for violation in scan_file(path)]
    if violations:
        for violation in violations:
            print(f"  ✗ {violation}\n")
        print(f"FAILED: {len(violations)} plain-text rule violation(s).")
        return 1
    print(f"PASSED: {len(files)} QML files scanned; every Text, Label, TextEdit and TextArea is plain text, and no ToolTip renders dynamic text as AutoText.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
