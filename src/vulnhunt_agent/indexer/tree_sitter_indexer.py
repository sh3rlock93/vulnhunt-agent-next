"""Tree-sitter based indexer. Currently supports Python; extend by adding languages."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import tree_sitter_c
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from .base import FileIndex, RepoIndex, Symbol


_JS_LANG = Language(tree_sitter_javascript.language())
_TS_LANG = Language(tree_sitter_typescript.language_typescript())
_TSX_LANG = Language(tree_sitter_typescript.language_tsx())

_LANGUAGES = {
    "py":   ("python",     Language(tree_sitter_python.language())),
    "c":    ("c",          Language(tree_sitter_c.language())),
    "h":    ("c",          Language(tree_sitter_c.language())),
    "js":   ("javascript", _JS_LANG),
    "mjs":  ("javascript", _JS_LANG),
    "cjs":  ("javascript", _JS_LANG),
    "jsx":  ("javascript", _JS_LANG),
    "ts":   ("typescript", _TS_LANG),
    "tsx":  ("typescript", _TSX_LANG),
    "java": ("java",       Language(tree_sitter_java.language())),
}


@dataclass(frozen=True)
class CFunctionRegion:
    """A normal or conservatively recovered C function definition."""

    container: Node
    declarator: Node
    body_nodes: tuple[Node, ...]
    line: int
    end_line: int
    start_byte: int
    recovered: bool = False


class TreeSitterIndexer:
    def __init__(self):
        self._parsers: dict[str, Parser] = {
            ext: Parser(lang) for ext, (_, lang) in _LANGUAGES.items()
        }

    def supports(self, path: Path) -> bool:
        return path.suffix.lstrip(".") in _LANGUAGES

    def index_repo(self, repo: Path, files: list[str]) -> RepoIndex:
        indexes: list[FileIndex] = []
        for rel in files:
            path = repo / rel
            if not self.supports(path):
                continue
            try:
                fi = self._index_file(repo, rel)
                indexes.append(fi)
            except Exception:
                continue
        return RepoIndex(files=indexes)

    def _index_file(self, repo: Path, rel: str) -> FileIndex:
        ext = Path(rel).suffix.lstrip(".")
        lang_name, _ = _LANGUAGES[ext]
        parser = self._parsers[ext]

        source = (repo / rel).read_bytes()
        tree = parser.parse(source)
        root = tree.root_node

        imports: list[str] = []
        symbols: list[Symbol] = []

        if lang_name == "python":
            _walk_python(root, source, imports, symbols)
        elif lang_name == "c":
            _walk_c(root, source, imports, symbols)
        elif lang_name in ("javascript", "typescript"):
            _walk_js_ts(root, source, imports, symbols)
        elif lang_name == "java":
            _walk_java(root, source, imports, symbols)

        return FileIndex(
            path=rel,
            language=lang_name,
            loc=source.count(b"\n") + 1,
            imports=imports,
            symbols=symbols,
        )


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def c_function_regions(root: Node, source: bytes) -> tuple[CFunctionRegion, ...]:
    """Return function regions, including strict recovery from parse errors.

    Some macro-decorated declarations are represented as a top-level ERROR
    whose direct children still contain a function declarator, body statements,
    and an isolated closing brace. Recovery requires all three structural
    anchors so an arbitrary expression or prototype cannot become a function.
    """
    regions: list[CFunctionRegion] = []
    normal_ranges: list[tuple[int, int]] = []
    for node in _walk_nodes(root):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        body = node.child_by_field_name("body")
        if declarator is None or body is None:
            continue
        regions.append(CFunctionRegion(
            container=node,
            declarator=declarator,
            body_nodes=(body,),
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_byte=node.start_byte,
        ))
        normal_ranges.append((node.start_byte, node.end_byte))

    for node in _walk_nodes(root):
        if node.type != "ERROR" or any(
            start <= node.start_byte and node.end_byte <= end
            for start, end in normal_ranges
        ):
            continue
        children = tuple(node.named_children)
        for index, declarator in enumerate(children):
            if declarator.type != "function_declarator":
                continue
            closing = next(
                (
                    position
                    for position in range(index + 1, len(children))
                    if children[position].type == "ERROR"
                    and _text(children[position], source).strip() == "}"
                ),
                None,
            )
            if closing is None:
                continue
            body_nodes = children[index + 1 : closing]
            next_start = (
                body_nodes[0].start_byte
                if body_nodes else children[closing].start_byte
            )
            if b"{" not in source[declarator.end_byte:next_start]:
                continue
            regions.append(CFunctionRegion(
                container=node,
                declarator=declarator,
                body_nodes=body_nodes,
                line=node.start_point[0] + 1,
                end_line=children[closing].end_point[0] + 1,
                start_byte=node.start_byte,
                recovered=True,
            ))
            break

    unique = {
        (region.declarator.start_byte, region.declarator.end_byte): region
        for region in regions
    }
    return tuple(sorted(
        unique.values(),
        key=lambda item: (item.line, item.declarator.start_byte),
    ))


def _walk_nodes(root: Node):
    yield root
    for child in root.children:
        yield from _walk_nodes(child)


def _walk_python(node: Node, source: bytes, imports: list[str], symbols: list[Symbol],
                 parent_class: str = "") -> None:
    for child in node.children:
        t = child.type

        if t == "import_statement":
            for n in child.children:
                if n.type == "dotted_name":
                    imports.append(_text(n, source))

        elif t == "import_from_statement":
            module = ""
            for n in child.children:
                if n.type == "dotted_name" and not module:
                    module = _text(n, source)
                    break
            if module:
                imports.append(module)

        elif t == "function_definition":
            name = _field_text(child, "name", source)
            params = _field_text(child, "parameters", source) or "()"
            sig = f"def {name}{params}"
            kind: Literal["method", "function"] = "method" if parent_class else "function"
            symbols.append(Symbol(
                name=name, kind=kind, line=child.start_point[0] + 1,
                signature=sig, parent=parent_class,
            ))

        elif t == "class_definition":
            cls_name = _field_text(child, "name", source)
            symbols.append(Symbol(
                name=cls_name, kind="class", line=child.start_point[0] + 1,
                signature=f"class {cls_name}",
            ))
            body = child.child_by_field_name("body")
            if body:
                _walk_python(body, source, imports, symbols, parent_class=cls_name)
            continue  # don't recurse twice

        _walk_python(child, source, imports, symbols, parent_class)


def _field_text(node: Node, field: str, source: bytes) -> str:
    n = node.child_by_field_name(field)
    return _text(n, source) if n else ""


def _walk_c(node: Node, source: bytes, imports: list[str], symbols: list[Symbol]) -> None:
    """Extract #include paths and function/typedef/struct names from C source."""
    for child in node.children:
        t = child.type

        if t == "preproc_include":
            for n in child.children:
                if n.type in ("system_lib_string", "string_literal"):
                    imports.append(_text(n, source).strip('<>"'))

        elif t == "function_definition":
            declarator = child.child_by_field_name("declarator")
            name = _c_function_name(declarator, source) if declarator else ""
            if name:
                sig = _text(declarator, source).splitlines()[0] if declarator else name
                symbols.append(Symbol(
                    name=name, kind="function",
                    line=child.start_point[0] + 1, signature=sig[:200],
                ))

        elif t == "declaration":
            # extern function prototypes at file scope
            declarator = child.child_by_field_name("declarator")
            name = _c_function_name(declarator, source) if declarator else ""
            if name and declarator and declarator.type == "function_declarator":
                symbols.append(Symbol(
                    name=name, kind="function",
                    line=child.start_point[0] + 1,
                    signature=_text(declarator, source)[:200],
                ))

        elif t in ("struct_specifier", "union_specifier", "enum_specifier"):
            name_node = child.child_by_field_name("name")
            if name_node:
                symbols.append(Symbol(
                    name=_text(name_node, source), kind="class",
                    line=child.start_point[0] + 1,
                    signature=f"{t.split('_')[0]} {_text(name_node, source)}",
                ))

        elif t == "type_definition":
            name_node = child.child_by_field_name("declarator")
            if name_node:
                nm = _text(name_node, source).strip()
                symbols.append(Symbol(
                    name=nm, kind="class",
                    line=child.start_point[0] + 1,
                    signature=f"typedef {nm}",
                ))

        # Don't recurse into function bodies (keep symbol list focused on top level).

    existing = {
        (item.name, item.line)
        for item in symbols
        if item.kind == "function"
    }
    for region in c_function_regions(node, source):
        name = _c_function_name(region.declarator, source)
        if not name or (name, region.line) in existing:
            continue
        symbols.append(Symbol(
            name=name,
            kind="function",
            line=region.line,
            signature=_text(region.declarator, source).splitlines()[0][:200],
        ))


def _walk_js_ts(node: Node, source: bytes, imports: list[str], symbols: list[Symbol],
                parent_class: str = "") -> None:
    """Extract imports/requires and top-level function / class / exported symbols
    from JavaScript or TypeScript source. Only descends into module-level nodes
    (import statements and export declarations' inner decl) to avoid double-counting."""
    for child in node.children:
        t = child.type

        # import foo from 'x';  import { a } from 'x';  import 'x';
        if t == "import_statement":
            src = child.child_by_field_name("source")
            if src:
                imports.append(_text(src, source).strip("'\""))

        elif t == "export_statement":
            src = child.child_by_field_name("source")
            if src:
                imports.append(_text(src, source).strip("'\""))
            decl = child.child_by_field_name("declaration")
            if decl is not None:
                _handle_js_declaration(decl, source, imports, symbols, parent_class)

        elif t == "function_declaration":
            _extract_js_symbol(child, source, symbols, parent_class)

        elif t == "class_declaration":
            _emit_js_class(child, source, symbols)

        elif t in ("lexical_declaration", "variable_declaration"):
            # handle `const x = require(...)` and `const foo = () => {}`
            _collect_requires(child, source, imports)
            for d in child.children:
                if d.type == "variable_declarator":
                    _maybe_arrow_symbol(d, source, symbols, parent_class)


def _handle_js_declaration(decl: Node, source: bytes, imports: list[str],
                           symbols: list[Symbol], parent_class: str) -> None:
    t = decl.type
    if t == "function_declaration":
        _extract_js_symbol(decl, source, symbols, parent_class)
    elif t == "class_declaration":
        _emit_js_class(decl, source, symbols)
    elif t in ("lexical_declaration", "variable_declaration"):
        _collect_requires(decl, source, imports)
        for d in decl.children:
            if d.type == "variable_declarator":
                _maybe_arrow_symbol(d, source, symbols, parent_class)


def _emit_js_class(node: Node, source: bytes, symbols: list[Symbol]) -> None:
    name_node = node.child_by_field_name("name")
    cls_name = _text(name_node, source) if name_node else ""
    if not cls_name:
        return
    symbols.append(Symbol(
        name=cls_name, kind="class",
        line=node.start_point[0] + 1,
        signature=f"class {cls_name}",
    ))
    body = node.child_by_field_name("body")
    if body:
        for method in body.children:
            if method.type == "method_definition":
                _extract_js_symbol(method, source, symbols, cls_name)


def _collect_requires(decl: Node, source: bytes, imports: list[str]) -> None:
    # Find call_expression where callee is 'require' and argument is a string.
    def _visit(n: Node):
        if n.type == "call_expression":
            callee = n.child_by_field_name("function")
            if callee and _text(callee, source) == "require":
                args = n.child_by_field_name("arguments")
                if args and len(args.children) >= 2:
                    arg = args.children[1]
                    if arg.type == "string":
                        imports.append(_text(arg, source).strip("'\"`"))
        for c in n.children:
            _visit(c)
    _visit(decl)


def _extract_js_symbol(node: Node, source: bytes, symbols: list[Symbol],
                       parent_class: str) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        # method_definition uses field 'name' too; skip otherwise
        return
    name = _text(name_node, source)
    if not name:
        return
    params = node.child_by_field_name("parameters")
    params_text = _text(params, source) if params else "()"
    kind: Literal["method", "function"] = "method" if parent_class else "function"
    prefix = "method" if parent_class else "function"
    symbols.append(Symbol(
        name=name, kind=kind,
        line=node.start_point[0] + 1,
        signature=f"{prefix} {name}{params_text}"[:200],
        parent=parent_class,
    ))


def _maybe_arrow_symbol(declarator: Node, source: bytes, symbols: list[Symbol],
                        parent_class: str) -> None:
    name_node = declarator.child_by_field_name("name")
    value_node = declarator.child_by_field_name("value")
    if name_node is None or value_node is None:
        return
    if value_node.type not in ("arrow_function", "function_expression"):
        return
    name = _text(name_node, source)
    params = value_node.child_by_field_name("parameters")
    params_text = _text(params, source) if params else "()"
    symbols.append(Symbol(
        name=name, kind="function",
        line=declarator.start_point[0] + 1,
        signature=f"const {name} = {params_text} => ..."[:200],
        parent=parent_class,
    ))


def _walk_java(node: Node, source: bytes, imports: list[str], symbols: list[Symbol],
               parent_class: str = "") -> None:
    for child in node.children:
        t = child.type

        if t == "import_declaration":
            for n in child.children:
                if n.type in ("scoped_identifier", "identifier"):
                    imports.append(_text(n, source))
                    break

        elif t in ("class_declaration", "interface_declaration", "enum_declaration",
                   "record_declaration"):
            cls_name = _field_text(child, "name", source)
            if not cls_name:
                continue
            kind_word = t.split("_")[0]
            symbols.append(Symbol(
                name=cls_name, kind="class",
                line=child.start_point[0] + 1,
                signature=f"{kind_word} {cls_name}",
            ))
            body = child.child_by_field_name("body")
            if body:
                _walk_java(body, source, imports, symbols, parent_class=cls_name)

        elif t == "method_declaration":
            name = _field_text(child, "name", source)
            params = _field_text(child, "parameters", source) or "()"
            ret = _field_text(child, "type", source)
            sig = f"{ret} {name}{params}".strip() if ret else f"{name}{params}"
            symbols.append(Symbol(
                name=name, kind="method" if parent_class else "function",
                line=child.start_point[0] + 1,
                signature=sig[:200], parent=parent_class,
            ))

        elif t == "constructor_declaration":
            name = _field_text(child, "name", source)
            params = _field_text(child, "parameters", source) or "()"
            symbols.append(Symbol(
                name=name, kind="method",
                line=child.start_point[0] + 1,
                signature=f"{name}{params}"[:200], parent=parent_class,
            ))


def _c_function_name(declarator: Node | None, source: bytes) -> str:
    """Peel pointer/array wrappers until we hit the identifier."""
    if declarator is None:
        return ""
    cur = declarator
    while cur is not None:
        if cur.type == "identifier":
            return _text(cur, source)
        inner = cur.child_by_field_name("declarator")
        if inner is None:
            break
        cur = inner
    return ""
