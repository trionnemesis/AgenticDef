"""Boundaries and traceability of the evaluation layer (evals/SPEC.md, section 2).

Bracketed ids trace to requirement ids in evals/SPEC.md.
"""
import ast
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "evals" / "SPEC.md"
REQUIREMENT = re.compile(r"EV-[A-Z]+-\d{2}")


def imports(path):
    """Yield (top-level module, level, node) for every import statement in the file."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], 0, node
        elif isinstance(node, ast.ImportFrom):
            yield (node.module or "").split(".")[0], node.level, node


def test_runtime_never_imports_evals():
    """[EV-ARCH-01] No module under src/agenticdef imports evals, so semantic evaluation stays outside the runtime."""
    modules = sorted((ROOT / "src" / "agenticdef").rglob("*.py"))
    assert len(modules) >= 10
    for path in modules:
        for module, level, node in imports(path):
            assert module != "evals", f"{path} line {node.lineno}"
        assert not re.search(r"\bevals\b", path.read_text(encoding="utf-8")), path
    assert not (ROOT / "src" / "evals").exists()


def test_oracle_imports_only_the_standard_library():
    """[EV-ARCH-02] oracle.py has absolute stdlib imports only; no runtime, no third party, no dynamic import."""
    path = ROOT / "evals" / "oracle.py"
    seen = list(imports(path))
    assert seen, "oracle.py is expected to import something from the stdlib"
    for module, level, node in seen:
        assert level == 0, f"relative import at line {node.lineno}"
        assert module in sys.stdlib_module_names, f"{module} (line {node.lineno}) is not standard library"
        assert module not in {"importlib", "pkgutil", "runpy", "subprocess", "socket", "ctypes"}, module
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not called & {"__import__", "exec", "eval", "compile", "open"}, called


def test_oracle_does_not_reference_the_runtime_decision_logic():
    """[EV-ARCH-02] The required reads are written out in oracle.py, not borrowed from the runtime or the double."""
    names = {n.id for n in ast.walk(ast.parse((ROOT / "evals" / "oracle.py").read_text(encoding="utf-8")))
             if isinstance(n, ast.Name)}
    assert not names & {"required_requests", "requests_for", "ReplayModel", "FixtureTools", "Investigator"}


def test_evals_is_in_the_sdist_but_not_in_the_wheel():
    """[EV-ARCH-03] MANIFEST.in ships evals; pytest can import it; the wheel package list stays src-only."""
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    assert "recursive-include evals *.py *.json *.md" in manifest
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    assert "evals" not in project["tool"]["setuptools"].get("packages", {}).get("find", {}).get("include", [])
    assert project["tool"]["pytest"]["ini_options"]["pythonpath"] == ["src", "."]
    for name in ("__init__.py", "SPEC.md", "oracle.py", "cases.py", "runner.py", "schemas/case.schema.json",
                 "schemas/report.schema.json"):
        assert (ROOT / "evals" / name).is_file(), name


def test_evals_package_init_is_inert():
    """[EV-ARCH-02] Importing evals (or evals.oracle) must not pull in the runtime through the package __init__."""
    tree = ast.parse((ROOT / "evals" / "__init__.py").read_text(encoding="utf-8"))
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]


def _imports_live(node, level):
    """True if the import statement imports evals.live, absolutely or relatively."""
    if isinstance(node, ast.Import):
        return any(a.name == "evals.live" or a.name.startswith("evals.live.") for a in node.names)
    target, names = node.module or "", {a.name for a in node.names}
    if level == 0:
        return target == "evals.live" or target.startswith("evals.live.") or (target == "evals" and "live" in names)
    return level == 1 and (target == "live" or (target == "" and "live" in names))


def test_network_capability_is_confined_to_the_live_modules():
    """[EV-ARCH-04] Only live.py builds a network transport or imports AnthropicModel; httpx appears only in live.py,
    metering.py and runner.py (type checks); no other module imports evals.live; no shell, no exec."""
    forbidden = {"socket", "urllib", "http", "requests", "aiohttp", "anthropic", "kubernetes", "ssl"}
    httpx_allowed = {"live.py", "metering.py", "runner.py"}
    network_names = {"AsyncHTTPTransport", "HTTPTransport", "AsyncClient", "Client", "AnthropicModel"}
    for path in sorted((ROOT / "evals").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module, level, node in imports(path):
            assert module not in forbidden, f"{path.name} line {node.lineno}: {module}"
            if module == "httpx":
                assert path.name in httpx_allowed, f"{path.name} line {node.lineno}: httpx"
            if path.name != "live.py":
                assert not _imports_live(node, level), f"{path.name} line {node.lineno} imports evals.live"
        if path.name != "live.py":
            used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            used |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            used |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
            assert not used & network_names, f"{path.name}: {sorted(used & network_names)}"
        shell = [n for n in ast.walk(tree) if isinstance(n, ast.keyword) and n.arg == "shell"]
        assert not shell, path.name
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert not calls & {"exec", "eval", "compile"}, path.name


def test_every_spec_requirement_is_tested_and_every_test_reference_exists():
    """Traceability: SPEC.md is the single source the tests trace to, in both directions."""
    defined = set(re.findall(r"^- (EV-[A-Z]+-\d{2}):", SPEC.read_text(encoding="utf-8"), re.M))
    defined |= set(re.findall(r"^\| (EV-[A-Z]+-\d{2}) \|", SPEC.read_text(encoding="utf-8"), re.M))
    assert len(defined) >= 45
    referenced = set()
    for path in sorted((ROOT / "tests").glob("test_evals_*.py")):
        referenced |= set(REQUIREMENT.findall(path.read_text(encoding="utf-8")))
    assert referenced - defined == set(), f"tests cite unknown requirements: {sorted(referenced - defined)}"
    assert defined - referenced == set(), f"requirements without a test: {sorted(defined - referenced)}"
    areas = {i.split("-")[1] for i in defined}
    assert areas == {"ARCH", "ORC", "CAT", "CASE", "RUN", "REP", "GEN", "BASE", "MET", "LIVE"}
