"""
AST Analyzer — Performs Python AST-based analysis on script files.

Extracts a ScriptContext dataclass with:
- imports (modules, from-imports)
- function definitions
- class definitions
- global variables
- function calls (especially dangerous ones)
- string literals (URLs, IPs, paths)
- exec/eval/compile usage
- subprocess/os.system calls
- file I/O operations
- network operations
- environment variable access

Then runs security checks based on the extracted context.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding


@dataclass
class ImportInfo:
    """An import statement."""
    module: str
    names: List[str]  # imported names; empty for plain `import X`
    alias: Optional[str] = None
    line: int = 0


@dataclass
class FunctionCallInfo:
    """A function/method call."""
    name: str           # e.g. "os.system", "eval", "requests.get"
    args_count: int = 0
    has_kwargs: bool = False
    line: int = 0
    col: int = 0


@dataclass
class FileIOInfo:
    """A file I/O operation."""
    operation: str  # "open", "read", "write", "Path"
    mode: Optional[str] = None
    line: int = 0


@dataclass
class ScriptContext:
    """Extracted context from a Python script AST."""
    imports: List[ImportInfo] = field(default_factory=list)
    function_defs: List[str] = field(default_factory=list)
    class_defs: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    dangerous_calls: List[FunctionCallInfo] = field(default_factory=list)
    all_calls: List[FunctionCallInfo] = field(default_factory=list)
    string_literals: List[str] = field(default_factory=list)
    file_operations: List[FileIOInfo] = field(default_factory=list)
    env_accesses: List[str] = field(default_factory=list)
    network_modules: Set[str] = field(default_factory=set)
    exec_eval_usage: List[FunctionCallInfo] = field(default_factory=list)
    subprocess_calls: List[FunctionCallInfo] = field(default_factory=list)
    has_try_except: bool = False
    has_async: bool = False
    total_lines: int = 0
    parse_errors: List[str] = field(default_factory=list)


# Modules considered dangerous or security-sensitive
DANGEROUS_MODULES = {
    "os", "subprocess", "shutil", "ctypes", "pickle", "marshal",
    "shelve", "tempfile", "socket", "http", "urllib", "requests",
    "httpx", "aiohttp", "paramiko", "ftplib", "smtplib", "telnetlib",
}

NETWORK_MODULES = {
    "socket", "http", "urllib", "requests", "httpx", "aiohttp",
    "paramiko", "ftplib", "smtplib", "telnetlib", "websocket",
    "websockets", "grpc", "xmlrpc",
}

DANGEROUS_FUNCTIONS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawn", "os.spawnl", "os.spawnle",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
    "shelve.open",
}


class ASTExtractor(ast.NodeVisitor):
    """Walks Python AST and extracts ScriptContext."""

    def __init__(self):
        self.context = ScriptContext()
        self._current_scope: List[str] = []

    def extract(self, source: str) -> ScriptContext:
        """Parse source and extract context."""
        self.context.total_lines = source.count("\n") + 1
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            self.context.parse_errors.append(f"SyntaxError: {e}")
            return self.context

        self.visit(tree)
        return self.context

    # ------- Imports -------
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            imp = ImportInfo(
                module=alias.name,
                names=[],
                alias=alias.asname,
                line=node.lineno,
            )
            self.context.imports.append(imp)
            top_module = alias.name.split(".")[0]
            if top_module in NETWORK_MODULES:
                self.context.network_modules.add(top_module)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        names = [a.name for a in node.names] if node.names else []
        imp = ImportInfo(module=module, names=names, line=node.lineno)
        self.context.imports.append(imp)
        top_module = module.split(".")[0]
        if top_module in NETWORK_MODULES:
            self.context.network_modules.add(top_module)
        self.generic_visit(node)

    # ------- Definitions -------
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.context.function_defs.append(node.name)
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.context.function_defs.append(node.name)
        self.context.has_async = True
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef):
        self.context.class_defs.append(node.name)
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    # ------- Assignments -------
    def visit_Assign(self, node: ast.Assign):
        if not self._current_scope:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.context.global_vars.append(target.id)
        self.generic_visit(node)

    # ------- Function calls -------
    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node.func)
        if call_name:
            call_info = FunctionCallInfo(
                name=call_name,
                args_count=len(node.args),
                has_kwargs=bool(node.keywords),
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
            )
            self.context.all_calls.append(call_info)

            # Classify
            if call_name in DANGEROUS_FUNCTIONS or any(
                call_name.startswith(d) for d in DANGEROUS_FUNCTIONS
            ):
                self.context.dangerous_calls.append(call_info)

            if call_name in ("eval", "exec", "compile"):
                self.context.exec_eval_usage.append(call_info)

            if call_name.startswith("subprocess.") or call_name in (
                "os.system", "os.popen"
            ):
                self.context.subprocess_calls.append(call_info)

            # File I/O
            if call_name == "open":
                mode = self._extract_open_mode(node)
                self.context.file_operations.append(
                    FileIOInfo(operation="open", mode=mode, line=getattr(node, "lineno", 0))
                )

            # Env access
            if call_name in ("os.environ.get", "os.getenv"):
                self.context.env_accesses.append(
                    self._extract_first_string_arg(node) or "unknown"
                )

        self.generic_visit(node)

    # ------- String literals -------
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and len(node.value) > 3:
            self.context.string_literals.append(node.value)
        self.generic_visit(node)

    # ------- Try/Except -------
    def visit_Try(self, node: ast.Try):
        self.context.has_try_except = True
        self.generic_visit(node)

    # ------- Helpers -------
    def _get_call_name(self, node) -> Optional[str]:
        """Extract dotted call name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_call_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return None

    def _extract_open_mode(self, node: ast.Call) -> Optional[str]:
        """Extract the mode argument from an open() call."""
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant):
                return str(mode_arg.value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return None

    def _extract_first_string_arg(self, node: ast.Call) -> Optional[str]:
        """Extract the first string argument."""
        if node.args and isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        return None


class PythonASTAnalyzer:
    """Runs security analysis using the extracted AST context."""

    def __init__(self):
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a Python script component using AST."""
        self.findings = []

        content = component.content
        if not content:
            return self.findings

        language = component.metadata.get("language", "unknown")
        if language != "python":
            return self.findings

        extractor = ASTExtractor()
        ctx = extractor.extract(content)

        if ctx.parse_errors:
            self.findings.append(SecurityFinding(
                severity="low",
                rule_id="ast-parse-error",
                rule_name="AST Parse Error",
                message=f"Could not fully parse Python AST: {ctx.parse_errors[0]}",
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                recommendation="Ensure valid Python syntax for complete analysis",
            ))

        # Run checks
        self._check_dangerous_imports(ctx, component)
        self._check_exec_eval(ctx, component)
        self._check_subprocess(ctx, component)
        self._check_file_operations(ctx, component)
        self._check_network_with_file_io(ctx, component)
        self._check_env_access(ctx, component)
        self._check_suspicious_strings(ctx, component)
        self._check_bare_except(ctx, component, content)

        return self.findings

    def _check_dangerous_imports(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag imports of dangerous modules."""
        for imp in ctx.imports:
            top = imp.module.split(".")[0]
            if top in DANGEROUS_MODULES:
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="ast-dangerous-import",
                    rule_name="Dangerous Module Import",
                    message=f"Imports security-sensitive module: {imp.module}",
                    component_type=comp.type,
                    component_name=comp.name,
                    component_path=comp.path,
                    line=imp.line,
                    recommendation=f"Review usage of '{imp.module}'; ensure it is necessary and safe",
                ))

    def _check_exec_eval(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag eval/exec/compile usage."""
        for call in ctx.exec_eval_usage:
            self.findings.append(SecurityFinding(
                severity="critical",
                rule_id="ast-exec-eval",
                rule_name="Dynamic Code Execution",
                message=f"{call.name}() called at line {call.line} — arbitrary code execution risk",
                component_type=comp.type,
                component_name=comp.name,
                component_path=comp.path,
                line=call.line,
                recommendation=f"Remove {call.name}() or replace with a safer alternative",
            ))

    def _check_subprocess(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag subprocess / os.system calls."""
        for call in ctx.subprocess_calls:
            shell_risk = "shell=True" if call.has_kwargs else ""
            severity = "critical" if "system" in call.name or "popen" in call.name else "high"
            self.findings.append(SecurityFinding(
                severity=severity,
                rule_id="ast-subprocess",
                rule_name="Subprocess Execution",
                message=f"{call.name}() called at line {call.line}{' (may use ' + shell_risk + ')' if shell_risk else ''}",
                component_type=comp.type,
                component_name=comp.name,
                component_path=comp.path,
                line=call.line,
                recommendation="Avoid shell=True; validate all command arguments; prefer subprocess.run with explicit args list",
            ))

    def _check_file_operations(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag file write operations."""
        for fio in ctx.file_operations:
            if fio.mode and any(m in fio.mode for m in ("w", "a", "x")):
                self.findings.append(SecurityFinding(
                    severity="medium",
                    rule_id="ast-file-write",
                    rule_name="File Write Operation",
                    message=f"File opened in write mode ('{fio.mode}') at line {fio.line}",
                    component_type=comp.type,
                    component_name=comp.name,
                    component_path=comp.path,
                    line=fio.line,
                    recommendation="Validate file paths; avoid writing to system directories",
                ))

    def _check_network_with_file_io(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag when network modules are used together with file I/O (data exfil indicator)."""
        if ctx.network_modules and ctx.file_operations:
            self.findings.append(SecurityFinding(
                severity="high",
                rule_id="ast-network-file-combo",
                rule_name="Network + File I/O Combination",
                message=f"Script imports network modules ({', '.join(ctx.network_modules)}) and performs file I/O — potential data exfiltration",
                component_type=comp.type,
                component_name=comp.name,
                component_path=comp.path,
                recommendation="Review whether file contents are transmitted over the network",
            ))

    def _check_env_access(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag access to sensitive environment variables."""
        sensitive_patterns = {"key", "secret", "token", "password", "credential", "auth"}
        for env_var in ctx.env_accesses:
            lower = env_var.lower()
            if any(p in lower for p in sensitive_patterns):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="ast-sensitive-env",
                    rule_name="Sensitive Environment Variable Access",
                    message=f"Accesses potentially sensitive environment variable: {env_var}",
                    component_type=comp.type,
                    component_name=comp.name,
                    component_path=comp.path,
                    recommendation="Ensure sensitive environment variables are not leaked or logged",
                ))

    def _check_suspicious_strings(self, ctx: ScriptContext, comp: PluginComponent) -> None:
        """Flag suspicious string literals (IPs, hardcoded credentials, URLs with user/pass)."""
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        cred_pattern = re.compile(r"(?:password|passwd|secret|api_key|apikey)\s*[=:]\s*.+", re.IGNORECASE)
        auth_url_pattern = re.compile(r"https?://[^@\s]+:[^@\s]+@")

        for s in ctx.string_literals:
            if auth_url_pattern.search(s):
                self.findings.append(SecurityFinding(
                    severity="critical",
                    rule_id="ast-hardcoded-cred-url",
                    rule_name="Hardcoded Credentials in URL",
                    message=f"URL contains embedded credentials: {s[:60]}...",
                    component_type=comp.type,
                    component_name=comp.name,
                    component_path=comp.path,
                    recommendation="Never embed credentials in URLs; use environment variables or secrets management",
                ))
            elif cred_pattern.search(s):
                self.findings.append(SecurityFinding(
                    severity="high",
                    rule_id="ast-hardcoded-credential",
                    rule_name="Potential Hardcoded Credential",
                    message=f"String contains credential-like pattern: '{s[:40]}...'",
                    component_type=comp.type,
                    component_name=comp.name,
                    component_path=comp.path,
                    recommendation="Use environment variables or secrets management instead of hardcoded credentials",
                ))

    def _check_bare_except(
        self, ctx: ScriptContext, comp: PluginComponent, content: str
    ) -> None:
        """Flag bare except clauses that could hide security errors."""
        if not ctx.has_try_except:
            return
        # Quick regex check for bare except
        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            if stripped == "except:" or stripped.startswith("except Exception"):
                if any(c.name in ("eval", "exec", "subprocess") for c in ctx.dangerous_calls):
                    self.findings.append(SecurityFinding(
                        severity="medium",
                        rule_id="ast-bare-except-dangerous",
                        rule_name="Bare Except with Dangerous Code",
                        message=f"Bare except clause at line {i} may silently catch errors from dangerous operations",
                        component_type=comp.type,
                        component_name=comp.name,
                        component_path=comp.path,
                        line=i,
                        recommendation="Use specific exception types; don't silently catch errors from dangerous operations",
                    ))
                    break  # One finding is enough
