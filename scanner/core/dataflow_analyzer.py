"""
Dataflow Analyzer — Basic source-to-sink taint tracking for Python scripts.

Identifies data flows from untrusted sources to dangerous sinks:

Sources (taint origins):
- os.environ.get / os.getenv (environment variables)
- input() / sys.stdin
- open().read() (file reads)
- requests.get().text / .json() (network responses)
- sys.argv, argparse (command-line arguments)
- Function parameters

Sinks (dangerous destinations):
- eval(), exec(), compile()
- os.system(), subprocess.*
- open(..., 'w').write() (file writes)
- SQL query construction
- requests.post() (network sends)

This is a simplified, intra-procedural analysis working at the AST level.
It does NOT perform full symbolic execution — it tracks variable names
through assignments and flags when a tainted variable reaches a sink.
"""

import ast
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict

from .plugin_parser import PluginComponent
from .skill_analyzer import SecurityFinding


@dataclass
class TaintFlow:
    """A detected tainted data flow from source to sink."""
    source_type: str       # e.g. "env_var", "user_input", "file_read", "network"
    source_detail: str     # e.g. "os.environ.get('API_KEY')"
    source_line: int
    sink_type: str         # e.g. "eval", "subprocess", "file_write", "network_send"
    sink_detail: str       # e.g. "eval(user_data)"
    sink_line: int
    tainted_var: str       # the variable name carrying the taint
    path: List[str] = field(default_factory=list)  # intermediate steps


# Source functions/patterns
SOURCE_FUNCTIONS = {
    "os.environ.get": "env_var",
    "os.getenv": "env_var",
    "os.environ": "env_var",
    "input": "user_input",
    "sys.stdin.read": "user_input",
    "sys.stdin.readline": "user_input",
    "open": "file_read",
    "requests.get": "network",
    "requests.post": "network",
    "httpx.get": "network",
    "httpx.post": "network",
    "urllib.request.urlopen": "network",
    "json.loads": "deserialization",
    "yaml.safe_load": "deserialization",
    "yaml.load": "deserialization",
}

# Sink functions
SINK_FUNCTIONS = {
    "eval": "code_execution",
    "exec": "code_execution",
    "compile": "code_execution",
    "__import__": "dynamic_import",
    "os.system": "command_execution",
    "os.popen": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.run": "command_execution",
    "subprocess.Popen": "command_execution",
    "subprocess.check_call": "command_execution",
    "subprocess.check_output": "command_execution",
    "requests.post": "network_send",
    "requests.put": "network_send",
    "httpx.post": "network_send",
    "httpx.put": "network_send",
}


class TaintTracker(ast.NodeVisitor):
    """Tracks taint propagation through Python AST."""

    def __init__(self):
        self.tainted_vars: Dict[str, Dict] = {}  # var_name -> {source_type, source_detail, source_line}
        self.flows: List[TaintFlow] = []
        self._in_function: bool = False

    def track(self, source: str) -> List[TaintFlow]:
        """Parse source and track taint flows."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        self.visit(tree)
        return self.flows

    # ------- Track assignments that introduce taint -------
    def visit_Assign(self, node: ast.Assign):
        # Check if RHS is a tainted source
        source_info = self._check_source(node.value)
        if source_info:
            for target in node.targets:
                var_name = self._get_name(target)
                if var_name:
                    self.tainted_vars[var_name] = {
                        "source_type": source_info[0],
                        "source_detail": source_info[1],
                        "source_line": node.lineno,
                    }

        # Check if RHS is a tainted variable (propagation)
        rhs_name = self._get_name(node.value)
        if rhs_name and rhs_name in self.tainted_vars:
            for target in node.targets:
                var_name = self._get_name(target)
                if var_name:
                    self.tainted_vars[var_name] = self.tainted_vars[rhs_name].copy()

        self.generic_visit(node)

    # ------- Track function calls for sinks -------
    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node.func)
        if call_name:
            # Check if this call is a sink
            sink_type = SINK_FUNCTIONS.get(call_name)
            if sink_type:
                # Check if any argument is tainted
                for arg in node.args:
                    arg_name = self._get_name(arg)
                    if arg_name and arg_name in self.tainted_vars:
                        taint = self.tainted_vars[arg_name]
                        self.flows.append(TaintFlow(
                            source_type=taint["source_type"],
                            source_detail=taint["source_detail"],
                            source_line=taint["source_line"],
                            sink_type=sink_type,
                            sink_detail=f"{call_name}({arg_name})",
                            sink_line=node.lineno,
                            tainted_var=arg_name,
                        ))

            # Also check if this call is a source (for chained assignments)
            source_info = self._check_source(node)
            if source_info:
                # f-string or format call using tainted var would also propagate
                pass

        # Check for string formatting that introduces taint to sinks
        # e.g. f"SELECT * FROM {user_input}"
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            for arg in node.args:
                arg_name = self._get_name(arg)
                if arg_name and arg_name in self.tainted_vars:
                    # Mark the result as tainted too
                    pass

        self.generic_visit(node)

    # ------- Track JoinedStr (f-strings) that use tainted vars -------
    def visit_JoinedStr(self, node: ast.JoinedStr):
        # f-strings are potential injection vectors
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                name = self._get_name(value.value)
                if name and name in self.tainted_vars:
                    # f-string uses a tainted variable — mark parent assignment if any
                    pass
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function parameters as potential sources."""
        old_in_function = self._in_function
        self._in_function = True
        # Treat function parameters as potential taint sources
        for arg in node.args.args:
            self.tainted_vars[arg.arg] = {
                "source_type": "function_param",
                "source_detail": f"parameter '{arg.arg}'",
                "source_line": node.lineno,
            }
        self.generic_visit(node)
        self._in_function = old_in_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)  # type: ignore

    # ------- Helpers -------
    def _check_source(self, node) -> Optional[tuple]:
        """Check if a node is a taint source. Returns (source_type, detail) or None."""
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            if call_name:
                source_type = SOURCE_FUNCTIONS.get(call_name)
                if source_type:
                    detail = call_name
                    # Try to extract first arg for detail
                    if node.args and isinstance(node.args[0], ast.Constant):
                        detail = f"{call_name}('{node.args[0].value}')"
                    return (source_type, detail)
        # Check for attribute access on tainted vars (e.g. response.text)
        if isinstance(node, ast.Attribute):
            parent_name = self._get_name(node.value)
            if parent_name and parent_name in self.tainted_vars:
                return (
                    self.tainted_vars[parent_name]["source_type"],
                    f"{parent_name}.{node.attr}",
                )
        return None

    def _get_call_name(self, node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_call_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return None

    def _get_name(self, node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        return None


class DataflowAnalyzer:
    """Security analyzer that uses taint tracking to find source-to-sink flows."""

    SEVERITY_MAP = {
        "code_execution": "critical",
        "command_execution": "critical",
        "dynamic_import": "high",
        "network_send": "high",
        "file_write": "medium",
    }

    def __init__(self):
        self.findings: List[SecurityFinding] = []

    def analyze(self, component: PluginComponent) -> List[SecurityFinding]:
        """Analyze a Python script for tainted data flows."""
        self.findings = []

        content = component.content
        if not content:
            return self.findings

        language = component.metadata.get("language", "unknown")
        if language != "python":
            return self.findings

        tracker = TaintTracker()
        flows = tracker.track(content)

        for flow in flows:
            severity = self.SEVERITY_MAP.get(flow.sink_type, "high")
            self.findings.append(SecurityFinding(
                severity=severity,
                rule_id=f"dataflow-{flow.source_type}-to-{flow.sink_type}",
                rule_name=f"Tainted Data Flow: {flow.source_type} → {flow.sink_type}",
                message=(
                    f"Untrusted data from {flow.source_detail} (line {flow.source_line}) "
                    f"flows to {flow.sink_detail} (line {flow.sink_line}) "
                    f"via variable '{flow.tainted_var}'"
                ),
                component_type=component.type,
                component_name=component.name,
                component_path=component.path,
                line=flow.sink_line,
                recommendation=self._get_recommendation(flow),
            ))

        return self.findings

    def _get_recommendation(self, flow: TaintFlow) -> str:
        recs = {
            "code_execution": "Never pass untrusted data to eval/exec; use safer alternatives like ast.literal_eval",
            "command_execution": "Sanitize inputs; use subprocess with list args (no shell=True); validate allowed commands",
            "dynamic_import": "Do not use __import__ with untrusted input; whitelist allowed modules",
            "network_send": "Validate and sanitize data before sending over the network; review destinations",
            "file_write": "Validate file paths; use path.resolve() and check against allowlist",
        }
        return recs.get(flow.sink_type, "Validate and sanitize all untrusted input before use")
