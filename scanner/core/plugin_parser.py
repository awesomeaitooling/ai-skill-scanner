"""
Plugin Parser - Parses Claude Code plugin manifests and structures.

Handles parsing of:
- plugin.json manifests
- Directory structure discovery
- Component enumeration (skills, commands, hooks, agents, MCP servers)
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class PluginComponent:
    """Represents a discovered plugin component."""
    
    type: str  # skill, command, hook, agent, mcp, script, resource
    name: str
    path: str
    content: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class PluginManifest:
    """Parsed plugin manifest data."""
    
    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    commands_dir: str = "./commands"
    skills_dir: str = "./skills"
    agents_dir: str = "./agents"
    hooks_config: dict = field(default_factory=dict)
    mcp_servers: dict = field(default_factory=dict)
    lsp_servers: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


@dataclass
class ParsedPlugin:
    """Complete parsed plugin structure."""
    
    path: str
    manifest: PluginManifest
    components: list[PluginComponent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PluginParser:
    """Parses Claude Code plugins from filesystem or marketplace."""
    
    MANIFEST_LOCATIONS = [
        ".claude-plugin/plugin.json",
        "plugin.json",
    ]
    
    HOOKS_LOCATIONS = [
        "hooks/hooks.json",
        ".claude-plugin/hooks.json",
    ]
    
    MCP_LOCATIONS = [
        ".mcp.json",
        ".claude-plugin/.mcp.json",
    ]
    
    LSP_LOCATIONS = [
        ".lsp.json",
        ".claude-plugin/.lsp.json",
    ]
    
    # Maximum file size to read (5MB) to prevent memory exhaustion
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    def __init__(self, plugin_path: str):
        """Initialize parser with plugin path."""
        self.plugin_path = Path(plugin_path).resolve()
        self.errors: list[str] = []
    
    def _safe_resolve_path(self, relative_path: str) -> Path | None:
        """
        Safely resolve a path within the plugin directory.
        
        Prevents path traversal attacks by ensuring the resolved path
        is within the plugin directory.
        
        Args:
            relative_path: Relative path from plugin root
            
        Returns:
            Resolved Path if safe, None if path escapes plugin directory
        """
        # Normalize the path - remove leading ./ and normalize separators
        cleaned = relative_path.replace("\\", "/")
        
        # Remove any leading ./ or /
        while cleaned.startswith("./") or cleaned.startswith("/"):
            cleaned = cleaned[1:] if cleaned.startswith("/") else cleaned[2:]
        
        # Block obvious traversal attempts
        if ".." in cleaned:
            self.errors.append(f"Path traversal blocked: {relative_path}")
            return None
        
        # Resolve the full path
        try:
            target_path = (self.plugin_path / cleaned).resolve()
        except (OSError, ValueError) as e:
            self.errors.append(f"Invalid path: {relative_path} - {e}")
            return None
        
        # Verify the resolved path is within the plugin directory
        try:
            target_path.relative_to(self.plugin_path)
        except ValueError:
            self.errors.append(f"Path escapes plugin directory: {relative_path}")
            return None
        
        return target_path
    
    def _safe_read_file(self, file_path: Path) -> str | None:
        """
        Safely read a file with size limits and symlink protection.
        
        Args:
            file_path: Path to file to read
            
        Returns:
            File contents or None if file is too large, a symlink, or unreadable
        """
        try:
            if file_path.is_symlink():
                self.errors.append(f"Skipping symlink: {file_path.name}")
                return None

            file_size = file_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                self.errors.append(f"File too large ({file_size} bytes): {file_path.name}")
                return None
            
            return file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.errors.append(f"Error reading file {file_path.name}: {e}")
            return None
    
    def parse(self) -> ParsedPlugin:
        """Parse the plugin and return structured data."""
        self._standard_count = 0
        self._deep_count = 0
        
        manifest = self._parse_manifest()
        components = self._discover_components(manifest)
        
        result = ParsedPlugin(
            path=str(self.plugin_path),
            manifest=manifest,
            components=components,
            errors=self.errors.copy(),
        )
        # Attach discovery counts for verbose reporting
        result.standard_count = self._standard_count  # type: ignore[attr-defined]
        result.deep_count = self._deep_count  # type: ignore[attr-defined]
        return result
    
    def _parse_manifest(self) -> PluginManifest:
        """Parse the plugin manifest file."""
        manifest_path = self._find_file(self.MANIFEST_LOCATIONS)
        
        if not manifest_path:
            self.errors.append("No plugin manifest found (plugin.json)")
            return PluginManifest(name=self.plugin_path.name)
        
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON in manifest: {e}")
            return PluginManifest(name=self.plugin_path.name)
        except Exception as e:
            self.errors.append(f"Error reading manifest: {e}")
            return PluginManifest(name=self.plugin_path.name)
        
        # Parse hooks from manifest or separate file
        hooks_config = data.get("hooks", {})
        if not hooks_config:
            hooks_path = self._find_file(self.HOOKS_LOCATIONS)
            if hooks_path:
                try:
                    with open(hooks_path, "r", encoding="utf-8") as f:
                        hooks_data = json.load(f)
                        hooks_config = hooks_data.get("hooks", hooks_data)
                except Exception as e:
                    self.errors.append(f"Error reading hooks config: {e}")
        
        # Parse MCP servers from manifest or separate file
        mcp_servers = data.get("mcpServers", {})
        if not mcp_servers:
            mcp_path = self._find_file(self.MCP_LOCATIONS)
            if mcp_path:
                try:
                    with open(mcp_path, "r", encoding="utf-8") as f:
                        mcp_data = json.load(f)
                        mcp_servers = mcp_data.get("mcpServers", mcp_data)
                except Exception as e:
                    self.errors.append(f"Error reading MCP config: {e}")
        
        # Parse LSP servers from manifest or separate file
        lsp_servers = data.get("lspServers", {})
        if not lsp_servers:
            lsp_path = self._find_file(self.LSP_LOCATIONS)
            if lsp_path:
                try:
                    with open(lsp_path, "r", encoding="utf-8") as f:
                        lsp_data = json.load(f)
                        lsp_servers = lsp_data.get("lspServers", lsp_data)
                except Exception as e:
                    self.errors.append(f"Error reading LSP config: {e}")
        
        return PluginManifest(
            name=data.get("name", self.plugin_path.name),
            version=data.get("version", "0.0.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            commands_dir=data.get("commandsDir", "./commands"),
            skills_dir=data.get("skillsDir", "./skills"),
            agents_dir=data.get("agentsDir", "./agents"),
            hooks_config=hooks_config,
            mcp_servers=mcp_servers,
            lsp_servers=lsp_servers,
            raw=data
        )
    
    def _discover_components(self, manifest: PluginManifest) -> list[PluginComponent]:
        """Discover all plugin components.
        
        Runs standard directory-based discovery first, then a deep recursive
        discovery pass that finds components anywhere in the tree.  Results
        are merged with path-based deduplication (standard discovery wins).
        """
        components = []
        
        # --- Standard discovery (existing logic) ---
        
        # Discover skills
        components.extend(self._discover_skills(manifest.skills_dir))
        
        # Discover commands
        components.extend(self._discover_commands(manifest.commands_dir))
        
        # Discover agents
        components.extend(self._discover_agents(manifest.agents_dir))
        
        # Parse hooks as components
        components.extend(self._parse_hooks(manifest.hooks_config))
        
        # Parse MCP servers as components
        components.extend(self._parse_mcp_servers(manifest.mcp_servers))
        
        # Parse LSP servers as components
        components.extend(self._parse_lsp_servers(manifest.lsp_servers))
        
        # Discover scripts
        components.extend(self._discover_scripts())
        
        # Discover resources
        components.extend(self._discover_resources())
        
        standard_count = len(components)
        
        # --- Deep discovery pass (find anything the standard pass missed) ---
        deep_components = self._deep_discover_components()
        
        # Merge: deduplicate by path, standard discovery takes priority
        seen_paths = {c.path for c in components}
        deep_added = 0
        for dc in deep_components:
            if dc.path not in seen_paths:
                components.append(dc)
                seen_paths.add(dc.path)
                deep_added += 1
        
        # Store counts for verbose reporting
        self._standard_count = standard_count
        self._deep_count = deep_added
        
        return components
    
    def _discover_skills(self, skills_dir: str) -> list[PluginComponent]:
        """Discover SKILL.md files in skills directory."""
        components = []
        
        # Use safe path resolution to prevent traversal
        skills_path = self._safe_resolve_path(skills_dir)
        if skills_path is None or not skills_path.exists():
            return components
        
        for item in skills_path.iterdir():
            if item.is_dir():
                # Verify subdirectory is still within plugin
                try:
                    item.relative_to(self.plugin_path)
                except ValueError:
                    continue
                
                skill_md = item / "SKILL.md"
                if skill_md.exists():
                    content = self._safe_read_file(skill_md)
                    if content is not None:
                        components.append(PluginComponent(
                            type="skill",
                            name=item.name,
                            path=str(skill_md.relative_to(self.plugin_path)),
                            content=content,
                            metadata=self._parse_skill_metadata(content)
                        ))
                
                # Check for reference files and scripts
                for ref_file in item.glob("*.md"):
                    if ref_file.name != "SKILL.md":
                        ref_content = self._safe_read_file(ref_file)
                        if ref_content is not None:
                            components.append(PluginComponent(
                                type="resource",
                                name=ref_file.name,
                                path=str(ref_file.relative_to(self.plugin_path)),
                                content=ref_content
                            ))
                
                scripts_dir = item / "scripts"
                if scripts_dir.exists():
                    for script in scripts_dir.rglob("*"):
                        if script.is_file():
                            ext = script.suffix.lower()
                            script_content = None
                            is_binary = ext in self.BINARY_EXTENSIONS
                            if not is_binary:
                                script_content = self._safe_read_file(script)
                            components.append(PluginComponent(
                                type="script",
                                name=script.name,
                                path=str(script.relative_to(self.plugin_path)),
                                content=script_content,
                                metadata={
                                    "parent_skill": item.name,
                                    "is_binary": is_binary,
                                    "extension": ext,
                                    "language": self._detect_script_language(ext, script.name),
                                }
                            ))
        
        return components
    
    def _discover_commands(self, commands_dir: str) -> list[PluginComponent]:
        """Discover command markdown files."""
        components = []
        
        # Use safe path resolution to prevent traversal
        commands_path = self._safe_resolve_path(commands_dir)
        if commands_path is None or not commands_path.exists():
            return components
        
        # First check for COMMAND.md files in subdirectories (new structure)
        for item in commands_path.iterdir():
            if item.is_dir():
                # Verify subdirectory is still within plugin
                try:
                    item.relative_to(self.plugin_path)
                except ValueError:
                    continue
                
                command_md = item / "COMMAND.md"
                if command_md.exists():
                    content = self._safe_read_file(command_md)
                    if content is not None:
                        components.append(PluginComponent(
                            type="command",
                            name=item.name,
                            path=str(command_md.relative_to(self.plugin_path)),
                            content=content,
                            metadata=self._parse_command_metadata(content)
                        ))
        
        # Also check for *.md files directly in commands dir (old structure)
        for md_file in commands_path.glob("*.md"):
            # Verify file is within plugin directory
            try:
                md_file.relative_to(self.plugin_path)
            except ValueError:
                continue
                
            content = self._safe_read_file(md_file)
            if content is not None:
                components.append(PluginComponent(
                    type="command",
                    name=md_file.stem,
                    path=str(md_file.relative_to(self.plugin_path)),
                    content=content,
                    metadata=self._parse_command_metadata(content)
                ))
        
        return components
    
    def _discover_agents(self, agents_dir: str) -> list[PluginComponent]:
        """Discover agent markdown files."""
        components = []
        
        # Use safe path resolution to prevent traversal
        agents_path = self._safe_resolve_path(agents_dir)
        if agents_path is None or not agents_path.exists():
            return components
        
        # First check for AGENT.md files in subdirectories (new structure)
        for item in agents_path.iterdir():
            if item.is_dir():
                # Verify subdirectory is still within plugin
                try:
                    item.relative_to(self.plugin_path)
                except ValueError:
                    continue
                
                agent_md = item / "AGENT.md"
                if agent_md.exists():
                    content = self._safe_read_file(agent_md)
                    if content is not None:
                        components.append(PluginComponent(
                            type="agent",
                            name=item.name,
                            path=str(agent_md.relative_to(self.plugin_path)),
                            content=content,
                            metadata=self._parse_agent_metadata(content)
                        ))
        
        # Also check for *.md files directly in agents dir (old structure)
        for md_file in agents_path.glob("*.md"):
            # Verify file is within plugin directory
            try:
                md_file.relative_to(self.plugin_path)
            except ValueError:
                continue
                
            content = self._safe_read_file(md_file)
            if content is not None:
                components.append(PluginComponent(
                    type="agent",
                    name=md_file.stem,
                    path=str(md_file.relative_to(self.plugin_path)),
                    content=content,
                    metadata=self._parse_agent_metadata(content)
                ))
        
        return components
    
    def _parse_hooks(self, hooks_config) -> list[PluginComponent]:
        """Parse hooks configuration into components."""
        components = []
        
        # Handle case where hooks_config is not a dict
        if not isinstance(hooks_config, dict):
            if hooks_config:
                self.errors.append(f"Hooks config is not a dictionary: {type(hooks_config).__name__}")
            return components
        
        for event_name, event_hooks in hooks_config.items():
            if isinstance(event_hooks, list):
                for idx, hook in enumerate(event_hooks):
                    # Handle case where hook is not a dict
                    if not isinstance(hook, dict):
                        continue
                    
                    matcher = hook.get("matcher", "*")
                    inner_hooks = hook.get("hooks", [])
                    
                    # Handle case where inner_hooks is not a list
                    if not isinstance(inner_hooks, list):
                        inner_hooks = [inner_hooks] if inner_hooks else []
                    
                    for h_idx, h in enumerate(inner_hooks):
                        if not isinstance(h, dict):
                            continue
                        hook_type = h.get("type", "unknown")
                        components.append(PluginComponent(
                            type="hook",
                            name=f"{event_name}_{idx}_{h_idx}",
                            path=f"hooks/{event_name}",
                            metadata={
                                "event": event_name,
                                "matcher": matcher,
                                "hook_type": hook_type,
                                "command": h.get("command", ""),
                                "prompt": h.get("prompt", ""),
                                "config": h
                            }
                        ))
            elif isinstance(event_hooks, dict):
                # Handle alternate format where event directly contains hook config
                hook = event_hooks
                matcher = hook.get("matcher", "*")
                hook_type = hook.get("type", "unknown")
                components.append(PluginComponent(
                    type="hook",
                    name=f"{event_name}_0_0",
                    path=f"hooks/{event_name}",
                    metadata={
                        "event": event_name,
                        "matcher": matcher,
                        "hook_type": hook_type,
                        "command": hook.get("command", ""),
                        "prompt": hook.get("prompt", ""),
                        "config": hook
                    }
                ))
        
        return components
    
    def _parse_mcp_servers(self, mcp_servers) -> list[PluginComponent]:
        """Parse MCP server configurations into components."""
        components = []
        
        # Handle case where mcp_servers is not a dict
        if not isinstance(mcp_servers, dict):
            if mcp_servers:
                self.errors.append(f"MCP servers config is not a dictionary: {type(mcp_servers).__name__}")
            return components
        
        for server_name, config in mcp_servers.items():
            # Handle case where config is not a dict
            if not isinstance(config, dict):
                # If config is a string, treat it as a command
                if isinstance(config, str):
                    config = {"command": config}
                else:
                    self.errors.append(f"MCP server '{server_name}' config is not a dictionary")
                    continue
            
            components.append(PluginComponent(
                type="mcp",
                name=server_name,
                path=".mcp.json",
                metadata={
                    "command": config.get("command", ""),
                    "args": config.get("args", []),
                    "env": config.get("env", {}),
                    "cwd": config.get("cwd", ""),
                    "config": config
                }
            ))
        
        return components
    
    def _parse_lsp_servers(self, lsp_servers) -> list[PluginComponent]:
        """Parse LSP server configurations into components."""
        components = []
        
        # Handle case where lsp_servers is not a dict
        if not isinstance(lsp_servers, dict):
            if lsp_servers:
                self.errors.append(f"LSP servers config is not a dictionary: {type(lsp_servers).__name__}")
            return components
        
        for server_name, config in lsp_servers.items():
            # Handle case where config is not a dict
            if not isinstance(config, dict):
                if isinstance(config, str):
                    config = {"command": config}
                else:
                    self.errors.append(f"LSP server '{server_name}' config is not a dictionary")
                    continue
            
            components.append(PluginComponent(
                type="lsp",
                name=server_name,
                path=".lsp.json",
                metadata={
                    "command": config.get("command", ""),
                    "args": config.get("args", []),
                    "transport": config.get("transport", "stdio"),
                    "extensions": config.get("extensionToLanguage", {}),
                    "config": config
                }
            ))
        
        return components
    
    # Extensions that should be read and analyzed as scripts
    SCRIPT_EXTENSIONS = {
        ".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".zsh",
    }
    
    # Extensions treated as binary — flag presence, don't read
    BINARY_EXTENSIONS = {
        ".exe", ".dll", ".so", ".bin", ".wasm", ".jar", ".apk",
        ".dmg", ".msi", ".iso", ".img", ".deb", ".rpm",
    }
    
    # Extensions for text resources that should be read
    RESOURCE_TEXT_EXTENSIONS = {
        ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".txt",
        ".template", ".tmpl", ".env.example", ".conf", ".properties",
        ".xml", ".csv", ".sql", ".graphql",
    }
    
    # Directories to skip during deep discovery
    SKIP_DIRS = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        ".claude-plugin", ".cursor", ".github", ".vscode",
        "dist", "build",
    }
    
    # Component filenames for deep discovery (case-insensitive matching)
    _COMPONENT_FILENAMES = {
        "skill.md": "skill",
        "agent.md": "agent",
        "command.md": "command",
    }
    
    # Config filenames for deep discovery of hooks/mcp/lsp
    _CONFIG_FILENAMES = {
        "hooks.json": "hook",
        ".mcp.json": "mcp",
        ".lsp.json": "lsp",
    }
    
    # ClawHub / misc metadata filenames treated as resources
    _RESOURCE_FILENAMES = {"_meta.json", "config.json"}
    
    def _deep_discover_components(self) -> list[PluginComponent]:
        """
        Recursively discover components anywhere in the plugin tree by filename.
        
        This is a fallback/supplement to the standard directory-based discovery.
        It walks the entire tree looking for SKILL.md, AGENT.md, COMMAND.md,
        hooks.json, .mcp.json, .lsp.json, scripts, and resource files —
        regardless of where they live in the directory structure.
        
        Case-insensitive matching is used for SKILL.md, AGENT.md, COMMAND.md
        to handle ClawHub downloads and other non-standard layouts.
        """
        components: list[PluginComponent] = []
        
        for dirpath, dirnames, filenames in os.walk(self.plugin_path, followlinks=False):
            current = Path(dirpath)
            
            # Verify we're still within the plugin directory
            try:
                current.relative_to(self.plugin_path)
            except ValueError:
                continue
            
            # Prune skip directories (modifying dirnames in-place)
            dirnames[:] = [
                d for d in dirnames
                if d not in self.SKIP_DIRS
            ]
            
            for filename in filenames:
                file_path = current / filename
                
                # Safety: verify file is within plugin directory
                try:
                    rel_path = str(file_path.relative_to(self.plugin_path))
                except ValueError:
                    continue
                
                name_lower = filename.lower()
                
                # --- Component markdown files (case-insensitive) ---
                if name_lower in self._COMPONENT_FILENAMES:
                    comp_type = self._COMPONENT_FILENAMES[name_lower]
                    content = self._safe_read_file(file_path)
                    if content is not None:
                        # Derive component name from parent directory
                        parent_name = current.name
                        if current == self.plugin_path:
                            # File is at plugin root — use plugin dir name
                            parent_name = self.plugin_path.name
                        
                        # Choose metadata parser based on type
                        if comp_type == "skill":
                            metadata = self._parse_skill_metadata(content)
                        elif comp_type == "agent":
                            metadata = self._parse_agent_metadata(content)
                        else:
                            metadata = self._parse_command_metadata(content)
                        
                        metadata["deep_discovery"] = True
                        
                        components.append(PluginComponent(
                            type=comp_type,
                            name=parent_name,
                            path=rel_path,
                            content=content,
                            metadata=metadata,
                        ))
                    continue
                
                # --- Config files (hooks.json, .mcp.json, .lsp.json) ---
                if filename in self._CONFIG_FILENAMES:
                    config_type = self._CONFIG_FILENAMES[filename]
                    if file_path.is_symlink():
                        continue
                    try:
                        raw = file_path.read_text(encoding="utf-8")
                        data = json.loads(raw)
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    
                    if config_type == "hook":
                        hooks_data = data.get("hooks", data) if isinstance(data, dict) else data
                        if isinstance(hooks_data, dict):
                            for comp in self._parse_hooks(hooks_data):
                                comp.metadata["deep_discovery"] = True
                                components.append(comp)
                    elif config_type == "mcp":
                        mcp_data = data.get("mcpServers", data) if isinstance(data, dict) else data
                        if isinstance(mcp_data, dict):
                            for comp in self._parse_mcp_servers(mcp_data):
                                comp.path = rel_path
                                comp.metadata["deep_discovery"] = True
                                components.append(comp)
                    elif config_type == "lsp":
                        lsp_data = data.get("lspServers", data) if isinstance(data, dict) else data
                        if isinstance(lsp_data, dict):
                            for comp in self._parse_lsp_servers(lsp_data):
                                comp.path = rel_path
                                comp.metadata["deep_discovery"] = True
                                components.append(comp)
                    continue
                
                # --- ClawHub / metadata resource files ---
                if filename in self._RESOURCE_FILENAMES:
                    content = self._safe_read_file(file_path)
                    components.append(PluginComponent(
                        type="resource",
                        name=filename,
                        path=rel_path,
                        content=content,
                        metadata={
                            "resource_type": "metadata",
                            "file_type": file_path.suffix[1:] if file_path.suffix else "unknown",
                            "is_binary": False,
                            "deep_discovery": True,
                        },
                    ))
                    continue
                
                # --- Script files by extension ---
                ext = file_path.suffix.lower()
                if ext in self.SCRIPT_EXTENSIONS:
                    is_binary = False
                    content = self._safe_read_file(file_path)
                    components.append(PluginComponent(
                        type="script",
                        name=filename,
                        path=rel_path,
                        content=content,
                        metadata={
                            "standalone": True,
                            "is_binary": False,
                            "extension": ext,
                            "language": self._detect_script_language(ext, filename),
                            "deep_discovery": True,
                        },
                    ))
                    continue
                
                if ext in self.BINARY_EXTENSIONS:
                    components.append(PluginComponent(
                        type="script",
                        name=filename,
                        path=rel_path,
                        metadata={
                            "standalone": True,
                            "is_binary": True,
                            "extension": ext,
                            "deep_discovery": True,
                        },
                    ))
                    continue
        
        return components
    
    def _discover_scripts(self) -> list[PluginComponent]:
        """Discover standalone script files and read their content."""
        components = []
        scripts_path = self.plugin_path / "scripts"
        
        if not scripts_path.exists():
            return components
        
        for script in scripts_path.rglob("*"):
            if not script.is_file():
                continue
            
            # Verify file is within plugin directory
            try:
                script.relative_to(self.plugin_path)
            except ValueError:
                continue
            
            ext = script.suffix.lower()
            rel_path = str(script.relative_to(self.plugin_path))
            
            if ext in self.BINARY_EXTENSIONS:
                # Flag binary but don't read
                components.append(PluginComponent(
                    type="script",
                    name=script.name,
                    path=rel_path,
                    metadata={
                        "standalone": True,
                        "is_binary": True,
                        "extension": ext,
                    }
                ))
            else:
                # Read script content (text files)
                content = self._safe_read_file(script)
                components.append(PluginComponent(
                    type="script",
                    name=script.name,
                    path=rel_path,
                    content=content,
                    metadata={
                        "standalone": True,
                        "is_binary": False,
                        "extension": ext,
                        "language": self._detect_script_language(ext, script.name),
                    }
                ))
        
        return components
    
    def _discover_resources(self) -> list[PluginComponent]:
        """Discover resource files (templates, configs, schemas, etc.) and read text content."""
        components = []
        resources_path = self.plugin_path / "resources"
        
        if not resources_path.exists():
            return components
        
        for resource_file in resources_path.rglob("*"):
            if not resource_file.is_file():
                continue
            
            # Verify file is within plugin directory
            try:
                resource_file.relative_to(self.plugin_path)
            except ValueError:
                continue
            
            ext = resource_file.suffix.lower()
            rel_path = str(resource_file.relative_to(self.plugin_path))
            relative_inner = resource_file.relative_to(resources_path)
            resource_type = relative_inner.parts[0] if len(relative_inner.parts) > 1 else "general"
            
            if ext in self.BINARY_EXTENSIONS:
                # Flag binary resources
                components.append(PluginComponent(
                    type="resource",
                    name=resource_file.name,
                    path=rel_path,
                    metadata={
                        "resource_type": resource_type,
                        "file_type": ext[1:] if ext else "unknown",
                        "is_binary": True,
                    }
                ))
            else:
                # Read text resources
                content = self._safe_read_file(resource_file)
                components.append(PluginComponent(
                    type="resource",
                    name=resource_file.name,
                    path=rel_path,
                    content=content,
                    metadata={
                        "resource_type": resource_type,
                        "file_type": ext[1:] if ext else "unknown",
                        "is_binary": False,
                    }
                ))
        
        return components
    
    def _detect_script_language(self, ext: str, filename: str) -> str:
        """Detect script language from extension or filename."""
        lang_map = {
            ".py": "python",
            ".sh": "bash",
            ".bash": "bash",
            ".zsh": "bash",
            ".js": "javascript",
            ".ts": "typescript",
            ".rb": "ruby",
            ".pl": "perl",
        }
        
        if ext in lang_map:
            return lang_map[ext]
        
        # Check common filenames without extensions
        name_lower = filename.lower()
        if name_lower in ("makefile", "dockerfile"):
            return name_lower
        if name_lower in ("rakefile", "gemfile"):
            return "ruby"
        
        return "unknown"
    
    def _parse_skill_metadata(self, content: str) -> dict:
        """Extract metadata from SKILL.md content."""
        metadata = {}
        lines = content.split("\n")
        
        # Check for YAML frontmatter
        if lines and lines[0].strip() == "---":
            end_idx = -1
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == "---":
                    end_idx = i
                    break
            
            if end_idx > 0:
                frontmatter = "\n".join(lines[1:end_idx])
                try:
                    import yaml
                    metadata["frontmatter"] = yaml.safe_load(frontmatter)
                except Exception:
                    metadata["frontmatter_raw"] = frontmatter
        
        # Extract title
        for line in lines:
            if line.startswith("# "):
                metadata["title"] = line[2:].strip()
                break
        
        return metadata
    
    def _parse_command_metadata(self, content: str) -> dict:
        """Extract metadata from command markdown."""
        return self._parse_skill_metadata(content)
    
    def _parse_agent_metadata(self, content: str) -> dict:
        """Extract metadata from agent markdown."""
        metadata = self._parse_skill_metadata(content)
        
        # Look for capabilities section
        if "## Capabilities" in content:
            cap_start = content.index("## Capabilities")
            cap_section = content[cap_start:]
            # Extract bullet points
            capabilities = []
            for line in cap_section.split("\n"):
                if line.strip().startswith("- "):
                    capabilities.append(line.strip()[2:])
                elif line.startswith("## ") and "Capabilities" not in line:
                    break
            metadata["capabilities"] = capabilities
        
        return metadata
    
    def _find_file(self, locations: list[str]) -> Optional[Path]:
        """Find the first existing file from a list of locations."""
        for loc in locations:
            path = self.plugin_path / loc
            if path.exists():
                return path
        return None

