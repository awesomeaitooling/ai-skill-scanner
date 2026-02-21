import { PluginNode } from './PluginNode';
import { SkillNode } from './SkillNode';
import { CommandNode } from './CommandNode';
import { HookNode } from './HookNode';
import { MCPNode } from './MCPNode';
import { AgentNode } from './AgentNode';
import { ScriptNode } from './ScriptNode';
import { ResourceNode } from './ResourceNode';
import { LSPNode } from './LSPNode';

export const nodeTypes = {
  plugin: PluginNode,
  skill: SkillNode,
  command: CommandNode,
  hook: HookNode,
  mcp: MCPNode,
  lsp: LSPNode,
  agent: AgentNode,
  script: ScriptNode,
  resource: ResourceNode,
};

export {
  PluginNode,
  SkillNode,
  CommandNode,
  HookNode,
  MCPNode,
  LSPNode,
  AgentNode,
  ScriptNode,
  ResourceNode,
};

