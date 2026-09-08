# Shadowfetch Fireline

Run autonomous coding agents full-auto without giving them your whole machine.

## Quick start

    mkdir -p ~/Workspaces/myproject && cd ~/Workspaces/myproject
    shadowfetch-firebreak run -- claude --dangerously-skip-permissions

The agent sees a read-only system with only this workspace writable, no network
if you pass `--net none`, and none of your API keys in its environment. A
checkpoint is taken first; undo everything it did with:

    shadowfetch-checkpoint undo myproject <checkpoint-id>

## Give agents Shadowfetch's own tools (MCP)

    shadowfetch-mcp config --claude   # prints the commands to register them
    shadowfetch-mcp config --json     # prints an mcpServers block

Servers: passport (read-only self-check), phoenix (read-only restore points),
checkpoint (snapshot/diff/undo one workspace), fs (scoped read-only files).

The fs server refuses to start unless SF_MCP_FS_ROOT names the one directory
the agent may read. There is no default: it will not fall back to the working
directory, and it rejects a scope that is a filesystem root, a top-level
directory, your whole home directory, or a credential store. The configs
printed above already carry the scope.

## Read the audit trail

    shadowfetch-firebreak log
