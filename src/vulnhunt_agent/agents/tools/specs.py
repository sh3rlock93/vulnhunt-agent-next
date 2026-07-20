"""Bedrock Converse tool specs. Static descriptors only — no behaviour."""
from __future__ import annotations

READ_TOOLS = [
    {
        "toolSpec": {
            "name": "read_file",
            "description": "Read a file from the repo. Returns text with line numbers.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path inside repo."},
                    "start": {"type": "integer", "description": "1-indexed start line.", "default": 1},
                    "end": {"type": "integer", "description": "Inclusive end line. Omit for full file."},
                },
                "required": ["path"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "grep",
            "description": "Search regex pattern across the repo. Returns matches as 'path:line:text'.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "Sub-path to limit search. Optional."},
                    "max_results": {"type": "integer", "default": 100},
                },
                "required": ["pattern"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "list_dir",
            "description": "List files/dirs in a path (non-recursive).",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative dir path."},
                },
                "required": ["path"],
            }},
        }
    },
]


POC_READ_TOOL = {
    "toolSpec": {
        "name": "read_poc",
        "description": (
            "Read a PoC file the Hunter wrote during exploitation. "
            "Path is relative to the PoC directory (no leading slash)."
        ),
        "inputSchema": {"json": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path under PoC dir."},
            },
            "required": ["path"],
        }},
    }
}


SANDBOX_TOOLS = [
    {
        "toolSpec": {
            "name": "write_poc",
            "description": (
                "Write a PoC file into the sandbox workspace (/workspace). "
                "Use to create Python scripts, test inputs, etc. Path is relative."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path under /workspace."},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "exec",
            "description": (
                "Run an argv command directly inside the sandbox (isolated, no network). "
                "Use to execute PoC, inspect behavior, confirm the vulnerability. "
                "Returns exit_code, stdout, stderr."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": "Executable and arguments, without shell syntax.",
                    },
                    "cwd": {
                        "type": "string",
                        "default": "/workspace",
                        "description": "Absolute directory below /workspace or /code.",
                    },
                    "timeout": {"type": "integer", "default": 60},
                },
                "required": ["argv"],
            }},
        }
    },
]


def tool_specs(with_sandbox: bool) -> list[dict]:
    return READ_TOOLS + (SANDBOX_TOOLS if with_sandbox else [])
