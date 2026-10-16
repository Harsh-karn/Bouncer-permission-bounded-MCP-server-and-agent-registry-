"""
Read tools for Bouncer MCP server.
Allows agents to inspect tasks and comments without any write capabilities.
"""

from typing import Any, Dict, List, Optional
from bouncer.adapters.notion import NotionAdapter


class ReadTools:
    """Read tool implementations wired to the capability-restricted Notion adapter."""

    def __init__(self, adapter: Optional[NotionAdapter] = None):
        self.adapter = adapter or NotionAdapter(sandbox_mode=True)

    def read_tasks(self, limit: int = 10, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List tasks from the shared work system.
        Arguments:
            limit: Maximum number of tasks to return (default 10, max 50).
            status: Optional filter by status ('In Progress', 'Done', etc.).
        """
        clamped_limit = max(1, min(limit, 50))
        return self.adapter.read_tasks(limit=clamped_limit, status=status)

    def read_task(self, task_id: str) -> Dict[str, Any]:
        """
        Retrieve full details of a specific task.
        Arguments:
            task_id: Unique task identifier (e.g. 'task-101').
        """
        return self.adapter.read_task(task_id=task_id)

    def read_comments(self, task_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve discussion comments on a specific task.
        Arguments:
            task_id: Unique task identifier.
        """
        return self.adapter.read_comments(task_id=task_id)
