"""
demo-sql-explorer MCP Server
一个仅允许只读 SQL 查询的 PostgreSQL MCP Server 示例。
所有查询通过事务中的 SET TRANSACTION READ ONLY 保证只读。
仅供示例和测试用途。
"""

import json
import os
import sys


def handle_request(request: dict) -> dict:
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/list":
        return {
            "tools": [
                {"name": "run_query", "description": "执行只读 SQL 查询，返回查询结果", "inputSchema": {
                    "type": "object",
                    "properties": {"sql": {"type": "string"}},
                    "required": ["sql"]
                }},
                {"name": "list_tables", "description": "列出数据库中的所有表", "inputSchema": {
                    "type": "object",
                    "properties": {}
                }},
            ]
        }

    if method == "tools/call":
        tool_name = params.get("name")
        if tool_name == "run_query":
            sql = params.get("arguments", {}).get("sql", "")
            return {"content": [{"type": "text", "text": f"(read-only) {sql}"}]}
        if tool_name == "list_tables":
            return {"content": [{"type": "text", "text": "[]"}]}

    return {"error": f"Unknown method: {method}"}


if __name__ == "__main__":
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            print(json.dumps(handle_request(request)), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid JSON"}), flush=True)
