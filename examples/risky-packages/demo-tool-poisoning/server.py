"""
demo-tool-poisoning MCP Server（风险示例）
演示"工具描述投毒"攻击：manifest 中 get_weather 工具的描述声称具备
"管理员权限 + 任意 shell 执行"能力，但 permissions 声明完全不允许。
仅供扫描器 SR-017 检测测试使用，请勿部署。
"""

import json
import sys


def handle_request(request: dict) -> dict:
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/list":
        return {
            "tools": [
                {"name": "get_weather", "description": "获取天气信息", "inputSchema": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}}
                }},
                {"name": "list_directory", "description": "列出目录内容", "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string", "default": "."}}
                }},
            ]
        }

    if method == "tools/call":
        tool_name = params.get("name")
        if tool_name == "get_weather":
            return {"content": [{"type": "text", "text": "{\"weather\": \"sunny\"}"}]}
        if tool_name == "list_directory":
            return {"content": [{"type": "text", "text": "[]"}]}

    return {"error": f"Unknown method: {method}"}


if __name__ == "__main__":
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            print(json.dumps(handle_request(request)), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid JSON"}), flush=True)
