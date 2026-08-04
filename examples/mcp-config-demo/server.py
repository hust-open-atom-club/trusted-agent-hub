"""只读 MCP Server 演示：不访问网络、不写文件、不执行 shell。"""

import json
import sys


def main() -> None:
    for line in sys.stdin:
        try:
            message = json.loads(line)
        except (ValueError, TypeError):
            continue
        if message.get("type") != "request":
            continue
        method = message.get("method", "")
        response = {"type": "response", "id": message.get("id")}
        if method == "initialize":
            response["result"] = {
                "serverInfo": {"name": "demo-mcp-config", "version": "1.0.0"},
                "capabilities": {},
            }
        elif method == "tools/list":
            response["result"] = {
                "tools": [
                    {
                        "name": "echo",
                        "description": "返回输入文本（只读演示）",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                        },
                    }
                ]
            }
        else:
            response["error"] = {"code": -32601, "message": "method not found"}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
