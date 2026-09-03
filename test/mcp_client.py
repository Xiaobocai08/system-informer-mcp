"""
Minimal MCP stdio client used to drive and verify si-mcp.exe.

Usage:
    python mcp_client.py                      # initialize + tools/list summary
    python mcp_client.py call <tool> '<json>' # call one tool with JSON args
    python mcp_client.py prompts              # list prompts
    python mcp_client.py prompt <name> '<json>'
"""
import json
import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "..", "build", "si-mcp.exe")


class McpClient:
    def __init__(self, exe=SERVER, env=None):
        self.proc = subprocess.Popen(
            [exe],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=env,
        )
        self._id = 0
        self.stderr_lines = []
        t = threading.Thread(target=self._pump_stderr, daemon=True)
        t.start()

    def _pump_stderr(self):
        for raw in self.proc.stderr:
            self.stderr_lines.append(raw.decode("utf-8", "replace").rstrip())

    def _send(self, msg):
        data = (json.dumps(msg) + "\n").encode("utf-8")
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def _recv(self):
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout; stderr:\n" + "\n".join(self.stderr_lines))
        return json.loads(line.decode("utf-8"))

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        resp = self._recv()
        assert resp.get("id") == self._id, f"id mismatch: {resp}"
        return resp

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def initialize(self):
        r = self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "si-mcp-test", "version": "0.1"},
        })
        self.notify("notifications/initialized")
        return r["result"]

    def list_tools(self):
        return self.request("tools/list")["result"]["tools"]

    def call(self, name, arguments=None):
        r = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in r:
            return {"_rpc_error": r["error"]}
        res = r["result"]
        out = res.get("structuredContent")
        if out is None:
            # fall back to parsing the text block
            txt = res["content"][0]["text"]
            try:
                out = json.loads(txt)
            except Exception:
                out = {"_text": txt}
        out["_isError"] = bool(res.get("isError"))
        return out

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def main(argv):
    c = McpClient()
    try:
        init = c.initialize()
        if len(argv) == 0:
            print("serverInfo:", json.dumps(init["serverInfo"]))
            print("capabilities:", json.dumps(init["capabilities"]))
            print("instructions (first 300 chars):", init.get("instructions", "")[:300].replace("\n", " "))
            tools = c.list_tools()
            print(f"\n{len(tools)} tools:")
            for t in tools:
                props = list(t["inputSchema"].get("properties", {}).keys())
                flag = " [DESTRUCTIVE]" if t.get("annotations", {}).get("destructiveHint") else ""
                print(f"  - {t['name']}({', '.join(props)}){flag}")
        elif argv[0] == "call":
            name = argv[1]
            args = json.loads(argv[2]) if len(argv) > 2 else {}
            print(json.dumps(c.call(name, args), indent=2, ensure_ascii=False))
        elif argv[0] == "prompts":
            print(json.dumps(c.request("prompts/list")["result"], indent=2))
        elif argv[0] == "prompt":
            name = argv[1]
            args = json.loads(argv[2]) if len(argv) > 2 else {}
            print(json.dumps(c.request("prompts/get", {"name": name, "arguments": args})["result"], indent=2))
        else:
            print(__doc__)
    finally:
        c.close()
        if c.stderr_lines:
            print("\n[server stderr]")
            for l in c.stderr_lines:
                print("  " + l)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main(sys.argv[1:])
