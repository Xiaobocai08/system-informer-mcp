import sys, time
from mcp_client import McpClient

def main():
    c = McpClient(); c.initialize()
    try:
        pid = c.call("launch_process", {"command_line": "notepad.exe", "window": "normal"})["pid"]
        print("launched notepad launcher pid", pid)
        time.sleep(2.0)
        # Modern Notepad's window may belong to a child process; search all windows by title/class.
        w = c.call("list_windows", {"visible_only": True, "limit": 400})
        hwnd = None; owner = None
        for win in w.get("windows", []):
            title = (win.get("title") or "").lower()
            cls = (win.get("className") or "").lower()
            if "notepad" in title or cls in ("notepad",) or "notepad" in cls:
                hwnd = win["hwnd"]; owner = win["pid"]; break
        print("matched window:", hwnd, "owner pid:", owner)
        assert hwnd, "could not locate a Notepad window among top-level windows"
        r = c.call("window_action", {"hwnd": hwnd, "action": "close", "confirm": True})
        print("close ->", r.get("message") or r.get("error"))
        assert not r["_isError"]
        time.sleep(1.0)
        # clean up whatever remains
        for p in (pid, owner):
            if p:
                c.call("terminate_process", {"pid": p, "confirm": True})
        print("CLOSE-WINDOW OK")
    finally:
        c.close()

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
