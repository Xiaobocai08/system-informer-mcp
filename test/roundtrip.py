"""Launch notepad -> inspect -> guard check -> suspend/resume -> terminate."""
import json
import sys
import time

from mcp_client import McpClient


def show(label, obj, keys=None):
    if keys:
        obj = {k: obj.get(k) for k in keys if k in obj}
    print(f"--- {label}\n{json.dumps(obj, indent=2, ensure_ascii=False)[:1500]}")


def main():
    c = McpClient()
    c.initialize()
    try:
        r = c.call("launch_process", {"command_line": "notepad.exe", "window": "normal"})
        show("launch_process", r)
        assert not r["_isError"], r
        pid = r["pid"]
        time.sleep(1.0)

        d = c.call("process_details", {"pid": pid})
        show("process_details", d, ["pid", "name", "imagePath", "commandLine", "parentName", "user",
                                    "integrity", "priorityClass", "affinityMask", "is32Bit", "protection",
                                    "critical", "beingDebugged", "currentDirectory", "workingSet_pretty",
                                    "gdiHandles", "userHandles", "running"])
        assert not d["_isError"], d
        assert d["name"].lower() == "notepad.exe", d["name"]

        t = c.call("process_token", {"pid": pid})
        show("process_token", {"user": t.get("user"), "integrity": t.get("integrity"),
                               "groupCount": t.get("groupCount"), "privilegeCount": t.get("privilegeCount"),
                               "firstPrivileges": (t.get("privileges") or [])[:3]})
        assert not t["_isError"], t

        tree = c.call("process_tree", {"root_pid": pid})
        show("process_tree(root_pid)", tree)

        # guard: no confirm -> refused
        g = c.call("suspend_process", {"pid": pid})
        show("suspend_process WITHOUT confirm (expect isError)", g)
        assert g["_isError"], "guard did not trigger"

        s = c.call("suspend_process", {"pid": pid, "confirm": True})
        show("suspend_process", s)
        assert not s["_isError"], s
        s = c.call("resume_process", {"pid": pid, "confirm": True})
        show("resume_process", s)
        assert not s["_isError"], s

        p = c.call("set_process_priority", {"pid": pid, "priority": "below_normal", "confirm": True})
        show("set_process_priority", p)
        assert not p["_isError"], p
        d2 = c.call("process_details", {"pid": pid})
        assert d2.get("priorityClass") == "below_normal", d2.get("priorityClass")
        print("priorityClass now:", d2.get("priorityClass"))

        a = c.call("set_process_affinity", {"pid": pid, "affinity_mask": "0x3", "confirm": True})
        show("set_process_affinity", a)
        assert not a["_isError"], a
        d3 = c.call("process_details", {"pid": pid})
        assert d3.get("affinityMask") == "0x3", d3.get("affinityMask")
        print("affinityMask now:", d3.get("affinityMask"))

        w = c.call("empty_working_set", {"pid": pid, "confirm": True})
        show("empty_working_set", w)
        assert not w["_isError"], w

        dmp = c.call("create_process_dump", {"pid": pid, "dump_type": "mini"})
        show("create_process_dump", dmp)
        assert not dmp["_isError"], dmp

        k = c.call("terminate_process", {"pid": pid, "confirm": True})
        show("terminate_process", k)
        assert not k["_isError"], k
        time.sleep(0.5)
        gone = c.call("process_details", {"pid": pid})
        show("process_details after terminate (expect error)", gone)
        assert gone["_isError"]
        print("\nROUNDTRIP OK")
    finally:
        c.close()
        for l in c.stderr_lines:
            print("[stderr]", l)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
