import sys, os, shutil
from pathlib import Path

FL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FL / "data/usr/lib/shadowfetch/mcp"))
import sf_mcp

failures = 0

def scenario(root, do_diff):
    global failures
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = root
    r = Path(root)
    shutil.rmtree(r, ignore_errors=True)
    (r / "proj/src").mkdir(parents=True)
    (r / "proj/src/app.py").write_text("original\n")
    (r / "proj/README.md").write_text("keep\n")
    srv = sf_mcp.build_checkpoint()
    ws = r / "proj"
    cid = srv.tools["snapshot"].handler({"workspace": "proj"}).split()[1]
    (ws / "src/app.py").write_text("REWRITTEN-BY-AGENT")
    (ws / "README.md").unlink()
    (ws / "src/added.py").write_text("junk")
    if do_diff:
        srv.tools["diff"].handler({"workspace": "proj", "checkpoint": cid})
    srv.tools["undo"].handler({"workspace": "proj", "checkpoint": cid})
    app = (ws / "src/app.py").read_text().strip()
    readme = (ws / "README.md").exists()
    added = (ws / "src/added.py").exists()
    ok = (app == "original" and readme and not added)
    print(f"  [{'diff' if do_diff else 'nodiff'}] app={app!r} README={readme} added={added} -> {'PASS' if ok else 'FAIL'}")
    failures += not ok

scenario("/tmp/sf-a", False)
scenario("/tmp/sf-b", True)
sys.exit(1 if failures else 0)
