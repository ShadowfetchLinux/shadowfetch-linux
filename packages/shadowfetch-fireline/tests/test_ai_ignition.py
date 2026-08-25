import subprocess, os, re, sys, json
FL = "/home/rtx5060ti/projects/shadowfetch-3.0.0/packages/shadowfetch-fireline"
AI = FL + "/data/usr/bin/shadowfetch-ai-ignition"
CAT = FL + "/data/usr/share/shadowfetch/ai-ignition/models.json"
os.environ["SHADOWFETCH_AI_CATALOG"] = CAT
catalog = json.load(open(CAT))
byid = {m["id"]: m for t in catalog["tiers"] for m in t["models"]}

def fits(m, v):
    need = m.get("min_vram_gb")
    if need is not None: return v >= need
    size = m.get("size_gb", 0)
    return size <= 4.0 if v == 0 else v >= size * 1.3

def rec(v):
    out = subprocess.run(["python3", AI, "recommend", "--vram-gb", str(v)],
                         capture_output=True, text=True).stdout
    mid = None
    name = re.search(r"Recommended: (.+?)  \[", out).group(1)
    for k, m in byid.items():
        if m["name"] == name: mid = k
    return mid, out

p = f = 0
def ck(d, c):
    global p, f
    print(("  PASS " if c else "  FAIL ") + d); p += c; f += (not c)

for v in [0, 2, 4, 6, 8, 10, 12, 16, 24, 48, 128]:
    mid, out = rec(v)
    m = byid[mid]
    ck(f"{v:>3}GB -> {m['name']} : is a real fit", fits(m, v))
    ck(f"{v:>3}GB -> {m['name']} : Apache-2.0 (safe-license default)", m["license"] == "apache-2.0")
# always returns a recommendation
ck("recommend never returns empty", "Recommended:" in rec(1)[1])
# plan errors on unknown id
rc = subprocess.run(["python3", AI, "plan", "nope"], capture_output=True).returncode
ck("plan rejects unknown model id", rc == 2)
# catalog lists all models
cout = subprocess.run(["python3", AI, "catalog"], capture_output=True, text=True).stdout
ck("catalog lists every model", all(mid in cout for mid in byid))
print(f"\n  {p} passed, {f} failed")
sys.exit(1 if f else 0)
