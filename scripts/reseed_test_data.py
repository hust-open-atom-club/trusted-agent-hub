"""清空 PostgreSQL 旧数据，按设计规范插入 50 条测试包/版本数据。
用法: python scripts/reseed_test_data.py
"""
import json
import uuid
import sys
from typing import Set
from datetime import datetime, timezone

DB_URL = "postgresql://postgres:293021@localhost:5432/trusted_agent_hub"

# ============================================================
# 固定参数
# ============================================================
SUBMITTER_ID   = "user-2ec4ba335e2a4fd88d0130b39e08c889"  # submitter 用户
SUBMITTER_NAME = "Test Submitter"
NOW            = datetime.now(timezone.utc).isoformat()

_used_ids: Set[str] = set()

def _uid(prefix: str) -> str:
    while True:
        uid = f"{prefix}-{uuid.uuid4().hex[:12]}"
        if uid not in _used_ids:
            _used_ids.add(uid)
            return uid

def _pkg(uid: str) -> str:
    return uid

def _ver(uid: str) -> str:
    while True:
        vid = uid.replace("pkg-", "ver-")
        if vid not in _used_ids:
            _used_ids.add(vid)
            return vid

# ============================================================
# 等级映射
# ============================================================
RISK_TO_GRADE = {
    "trusted":     "A",
    "low_risk":    "B",
    "medium_risk": "C",
    "high_risk":   "D",
    "untrusted":   "E",
}

# ============================================================
# 50 条包定义 — 覆盖全部状态 / 类型 / 等级组合
# ============================================================
# fmt: off
PACKAGES_RAW = [
    # ── 已发布 published (20条) ──
    {"name":"【test】code-review-skill","type":"skill","status":"published","risk_level":"trusted","grade":"A","install_count":1520,"avg_rating":4.8,"license":"MIT","keywords":["code-review","security","pull-request","quality"],"category":"developer-tools","homepage":"https://github.com/test/code-review-skill"},
    {"name":"【test】database-explorer-mcp","type":"mcp_server","status":"published","risk_level":"low_risk","grade":"B","install_count":890,"avg_rating":4.3,"license":"Apache-2.0","keywords":["database","postgresql","mcp","read-only"],"category":"data","homepage":"https://github.com/test/database-explorer-mcp"},
    {"name":"【test】dev-utility-plugin","type":"plugin","status":"published","risk_level":"medium_risk","grade":"C","install_count":340,"avg_rating":3.9,"license":"MIT","keywords":["dev-tools","lint","format","git"],"category":"productivity","homepage":"https://github.com/test/dev-utility-plugin"},
    {"name":"【test】docker-deploy-command","type":"command","status":"published","risk_level":"high_risk","grade":"D","install_count":120,"avg_rating":3.2,"license":"MIT","keywords":["docker","deploy","devops","container"],"category":"devops","homepage":"https://github.com/test/docker-deploy-command"},
    {"name":"【test】web-scraper-executor","type":"command","status":"published","risk_level":"untrusted","grade":"E","install_count":15,"avg_rating":1.8,"license":"MIT","keywords":["web","scraper","executor","network"],"category":"web","homepage":None},
    {"name":"【test】ci-cd-automation-skill","type":"skill","status":"published","risk_level":"trusted","grade":"A","install_count":2100,"avg_rating":4.9,"license":"MIT","keywords":["ci-cd","automation","github-actions","devops"],"category":"devops","homepage":"https://github.com/test/ci-cd-automation-skill"},
    {"name":"【test】k8s-monitor-mcp","type":"mcp_server","status":"published","risk_level":"low_risk","grade":"B","install_count":670,"avg_rating":4.5,"license":"Apache-2.0","keywords":["kubernetes","monitoring","mcp","infra"],"category":"infrastructure","homepage":"https://github.com/test/k8s-monitor-mcp"},
    {"name":"【test】refactor-assistant-plug","type":"plugin","status":"published","risk_level":"medium_risk","grade":"C","install_count":450,"avg_rating":4.1,"license":"MIT","keywords":["refactor","rename","extract","lint"],"category":"developer-tools","homepage":"https://github.com/test/refactor-assistant-plug"},
    {"name":"【test】system-info-command","type":"command","status":"published","risk_level":"low_risk","grade":"B","install_count":780,"avg_rating":4.4,"license":"MIT","keywords":["system","info","diagnostic","shell"],"category":"utility","homepage":"https://github.com/test/system-info-command"},
    {"name":"【test】lang-translation-skill","type":"skill","status":"published","risk_level":"trusted","grade":"A","install_count":3200,"avg_rating":4.7,"license":"MIT","keywords":["translation","i18n","l10n","language"],"category":"productivity","homepage":"https://github.com/test/lang-translation-skill"},
    # subagent 类型
    {"name":"【test】pr-review-subagent","type":"subagent","status":"published","risk_level":"medium_risk","grade":"C","install_count":540,"avg_rating":4.0,"license":"MIT","keywords":["pr","review","subagent","automation"],"category":"developer-tools","homepage":"https://github.com/test/pr-review-subagent"},
    {"name":"【test】docs-writer-subagent","type":"subagent","status":"published","risk_level":"low_risk","grade":"B","install_count":310,"avg_rating":4.2,"license":"MIT","keywords":["docs","generation","subagent","markdown"],"category":"developer-tools","homepage":"https://github.com/test/docs-writer-subagent"},
    # prompt 类型
    {"name":"【test】commit-msg-prompt","type":"prompt","status":"published","risk_level":"trusted","grade":"A","install_count":890,"avg_rating":4.6,"license":"MIT","keywords":["prompt","commit","message","conventional"],"category":"developer-tools","homepage":"https://github.com/test/commit-msg-prompt"},
    {"name":"【test】code-explainer-prompt","type":"prompt","status":"published","risk_level":"trusted","grade":"A","install_count":1200,"avg_rating":4.8,"license":"MIT","keywords":["prompt","explain","code","education"],"category":"education","homepage":"https://github.com/test/code-explainer-prompt"},
    # 更多 published 各种风险
    {"name":"【test】network-sniffer-command","type":"command","status":"published","risk_level":"high_risk","grade":"D","install_count":55,"avg_rating":2.9,"license":"MIT","keywords":["network","sniff","packet","diagnostic"],"category":"infrastructure","homepage":None},
    {"name":"【test】password-generator-skill","type":"skill","status":"published","risk_level":"low_risk","grade":"B","install_count":430,"avg_rating":4.3,"license":"MIT","keywords":["password","security","generator","utility"],"category":"security","homepage":"https://github.com/test/password-generator-skill"},
    {"name":"【test】git-workflow-plugin","type":"plugin","status":"published","risk_level":"trusted","grade":"A","install_count":2100,"avg_rating":4.7,"license":"MIT","keywords":["git","workflow","branch","merge"],"category":"devops","homepage":"https://github.com/test/git-workflow-plugin"},
    {"name":"【test】pdf-generator-command","type":"command","status":"published","risk_level":"medium_risk","grade":"C","install_count":290,"avg_rating":3.8,"license":"MIT","keywords":["pdf","generate","document","report"],"category":"productivity","homepage":"https://github.com/test/pdf-generator-command"},
    {"name":"【test】slack-notify-mcp","type":"mcp_server","status":"published","risk_level":"medium_risk","grade":"C","install_count":510,"avg_rating":4.0,"license":"MIT","keywords":["slack","notify","mcp","integration"],"category":"communication","homepage":"https://github.com/test/slack-notify-mcp"},
    {"name":"【test】bad-reputation-command","type":"command","status":"published","risk_level":"untrusted","grade":"E","install_count":8,"avg_rating":1.2,"license":"NONE","keywords":["untrusted","test","danger"],"category":"testing","homepage":None},

    # ── pending_review (5条) ──
    {"name":"【test】ai-prompt-optimizer","type":"skill","status":"pending_review","risk_level":"medium_risk","grade":"C","install_count":0,"avg_rating":None,"license":"MIT","keywords":["prompt","optimize","ai","llm"],"category":"ai-tools","homepage":"https://github.com/test/ai-prompt-optimizer"},
    {"name":"【test】image-resizer-mcp","type":"mcp_server","status":"pending_review","risk_level":"low_risk","grade":"B","install_count":0,"avg_rating":None,"license":"MIT","keywords":["image","resize","mcp","media"],"category":"media","homepage":"https://github.com/test/image-resizer-mcp"},
    {"name":"【test】test-generator-subagent","type":"subagent","status":"pending_review","risk_level":"medium_risk","grade":"C","install_count":0,"avg_rating":None,"license":"MIT","keywords":["test","generator","subagent","unit-test"],"category":"developer-tools","homepage":"https://github.com/test/test-generator-subagent"},
    {"name":"【test】json-formatter-command","type":"command","status":"pending_review","risk_level":"low_risk","grade":"B","install_count":0,"avg_rating":None,"license":"MIT","keywords":["json","format","cli","tool"],"category":"utility","homepage":"https://github.com/test/json-formatter-command"},
    {"name":"【test】multi-thread-plugin","type":"plugin","status":"pending_review","risk_level":"high_risk","grade":"D","install_count":0,"avg_rating":None,"license":"MIT","keywords":["multi-thread","plugin","performance","concurrent"],"category":"performance","homepage":"https://github.com/test/multi-thread-plugin"},

    # ── scanning (5条) ──
    {"name":"【test】file-system-mcp","type":"mcp_server","status":"scanning","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["filesystem","mcp","file","browse"],"category":"data","homepage":"https://github.com/test/file-system-mcp"},
    {"name":"【test】memory-cache-skill","type":"skill","status":"scanning","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["memory","cache","optimize"],"category":"performance","homepage":"https://github.com/test/memory-cache-skill"},
    {"name":"【test】log-parser-plugin","type":"plugin","status":"scanning","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["log","parse","analyze","debug"],"category":"developer-tools","homepage":"https://github.com/test/log-parser-plugin"},
    {"name":"【test】env-config-subagent","type":"subagent","status":"scanning","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["env","config","subagent","setup"],"category":"infrastructure","homepage":"https://github.com/test/env-config-subagent"},
    {"name":"【test】template-engine-prompt","type":"prompt","status":"scanning","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["template","engine","prompt","jinja"],"category":"developer-tools","homepage":"https://github.com/test/template-engine-prompt"},

    # ── draft (5条) ──
    {"name":"【test】note-taking-skill","type":"skill","status":"draft","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["notes","draft","organization"],"category":"productivity","homepage":None},
    {"name":"【test】time-tracker-command","type":"command","status":"draft","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["time","tracker","pomodoro","productivity"],"category":"productivity","homepage":None},
    {"name":"【test】calendar-sync-mcp","type":"mcp_server","status":"draft","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["calendar","sync","mcp","scheduling"],"category":"productivity","homepage":None},
    {"name":"【test】markdown-linter-plugin","type":"plugin","status":"draft","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["markdown","lint","format","docs"],"category":"developer-tools","homepage":None},
    {"name":"【test】code-metrics-prompts","type":"prompt","status":"draft","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["code","metrics","prompt","analysis"],"category":"developer-tools","homepage":None},

    # ── rejected (4条) ──
    {"name":"【test】shell-command-runner","type":"plugin","status":"rejected","risk_level":"untrusted","grade":"E","install_count":0,"avg_rating":None,"license":"MIT","keywords":["shell","command","executor","danger"],"category":"testing","homepage":None},
    {"name":"【test】crypto-miner-command","type":"command","status":"rejected","risk_level":"untrusted","grade":"E","install_count":0,"avg_rating":None,"license":"NONE","keywords":["crypto","miner","resource","abuse"],"category":"testing","homepage":None},
    {"name":"【test】keylogger-plugin","type":"plugin","status":"rejected","risk_level":"untrusted","grade":"E","install_count":0,"avg_rating":None,"license":"NONE","keywords":["keylogger","input","capture","danger"],"category":"testing","homepage":None},
    {"name":"【test】unsafe-exec-subagent","type":"subagent","status":"rejected","risk_level":"untrusted","grade":"E","install_count":0,"avg_rating":None,"license":"NONE","keywords":["unsafe","exec","subagent","danger"],"category":"testing","homepage":None},

    # ── changes_requested (4条) ──
    {"name":"【test】api-client-command","type":"command","status":"changes_requested","risk_level":"medium_risk","grade":"C","install_count":0,"avg_rating":None,"license":"Apache-2.0","keywords":["api","http","client","rest"],"category":"developer-tools","homepage":"https://github.com/test/api-client-command"},
    {"name":"【test】oauth-flow-skill","type":"skill","status":"changes_requested","risk_level":"medium_risk","grade":"C","install_count":0,"avg_rating":None,"license":"MIT","keywords":["oauth","auth","flow","security"],"category":"security","homepage":"https://github.com/test/oauth-flow-skill"},
    {"name":"【test】sms-sender-mcp","type":"mcp_server","status":"changes_requested","risk_level":"high_risk","grade":"D","install_count":0,"avg_rating":None,"license":"MIT","keywords":["sms","send","notification","mcp"],"category":"communication","homepage":"https://github.com/test/sms-sender-mcp"},
    {"name":"【test】batch-rename-prompt","type":"prompt","status":"changes_requested","risk_level":"low_risk","grade":"B","install_count":0,"avg_rating":None,"license":"MIT","keywords":["batch","rename","prompt","refactor"],"category":"developer-tools","homepage":"https://github.com/test/batch-rename-prompt"},

    # ── submitted (2条) ──
    {"name":"【test】data-migration-command","type":"command","status":"submitted","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["data","migration","cli","etl"],"category":"data","homepage":"https://github.com/test/data-migration-command"},
    {"name":"【test】csv-processor-mcp","type":"mcp_server","status":"submitted","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["csv","process","mcp","data"],"category":"data","homepage":"https://github.com/test/csv-processor-mcp"},

    # ── approved (2条) ──
    {"name":"【test】diagram-generator-skill","type":"skill","status":"approved","risk_level":"low_risk","grade":"B","install_count":0,"avg_rating":None,"license":"MIT","keywords":["diagram","generate","mermaid","visual"],"category":"developer-tools","homepage":"https://github.com/test/diagram-generator-skill"},
    {"name":"【test】spell-checker-plugin","type":"plugin","status":"approved","risk_level":"trusted","grade":"A","install_count":0,"avg_rating":None,"license":"MIT","keywords":["spell","checker","grammar","typo"],"category":"productivity","homepage":"https://github.com/test/spell-checker-plugin"},

    # ── error (2条) ──
    {"name":"【test】broken-build-command","type":"command","status":"error","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["broken","build","error","test"],"category":"testing","homepage":None},
    {"name":"【test】corrupt-package-skill","type":"skill","status":"error","risk_level":None,"grade":None,"install_count":0,"avg_rating":None,"license":"MIT","keywords":["corrupt","error","test","invalid"],"category":"testing","homepage":None},

    # ── yanked (1条) ──
    {"name":"【test】old-legacy-plugin","type":"plugin","status":"yanked","risk_level":"high_risk","grade":"D","install_count":95,"avg_rating":2.1,"license":"MIT","keywords":["legacy","yanked","deprecated","plugin"],"category":"utility","homepage":None},
]
# fmt: on


def _build_packages():
    packages = []
    versions = []
    for raw in PACKAGES_RAW:
        pkg_id = _uid("pkg")
        ver_id = _ver(pkg_id)
        name = raw["name"]
        ptype = raw["type"]
        status = raw["status"]
        ver = "1.0.0"
        risk = raw["risk_level"]
        grade = raw["grade"]

        pkg_json = {
            "id": pkg_id,
            "name": name,
            "type": ptype,
            "description": raw.get("description", f"{name} description"),
            "license": raw.get("license", "MIT"),
            "keywords": raw.get("keywords", []),
            "category": raw.get("category", "general"),
            "submitter_id": SUBMITTER_ID,
            "homepage": raw.get("homepage"),
            "owner": {"id": SUBMITTER_ID, "username": "submitter", "display_name": SUBMITTER_NAME, "role": "submitter"},
            "author": {"name": SUBMITTER_NAME, "email": "submitter@test.com"},
            "latest_version": ver,
            "status": status,
            "risk_level": risk,
            "grade": grade,
            "install_count": raw.get("install_count", 0),
            "avg_rating": raw.get("avg_rating"),
            "created_at": NOW,
            "updated_at": NOW,
        }

        # 版本数据
        trust_score = None
        if risk and grade:
            # 已评估的版本，带上 trust_score
            trust_score = {
                "model_version": "1.0.0",
                "risk_summary": {
                    "level": risk,
                    "grade": grade,
                    "top_risks": [],
                    "install_recommendation": (
                        "safe" if risk in ("trusted", "low_risk")
                        else ("review_recommended" if risk == "medium_risk" else "blocked")
                    ),
                },
                "calculated_at": NOW,
            }

        ver_json = {
            "id": ver_id,
            "package_id": pkg_id,
            "version": ver,
            "status": status,
            "description": raw.get("description", ""),
            "source": {
                "type": "github",
                "repository_url": raw.get("homepage") or f"https://github.com/test/{name}",
                "ref": "main",
                "commit_hash": "",
                "verified_owner": True,
            },
            "compatibility": ["codewhale"],
            "submitter_id": SUBMITTER_ID,
            "submitted_at": NOW,
            "created_at": NOW,
        }
        if trust_score:
            ver_json["trust_score"] = trust_score

        packages.append({
            "id": pkg_id,
            "name": name,
            "status": status,
            "latest_version": ver,
            "data": json.dumps(pkg_json, ensure_ascii=False),
        })
        versions.append({
            "id": ver_id,
            "package_id": pkg_id,
            "version": ver,
            "status": status,
            "data": json.dumps(ver_json, ensure_ascii=False),
        })

    return packages, versions


def main():
    import psycopg2
    conn = psycopg2.connect(host='localhost', port=5432, dbname='trusted_agent_hub', user='postgres', password='293021')
    cur = conn.cursor()

    # ── 清理旧数据（按依赖顺序：先子后父） ──
    print("[1/4] 清空旧数据...")
    tables = [
        "audit_logs", "feedback_records", "install_records",
        "trust_levels", "review_records", "scan_reports",
        "package_versions", "packages",
    ]
    for t in tables:
        cur.execute(f"DELETE FROM {t}")
        cur.execute(f"SELECT count(*) FROM {t}")
        remaining = cur.fetchone()[0]
        print(f"  {t}: {remaining} rows")
    conn.commit()

    # ── 生成新数据 ──
    print(f"\n[2/4] 生成 {len(PACKAGES_RAW)} 条包/版本数据...")
    packages, versions = _build_packages()

    # ── 插入 packages ──
    print("[3/4] 写入 packages...")
    insert_pkg_sql = (
        "INSERT INTO packages (id, name, status, latest_version, data) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    for p in packages:
        cur.execute(insert_pkg_sql, (p["id"], p["name"], p["status"], p["latest_version"], p["data"]))
        print(f"  + {p['name']} ({p['status']})")
    conn.commit()

    # ── 插入 versions ──
    print("[4/4] 写入 package_versions...")
    insert_ver_sql = (
        "INSERT INTO package_versions (id, package_id, version, status, data) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    for v in versions:
        cur.execute(insert_ver_sql, (v["id"], v["package_id"], v["version"], v["status"], v["data"]))
    conn.commit()

    cur.close()
    conn.close()
    print(f"\nDone! Wrote {len(packages)} packages + {len(versions)} versions.")


if __name__ == "__main__":
    main()
