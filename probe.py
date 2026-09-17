#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
金丝雀测试端 —— 用各组 base_url + key 发起请求，触发上游去抓你的落点图片，
然后从落点读回抓取方 IP，判断每个分组的上游出口。

依赖：requests（或用 --stdlib 走纯标准库，但流式处理会简化）

用法：
    # 1) 直接测试远端落点，并自动读取落点汇总
    python probe.py --canary http://1.2.3.4:8080

    # 2) 用自定义分组（默认读同目录 groups.json，或 .env）
    python probe.py --canary http://1.2.3.4:8080 --groups groups.json

    # 3) 只发起请求，不读汇总（落点在别处时）
    python probe.py --canary http://1.2.3.4:8080 --no-summary

.env 里识别的键（同 147ai 的命名习惯）：
    GPTOPENAI_BASE_URL / GPTOPENAI_API_KEY
    GPTAZ_BASE_URL     / GPTAZ_API_KEY
    GPTCODEX_BASE_URL  / GPTCODEX_API_KEY   （可选）

也可用 groups.json：
    {
      "openai": {"base_url": "https://api.147ai.cn", "api_key": "sk-..."},
      "azure":  {"base_url": "https://api.147ai.cn", "api_key": "sk-..."}
    }
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def resolve_groups(args):
    """优先级：--groups 文件 > .env > 同目录 groups.json"""
    if args.groups:
        with open(args.groups, encoding="utf-8") as f:
            raw = json.load(f)
        return {k: (v["base_url"], v["api_key"]) for k, v in raw.items()}

    for cand in (args.env, os.path.join(HERE, ".env"),
                 os.path.join(HERE, "..", ".env"), r"D:\147ai\test\.env"):
        env = load_env(cand)
        if env.get("GPTOPENAI_BASE_URL") or env.get("GPTAZ_BASE_URL"):
            groups = {}
            pairs = [("openai", "GPTOPENAI"), ("azure", "GPTAZ"), ("codex", "GPTCODEX")]
            for tag, prefix in pairs:
                b, k = env.get(f"{prefix}_BASE_URL"), env.get(f"{prefix}_API_KEY")
                if b and k:
                    groups[tag] = (b, k)
            print(f"[i] 分组来自 {os.path.abspath(cand)}: {sorted(groups)}")
            return groups

    p = os.path.join(HERE, "groups.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            raw = json.load(f)
        groups = {k: (v["base_url"], v["api_key"]) for k, v in raw.items()}
        print(f"[i] 分组来自 {p}: {sorted(groups)}")
        return groups

    sys.exit("找不到分组配置：请用 --groups，或提供含 GPTOPENAI_BASE_URL/GPTAZ_BASE_URL 的 .env")


def post_image(base, key, model, image_url, timeout=180):
    payload = {
        "model": model,
        "max_completion_tokens": 40,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Describe this image in one short sentence."},
                {"type": "image_url", "image_url": {"url": image_url}},
            ],
        }],
    }
    url = base.rstrip("/") + "/v1/chat/completions"
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
    t0 = time.time()
    if HAVE_REQUESTS:
        r = requests.post(url, headers=headers, json=payload, timeout=(20, timeout))
        dt = round(time.time() - t0, 2)
        return r.status_code, r.text[:400], dt
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(400).decode("utf-8", "replace"), round(time.time() - t0, 2)
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace"), round(time.time() - t0, 2)


def fetch_summary(canary, timeout=30):
    """读落点的汇总接口，拿到抓取方 IP 聚合。"""
    url = canary.rstrip("/") + "/"
    try:
        if HAVE_REQUESTS:
            r = requests.get(url, timeout=timeout)
            return r.json()
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)[:200]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--canary", required=True,
                    help="落点地址，例如 http://1.2.3.4:8080 （不要带 /canary）")
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--groups", help="groups.json 路径")
    ap.add_argument("--env", default=r"D:\147ai\test\.env", help=".env 路径")
    ap.add_argument("--repeat", type=int, default=1, help="每个分组重复几次")
    ap.add_argument("--interval", type=float, default=2.0, help="重复之间的间隔秒")
    ap.add_argument("--no-summary", action="store_true", help="不读落点汇总")
    args = ap.parse_args()

    groups = resolve_groups(args)
    canary_base = args.canary.rstrip("/")

    print(f"\n落点: {canary_base}")
    print(f"模型: {args.model}   每组重复: {args.repeat}\n")
    print("-" * 84)

    issued = {}
    for tag, (base, key) in groups.items():
        for i in range(args.repeat):
            img = f"{canary_base}/canary?g={tag}&n={i}&t={int(time.time())}"
            try:
                code, body, dt = post_image(base, key, args.model, img)
            except Exception as e:
                code, body, dt = "ERR", str(e)[:200], 0
            mark = "✓" if code == 200 else "✗"
            print(f"[{mark}] {tag:8s} #{i}  HTTP {code}  {dt}s  url={img}")
            print(f"         响应: {body[:200].replace(chr(10), ' ')}")
            issued.setdefault(tag, []).append(img)
            time.sleep(args.interval)

    print("-" * 84)
    if args.no_summary:
        print("已发起请求。请到落点看日志：", f"{canary_base}/")
        return

    # 给落点一点时间把日志落盘（上游抓图与响应是并发的）
    time.sleep(3)
    s = fetch_summary(canary_base)
    print("\n=== 落点汇总 ===")
    print(json.dumps(s, ensure_ascii=False, indent=2))

    if isinstance(s, dict) and s.get("by_tag"):
        print("\n=== 判读 ===")
        by_tag = s["by_tag"]
        for tag, ips in by_tag.items():
            print(f"  {tag:8s} 来源 IP: {list(ips.keys())}")
        if len(by_tag) >= 2:
            sets = [set(v.keys()) for v in by_tag.values()]
            common = set.intersection(*sets)
            if common:
                print(f"\n  两组存在公共出口 {sorted(common)} → 可能共用同一上游，Azure 标签可疑")
            else:
                print("\n  两组来源 IP 无交集 → 出口不同，与「Azure 走微软侧」一致")
        print("\n  把这些 IP 拿去查 ASN：")
        for tag, ips in by_tag.items():
            for ip in ips:
                print(f"    https://ipinfo.io/{ip}/org     ({tag})")
        print("""
  判读标准：
    · azure 组抓取 IP 落在微软网络（AS8075），且与 openai 组不同 → Azure 标签可信
    · 两组抓取 IP 完全相同 → 共用同一出口，Azure 标签可疑
    · 某组没有记录 → 该组上游没抓（可能被网关改写为 base64，或该渠道不支持图片输入）
  注意：OpenAI 自身部分算力在微软云上，所以「IP 属微软 ASN」是强旁证，需与
        越狱分类器结论等其他证据合并判断，不要单独当铁证。
""")


if __name__ == "__main__":
    main()
