#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
金丝雀落点服务 —— 记录「谁」来抓了图片。

用途：把本服务部署在你能看到访问日志的云服务器上，然后把它的地址作为 image_url
放进请求里发给各家上游。上游（Azure OpenAI / OpenAI 官方）会从自己的机房去拉这张图，
于是你的日志里就留下了抓取方的真实出口 IP。据此判断某条声称是 Azure 的渠道，
其图片抓取出口是否真的落在微软侧。

纯标准库实现，无第三方依赖。

运行：
    python server.py                      # 监听 0.0.0.0:8080
    python server.py --port 80            # 换端口
    CANARY_DATA=/data python server.py    # 指定日志落盘目录（容器里用这个）

接口：
    GET  /canary?g=<tag>      返回 1x1 PNG，并记录请求方信息
    GET  /                   健康检查，返回 JSON 统计
    POST /canary?g=<tag>      同上，兼容可能用 POST 的抓取器

数据：
    所有命中追加写入 $CANARY_DATA/canary_hits.jsonl（默认 ./data/canary_hits.jsonl）
    / 接口会实时汇总按 tag 与来源 IP 的聚合结果
"""
import argparse
import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 1x1 合法 PNG（红色像素）。已用 PIL 校验可被解析，勿手改。
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d4944415478da63f8cfc0f01f00050001ff57c72f0d"
    "0000000049454e44ae426082"
)

DATA_DIR = os.environ.get("CANARY_DATA", "./data")
LOG_PATH = os.path.join(DATA_DIR, "canary_hits.jsonl")
LOCK = threading.Lock()

# 判断抓取方归属时，优先看的请求头（有些抓取器会带，能辅助判断）
UA_INTEREST = ("user-agent", "x-forwarded-for", "x-real-ip", "via", "x-ms-", "x-azure-",
               "x-openai-", "openai-", "azure", "x-request-id", "apim-request-id")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def append_hit(entry):
    os.makedirs(DATA_DIR, exist_ok=True)
    with LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[warn] 写日志失败: {e}", file=sys.stderr)


def load_hits():
    hits = []
    if not os.path.exists(LOG_PATH):
        return hits
    with LOCK:
        try:
            with open(LOG_PATH, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            hits.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
    return hits


def summarize(hits):
    """按 tag -> 来源 IP 聚合，并给出两组是否共用出口的判断。"""
    by_tag = {}
    by_ip = {}
    for h in hits:
        tag = (parse_qs(h.get("query") or "").get("g") or ["-"])[0] or "-"
        ip = h.get("peer_ip") or "?"
        by_tag.setdefault(tag, {}).setdefault(ip, 0)
        by_tag[tag][ip] += 1
        by_ip.setdefault(ip, {"count": 0, "tags": set(), "ua": set()})
        by_ip[ip]["count"] += 1
        by_ip[ip]["tags"].add(tag)
        if h.get("user_agent"):
            by_ip[ip]["ua"].add(h["user_agent"][:120])

    verdict = "数据不足"
    if len(by_tag) >= 2:
        sets = [set(v.keys()) for v in by_tag.values()]
        common = set.intersection(*sets) if sets else set()
        if common:
            verdict = f"两组共用出口 IP {sorted(common)}，Azure 标签可疑"
        else:
            verdict = "两组来源 IP 无交集，出口不同"

    return {
        "total_hits": len(hits),
        "by_tag": {t: dict(sorted(v.items(), key=lambda kv: -kv[1])) for t, v in by_tag.items()},
        "by_ip": {ip: {"count": v["count"], "tags": sorted(v["tags"]), "ua": sorted(v["ua"])}
                  for ip, v in sorted(by_ip.items(), key=lambda kv: -kv[1]["count"])},
        "verdict": verdict,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "canary/2.0"
    protocol_version = "HTTP/1.1"

    def _record(self, method):
        peer = self.client_address[0]
        parsed = urlparse(self.path)
        headers = {k: v for k, v in self.headers.items()}
        entry = {
            "ts": utcnow(),
            "method": method,
            "path": parsed.path,
            "query": parsed.query,
            "tag": (parse_qs(parsed.query).get("g") or [""])[0],
            "peer_ip": peer,
            "peer_port": self.client_address[1],
            "xff": headers.get("X-Forwarded-For"),
            "x_real_ip": headers.get("X-Real-IP"),
            "user_agent": headers.get("User-Agent"),
            "headers": headers,
        }
        append_hit(entry)

        tag = entry["tag"]
        flag = f"   <<== 探针标记 g={tag}" if tag else ""
        print(f"\n[{entry['ts']}] {method} {self.path}{flag}", flush=True)
        print(f"    来源 IP : {peer}", flush=True)
        if entry["xff"]:
            print(f"    XFF     : {entry['xff']}", flush=True)
        print(f"    UA      : {entry['user_agent']}", flush=True)
        for k, v in headers.items():
            kl = k.lower()
            if kl in ("user-agent", "host", "accept", "accept-encoding", "connection", "content-length"):
                continue
            if any(kl.startswith(p) or p in kl for p in UA_INTEREST) or True:
                print(f"    {k}: {v[:130]}", flush=True)

    def _send_png(self):
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(PNG)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        try:
            self.wfile.write(PNG)
        except Exception:
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/health", "/summary"):
            hits = load_hits()
            body = json.dumps(summarize(hits), ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._record("GET")
        self._send_png()

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path in ("/", "/health", "/summary"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._record("HEAD")
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(PNG)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            try:
                self.rfile.read(length)
            except Exception:
                pass
        self._record("POST")
        self._send_png()

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"金丝雀落点已启动: http://{args.host}:{args.port}/canary", flush=True)
    print(f"日志: {os.path.abspath(LOG_PATH)}", flush=True)
    print(f"汇总: http://{args.host}:{args.port}/  (JSON)", flush=True)
    print("把图片 URL 设为: http://<你的公网地址>/canary?g={tag}\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n收到中断，退出。", flush=True)
    finally:
        httpd.server_close()
        print(json.dumps(summarize(load_hits()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
