# 金丝雀图片落点（canary-image-probe）

判断一条声称是 **Azure** 的 GPT 渠道，其图片抓取出口是否真的落在微软侧。

## 原理

把一张图的 URL 放进请求里发给上游。上游会**从自己的机房去拉这张图**（不是中转代拉，
已实测：慢速 URL 会让上游报出自己的下载超时）。于是你那台服务器的访问日志里，
就留下了抓取方的真实出口 IP。

- 两组的抓取 IP 不同，且 azure 组落在微软网络（AS8075）→ Azure 标签可信度高
- 两组抓取 IP 完全相同 → 共用同一出口，Azure 标签可疑
- 某组没有记录 → 该组没抓图（可能被网关改写为 base64，或该渠道不支持图片输入）

> 保留一句：OpenAI 自身有相当一部分算力跑在微软云上，所以「IP 属于微软 ASN」是强旁证，
> 不是铁证。要与越狱分类器探针的结论合并判断，两条独立证据同向才站得住。

## 部署到云服务器（Docker）

```bash
# 1. 上传本目录到服务器
scp -r canary-image-probe root@<你的服务器>:/opt/

# 2. 起服务
cd /opt/canary-image-probe
docker compose up -d --build

# 3. 确认可用（返回 image/png 即可）
curl -sI http://127.0.0.1:8080/canary?g=selftest
curl -s  http://127.0.0.1:8080/            # 看 JSON 汇总

# 4. 放行防火墙（示例：ufw）
ufw allow 8080/tcp
```

安全组也要放行对应的入方向端口。

**关键：不要挂在 CDN / 反向代理后面。** 否则你记到的是 CDN 的 IP，取证就失效了。
如果必须挂，请让反代把 `X-Forwarded-For` 透传进来（本服务会同时记录该头，但真实性
依赖反代配置，取证强度会下降）。

## 测试

在能访问 `.env` 的机器上（本机即可）：

```bash
# 自动读 .env 里的 GPTOPENAI_* / GPTAZ_*，并向落点发起请求
python probe.py --canary http://<你的服务器>:8080

# 指定模型与重复次数（重复有助于排除偶发缓存）
python probe.py --canary http://<你的服务器>:8080 --model gpt-4o --repeat 2
```

`probe.py` 会：
1. 为每个分组生成带唯一标记的 URL（`?g=openai` / `?g=azure`），从 `.env` 取 base_url + key 发起请求；
2. 读落点的 `/` 汇总接口，把抓取方 IP 按组打印出来；
3. 给出判读结论并列出每个 IP 的 ASN 查询链接。

拿到 IP 后查归属：

```bash
curl -s https://ipinfo.io/<ip>/org
```

## 分组配置

优先级：`--groups` 文件 > `--env` 指定的 .env > 同目录/上级目录的 .env > 本目录 groups.json。

`groups.json` 格式（不想动 .env 时用）：

```json
{
  "openai": { "base_url": "https://api.example.com", "api_key": "sk-xxx" },
  "azure":  { "base_url": "https://api.example.com", "api_key": "sk-yyy" }
}
```

`.env` 里识别的键：

```
GPTOPENAI_BASE_URL / GPTOPENAI_API_KEY
GPTAZ_BASE_URL     / GPTAZ_API_KEY
GPTCODEX_BASE_URL  / GPTCODEX_API_KEY   （可选）
```

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/canary?g=<tag>` | 返回 1x1 PNG，记录请求方 IP / UA / 全部请求头 |
| GET | `/` 或 `/health` | JSON 汇总：按 tag 与来源 IP 聚合，附判读结论 |
| POST | `/canary?g=<tag>` | 同 GET，兼容用 POST 的抓取器 |
| HEAD | `/canary?g=<tag>` | 只探活不取图 |

## 日志

- 命中明细：`./data/canary_hits.jsonl`（宿主机，每行一条 JSON，含全部请求头）
- 容器实时输出：`docker compose logs -f canary`

建议在测试前先清空，避免旧记录混淆：

```bash
rm -f data/canary_hits.jsonl && docker compose restart canary
```

## 排障

**落点没有记录**：先确认安全组/防火墙放行、`curl` 从外网能访问到；
再确认上游是否真的抓图——如果某渠道把 image_url 转成 base64 后转发，就不会有记录，
这条路对该渠道不适用。

**上游报错说不是图片**：本服务返回的是经 PIL 校验的合法 1x1 PNG；
若仍报错，检查是否被中间的网关改写了 Content-Type。

**IP 是内网地址或 CDN 段**：说明落点前面有代理，需要直连或用 `X-Forwarded-For`（真实性会下降）。

**抓取多次出现**：上游可能有重试，或你重复跑了 `probe.py`。用 `n=` 参数区分每次请求。
