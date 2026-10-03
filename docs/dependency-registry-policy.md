# 依赖来源策略

SR-008 将依赖来源判断与依赖安全判断分开处理。来源策略只回答“这个端点是否被批准用于当前生态和用途”，不会跳过 OSV/CVE 查询、版本锁定检查、仓库来源完整性检查或其他扫描规则。

## 分类与报告行为

| 分类 | 来源 | 默认行为 |
| --- | --- | --- |
| `official` | 内置、具备官方文档证据的端点 | 允许策略声明的用途 |
| `authoritative_mirror` | 具备维护方证据的镜像 | 允许策略声明的用途；内置 Yarn Classic 默认 registry |
| `approved_private` | API 服务或本地扫描环境的运维配置 | 允许策略声明的用途 |
| `unknown` | 未命中以上条目 | 按仓库与来源文件聚合进入人工复核 advisory |

未批准来源按 `(ecosystem, registry host, 来源文件, policy reason)` 合并为 `dependency_registry_policy` advisory。每组 `occurrence_count` 保留全量计数，`registry_policy.occurrences` 按稳定顺序展示最多 100 条样本，并用 `truncated` 标记剩余记录；整份报告最多展示 25 个来源策略分组和 500 条样本。超出的分组聚合为一条含省略分组数、记录数和原因摘要的 advisory。样本包含依赖名、版本、锁文件指针或行号、resolved URL、integrity、用途和 runtime/dev/test 等范围；单项过长的文本也会截断并以省略号标记。URL 在报告中会移除用户信息、查询参数和片段，避免泄露认证值。审核页默认折叠逐条证据，可展开查看。组内有多种范围时标为 `mixed`；只涉及 dev/test 的组为 `warning`，涉及 runtime、optional 或未知范围的组为 `high`。来源策略 advisory 要求人工复核，但不扣分、不改变评级，也不进入针对安全 findings 的 LLM 批处理。使用 HTTP 的依赖来源还会额外合并为一条 `medium` 安全 finding。

按 [npm lockfile 字段说明](https://docs.npmjs.com/files/package-lock.json/)，`devOptional=true` 表示依赖同时出现在开发依赖和非开发依赖的可选树中，因此归为 `mixed`；`dev=true` 与 `optional=true` 同时存在但没有 `devOptional` 时归为 `dev`。

advisory 会按处置方式区分三类拒绝原因：`unknown_host`、`non_registry_source`、`invalid_url` 表示来源本身未经批准，应改用官方源或由运维审核私有源；`canonical_url_mismatch`、`wrong_ecosystem`、`unapproved_port`、`usage_not_allowed` 表示命中了已知端点但路径、生态、端口或用途不符合策略，`ambiguous_ecosystem` 表示安装器上下文存在歧义、无法安全选择生态批准项，这些情况通常应修正写法或确认实际生态而不是新增审批；`insecure_scheme`、`credentials_in_url` 表示传输或凭据不安全，应改用 HTTPS 并移除 URL 内嵌凭据。具体 reason 及数量保留在 evidence 中。

`registry.npmmirror.com` 当前没有足够的官方归属证据，因此不作为 npm 官方源或内置权威镜像；它会落入 `unknown`。同一锁文件中的大量依赖会聚合为一条来源策略 advisory。

GitHub、GitLab、Bitbucket 和 `raw.githubusercontent.com` 等 Git 托管主机不会仅凭主机名被放行。`package.json` 中的 `git+https://github.com/...`、requirements 中的 `name @ git+https://...`，以及安装脚本中的 `pip install git+https://...`，在未命中当前生态批准的条目时按来源文件、生态、主机和拒绝原因聚合；未匹配的托管主机归类为 `unknown`（原因码 `unknown_host`）。`git+ssh://...` 直链也会被采集，但因其不是 HTTPS 来源，策略以 `non_registry_source` 拒绝。需要批准 HTTPS 直链时，运维可通过 `TAH_APPROVED_PRIVATE_REGISTRIES_JSON` 添加例如 `ecosystem=npm`、`exact_host=github.com`、`allow_as_resolved_download=true` 的条目，并提供组织自己的证据与复核日期。批准整个托管主机意味着信任该主机上所有符合用途的直链，能使用更窄的 `canonical_url` 时应优先使用。

`package.json` 的直接依赖会采集带 `://` 的 URL（包括 `git+ssh://`），并将 `github:owner/repo`、`gitlab:owner/repo`、`bitbucket:owner/repo` 和 `owner/repo` 等 npm Git 简写转换为对应主机的 `git+https://...` 来源。Python requirements 会采集带 extras 的 `name[extra] @ URL` 直接引用，以及裸写或通过 `-e`/`--editable` 声明的 Git、Hg、SVN、Bzr 远程 URL；`git+ssh://` 等非 HTTPS 来源仍交由策略拒绝。requirements 中裸写的 HTTP(S) URL、`-f`/`--find-links` 指向的 HTTP(S) 地址，以及安装脚本中 `pip install -f URL` / `pip install --find-links URL` 使用的 HTTP(S) 地址，均按 `resolved_download` 采集。非 VCS 的 `-e`/`--editable` HTTP(S) URL 也会形成来源观察；有 `#egg=` 时关联显式依赖名，否则不推断名称。代码文本中的 URL 观察器只从 HTTP(S) URL 的依赖上下文采集来源，不会单独识别 `git+ssh://` 文本。Cargo lockfile 的显式 `source` 字段由结构化解析器记录。

requirements 与安装脚本中的 `\` 续行先折叠为逻辑行，再按每个 URL 绑定的选项分类，并保留原始行号作为证据。`--index-url` 的值为 `registry_api`，`-f`/`--find-links` 的值为 `resolved_download`；位置参数 URL 不会因前一行的 registry 选项被放行，端点仅获批 registry API 用途时会产生 `usage_not_allowed`。

requirements 的源配置只从逻辑行前导选项序列采集，支持同一逻辑行中的多个源选项。依赖声明、直接引用 URL 或带引号的参数内容中的 `--index-url`、`-f` 等文本不会成为额外源配置，也不会污染后续依赖的 registry。遇到 editable 或包含文件选项时停止解析，保留此前源声明作为静态审查证据；这不表示 pip 会将混合行中的 index 应用为后续安装的全局源。独立 `=` 等非 URL 值不会覆盖 registry。

续行保留缩进，因此 `--index-url=\` 后接缩进 URL 会形成空值选项和单独的 URL。安装脚本将后者按位置参数下载分类；requirements 保守保留 `resolved_download` 观察，不新增依赖记录，也不授予 registry API 用途。这不表示 pip 会实际安装该 URL。需要缩进填写 registry 地址时使用 `--index-url \`（不带等号）；npm 的 `--registry` 同理。

安装脚本按 URL 所在命令段的安装器及其绑定选项推断生态。未被引号包裹的 `&&`、`||`、`;`、`|` 等运算符分隔命令段，其他命令、包名与 URL 中的 npm/pip 字样不会决定当前 URL 的生态。安装器归属不明确或与选项冲突时保留 `unknown` 并标记歧义，以 `ambiguous_ecosystem` 提示人工复核。

## 匹配规则

- 只接受 HTTPS；HTTP、嵌入凭据、未经批准的端口均拒绝。
- `exact_host` 只匹配完全相同的主机名。不会隐式信任子域，也不接受 `*.example.com` 一类通配符。
- `canonical_url` 同时校验主机、端口和路径。以 `/` 结尾的目录型条目允许该目录及其下级路径，其他条目只允许精确路径。例如 PyPI Simple API 只批准 `/simple` 和 `/simple/...`，不会把同一主机上的任意路径当作 registry。
- 条目按生态隔离；npm 端点不能因为主机相同而自动成为 PyPI 或 Cargo 端点。
- 代码 URL 观察器缺少安装器上下文、无法推断生态时，仅可回退匹配全部生态中的 `official` 或 `approved_private` 条目：`canonical_url` 条目仍要求 host/path 一致，`exact_host` 条目本身没有路径约束，因此只要求主机名一致；两者仍必须通过 HTTPS、端口与用途校验。未命中时按 `unknown_host` 拒绝。已明确推断为 npm/PyPI/Cargo/NuGet 时仍严格执行生态隔离；存在生态歧义的观察不使用此回退。
- `resolved_download` 只有在条目显式设置 `allow_as_resolved_download=true` 时才获批。
- URL 查询参数中出现官方地址不会改变实际主机判断，重定向器也不会被当作官方端点。

## 内置端点

策略版本 `2026-09-22` 的内置条目如下。`reviewed_at` 均为 `2026-09-22`。

| 生态 | 匹配目标 | 分类 | 下载用途 | 证据 |
| --- | --- | --- | --- | --- |
| npm | `registry.npmjs.org` | `official` | 允许 | [npm registry 文档](https://docs.npmjs.com/cli/v11/using-npm/registry/) |
| npm | `registry.yarnpkg.com` | `authoritative_mirror` | 允许 | [Yarn Classic 配置文档](https://classic.yarnpkg.com/lang/en/docs/cli/config/) |
| PyPI | `https://pypi.org/simple/` | `official` | 不允许 | [Python Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/) |
| PyPI | `files.pythonhosted.org` | `official` | 允许 | [PyPI API 文档](https://docs.pypi.org/api/) |
| Cargo | `https://github.com/rust-lang/crates.io-index` | `official` | 不允许 | [Cargo registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html) |
| Cargo | `https://index.crates.io/` | `official` | 不允许 | [Cargo registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html) |
| Cargo | `https://crates.io/` | `official` | 不允许 | [Cargo registries](https://doc.rust-lang.org/cargo/reference/registries.html) |
| NuGet | `https://api.nuget.org/v3/index.json` | `official` | 不允许 | [NuGet service API](https://learn.microsoft.com/en-us/nuget/api/overview) |

NuGet 条目用于完整表达策略目录；当前依赖解析器尚未解析 NuGet 项目或锁文件，因此不会据此声称完成了 NuGet 依赖覆盖。

## 批准组织私有源

私有源只能由 API 服务进程或本地 Python 扫描器进程的环境变量 `TAH_APPROVED_PRIVATE_REGISTRIES_JSON` 注入，单个扫描请求不能自行扩大信任范围。值是 JSON 数组，每项必须包含：

- `ecosystem`：`npm`、`pypi`、`cargo` 或 `nuget`；
- `exact_host` 或 `canonical_url`，二选一；
- `evidence_url`、`note`、`reviewed_at`；
- 可选的布尔值 `allow_as_resolved_download`，默认 `false`。

示例：

```json
[
  {
    "ecosystem": "npm",
    "exact_host": "npm.corp.example",
    "evidence_url": "https://security.corp.example/registries/npm",
    "allow_as_resolved_download": true,
    "note": "Company-managed npm proxy.",
    "reviewed_at": "2026-09-20"
  }
]
```

配置解析采用 fail-closed：API 应用启动时会构造一次不可变策略；未知字段、通配 host、非 HTTPS canonical/evidence URL、缺失审计字段或不支持的生态都会阻止服务启动，而不是让每个扫描任务分别失败或静默放行。后续 API 扫描复用同一策略实例。直接运行 `python -m scanners.risk_scanner.scanner ...` 时，CLI 会在扫描前从同名环境变量构造策略，非法配置同样会终止扫描。

## 当前解析覆盖

来源观察来自 npm `package-lock.json` / `npm-shrinkwrap.json` / `yarn.lock` / `pnpm-lock.yaml` / `.npmrc`、Python requirements / `Pipfile.lock` / `poetry.lock` / Poetry source 配置，以及 Cargo lock/source 配置。依赖文件中的 integrity/checksum 会保留在规范化记录中。`dependency_scan.integrity` 单独报告声明数、实际验证数和不匹配数。生产 API 在扫描器运行前通过独立的受信任获取层处理 lockfile：只读取扫描策略允许的 lockfile，只访问 registry policy 已批准的 HTTPS 下载地址，逐跳复核重定向和 DNS/IP，拒绝歧义 HTTP 分帧，并限制并发、单件大小、总流量与整个获取批次的共用超时；制品采用流式摘要，不保存正文。摘要结果通过 `RiskScanner(dependency_verifications=...)` 传入；测试和其他受信任调用方仍可使用兼容的 `dependency_artifacts={resolved_url: bytes}` 接口。

`not_checked` 表示获取阶段未启用；`unsupported` 表示摘要算法或格式均不受支持；获取被策略阻止、超时、达到制品预算或只完成一部分时，`dependency_scan.integrity` / `artifact_acquisition` 的覆盖状态为 `partial`，并通过 `unavailable_count`、`unsupported_count` 与 `unavailable_reasons` 说明原因，不能把未取得的制品当作已验证。这类获取覆盖缺口会生成零扣分的 `dependency_artifact_coverage` provenance advisory，供审核页展示和人工复核；它本身不会改变自动安全评级。lockfile 读取/解析错误和漏洞查询覆盖缺口会传播为非完整的报告级状态。`dependency_scan.artifact_acquisition` 保留 URL-free 的获取覆盖摘要和 `collection_errors`，使没有产生依赖记录的解析失败也保持可审计。运维可用 `TAH_DEPENDENCY_ARTIFACT_VERIFICATION_ENABLED` 禁用获取，或通过 `TAH_DEPENDENCY_ARTIFACT_MAX_ARTIFACTS`、`TAH_DEPENDENCY_ARTIFACT_MAX_CONCURRENCY`、`TAH_DEPENDENCY_ARTIFACT_MAX_BYTES`、`TAH_DEPENDENCY_ARTIFACT_MAX_TOTAL_BYTES` 和 `TAH_DEPENDENCY_ARTIFACT_TIMEOUT_SECONDS` 调整边界。扫描器本身不会请求不可信锁文件 URL。

漏洞查询先按生态、规范化包名和精确版本去重，并把清单范围声明映射到对应的 lockfile 坐标；随后通过 OSV `querybatch` 在有界并发、批大小、单次超时和指数退避重试下查询。生产 API 默认每次扫描最多查询 5000 个未命中缓存的坐标，而不是静默截断到 10 个。成功结果写入默认位于 `ARTIFACTS_ROOT/scanner-cache` 的私有 SQLite 缓存，后续扫描或中断重跑可以按 TTL 续用；该子目录不属于公开制品下载命名空间。`dependency_scan` 会报告 `total_unique_dependencies`、`queryable`、`queried`、`succeeded`、`failed`、`skipped`、`unsupported`、`rate_limited`、`remaining`，并最多为 500 个坐标保留数据源、查询时间、HTTP 状态、失败原因及 `source_file` / `scope` / registry 出现位置；其余坐标仍计入汇总，并通过 `query_results_truncated` 明示截断。状态区分 `complete`、`partial`、`failed`、`unavailable`、`unsupported` 和 `not_queried`；只要仍有未评估坐标，`dependency_check.known_vulnerabilities` 就是 `null`，不能把未完成查询解释为零漏洞，且报告级状态为非完整。相关边界由 `TAH_OSV_MAX_QUERIES`、`TAH_OSV_BATCH_SIZE`、`TAH_OSV_MAX_CONCURRENCY`、`TAH_OSV_TIMEOUT_SECONDS`、`TAH_OSV_MAX_RETRIES`、`TAH_OSV_RETRY_BACKOFF_MILLISECONDS`、`TAH_OSV_CACHE_TTL_SECONDS` 和 `TAH_OSV_CACHE_PATH` 配置。

`TAH_OSV_ENABLED=false` 可在离线或合规受限环境中禁止 OSV 查询，此时报告以 `not_queried` 明示未评估状态。`TAH_OSV_BASE_URL` 只接受 HTTPS 服务端根地址（回环开发地址可使用 HTTP），可用于组织内部镜像；缓存按该地址隔离。SQLite 缓存启用 WAL，进程内写入会串行执行；初始化时会清理过期项并仅保留最新 20 万行，读写失败后当前客户端会停用持久缓存。默认 `TAH_OSV_ALLOW_PRIVATE_COORDINATES=false`，明确来自批准私有源或未识别 registry 的包名和版本不会发送给 OSV，并以 `non_public_registry_not_queried` 记录；只有运维明确评估数据出站政策后才能启用。`system`、`docker`、`mcp_servers` 等非 OSV 包生态不会伪装成查询坐标，而是在 `non_osv_manifest_dependencies` 中单独列出。

`dependency_scan.manifest_lock` 对同目录的 `package.json` 和 npm lockfile v2/v3 的根声明进行保守比对：相同字符串与等价的精确版本可判为一致；缺失声明或不同的精确版本产生独立的 SR-008 finding；其他范围、`file:`、`workspace:` 等无法在静态扫描中证明等价的写法计入 `unchecked_count`，状态为 `partial`，不会误报为不一致。没有可比对的根声明时为 `not_checked`。确定性的 registry、已知漏洞、HTTP 传输、版本、typosquatting、完整性和清单差异结果不送入语义 LLM 审核；只有显式标记为需要语义判断、且具有真实扫描文件和有效行号的源码 finding 才能进入候选集合。
