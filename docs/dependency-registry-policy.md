# 依赖来源策略

SR-008 将依赖来源判断与依赖安全判断分开处理。来源策略只回答“这个端点是否被批准用于当前生态和用途”，不会跳过 OSV/CVE 查询、版本锁定检查、仓库来源完整性检查或其他扫描规则。

## 分类与报告行为

| 分类 | 来源 | 默认行为 |
| --- | --- | --- |
| `official` | 内置、具备官方文档证据的端点 | 允许策略声明的用途 |
| `authoritative_mirror` | 具备维护方证据的镜像 | 允许策略声明的用途；内置 Yarn Classic 默认 registry |
| `approved_private` | API 服务或本地扫描环境的运维配置 | 允许策略声明的用途 |
| `unknown` | 未命中以上条目 | 进入一次人工复核 advisory |

同一次扫描中的所有未批准来源会合并为一条 `dependency_registry_policy` advisory。它的级别为 `high`，要求人工复核，但不扣分、不改变评级，也不进入针对安全 findings 的 LLM 批处理。相同 `(ecosystem, URL, usage)` 在代码或多个来源中重复出现时只计为一条逻辑来源，文件分布仍单独列出。证据最多展示五个 host 和五个文件，并给出其余数量与各拒绝原因的计数。使用 HTTP 的依赖来源还会额外合并为一条 `medium` 安全 finding。

advisory 会按处置方式区分三类拒绝原因：`unknown_host`、`non_registry_source`、`invalid_url` 表示来源本身未经批准，应改用官方源或由运维审核私有源；`canonical_url_mismatch`、`wrong_ecosystem`、`unapproved_port`、`usage_not_allowed` 表示命中了已知端点但路径、生态、端口或用途不符合策略，通常应修正写法而不是新增审批；`insecure_scheme`、`credentials_in_url` 表示传输或凭据不安全，应改用 HTTPS 并移除 URL 内嵌凭据。具体 reason 及数量保留在 evidence 中。

`registry.npmmirror.com` 当前没有足够的官方归属证据，因此不作为 npm 官方源或内置权威镜像；它会落入 `unknown`，但无论有多少依赖使用它，都只产生一条来源策略 advisory。

GitHub、GitLab、Bitbucket 和 `raw.githubusercontent.com` 等 Git 托管主机不会仅凭主机名被放行。`package.json` 中的 `git+https://github.com/...`、requirements 中的 `name @ git+https://...`，以及安装脚本中的 `pip install git+https://...`，在未命中当前生态批准的条目时会进入同一条聚合 advisory；未匹配的托管主机归类为 `unknown`（原因码 `unknown_host`）。`git+ssh://...` 直链也会被采集，但因其不是 HTTPS 来源，策略以 `non_registry_source` 拒绝。需要批准 HTTPS 直链时，运维可通过 `TAH_APPROVED_PRIVATE_REGISTRIES_JSON` 添加例如 `ecosystem=npm`、`exact_host=github.com`、`allow_as_resolved_download=true` 的条目，并提供组织自己的证据与复核日期。批准整个托管主机意味着信任该主机上所有符合用途的直链，能使用更窄的 `canonical_url` 时应优先使用。

`package.json` 的直接依赖会采集带 `://` 的 URL（包括 `git+ssh://`），并将 `github:owner/repo`、`gitlab:owner/repo`、`bitbucket:owner/repo` 和 `owner/repo` 等 npm Git 简写转换为对应主机的 `git+https://...` 来源。Python requirements 会采集带 extras 的 `name[extra] @ URL` 直接引用，以及裸写或通过 `-e`/`--editable` 声明的 Git、Hg、SVN、Bzr 远程 URL；`git+ssh://` 等非 HTTPS 来源仍交由策略拒绝。requirements 中裸写的 HTTP(S) URL、`-f`/`--find-links` 指向的 HTTP(S) 地址，以及安装脚本中 `pip install -f URL` / `pip install --find-links URL` 使用的 HTTP(S) 地址，均按 `resolved_download` 采集。非 VCS 的 `-e`/`--editable` HTTP(S) URL 也会形成来源观察；有 `#egg=` 时关联显式依赖名，否则不推断名称。代码文本中的 URL 观察器只从 HTTP(S) URL 的依赖上下文采集来源，不会单独识别 `git+ssh://` 文本。Cargo lockfile 的显式 `source` 字段由结构化解析器记录。

## 匹配规则

- 只接受 HTTPS；HTTP、嵌入凭据、未经批准的端口均拒绝。
- `exact_host` 只匹配完全相同的主机名。不会隐式信任子域，也不接受 `*.example.com` 一类通配符。
- `canonical_url` 同时校验主机、端口和路径。以 `/` 结尾的目录型条目允许该目录及其下级路径，其他条目只允许精确路径。例如 PyPI Simple API 只批准 `/simple` 和 `/simple/...`，不会把同一主机上的任意路径当作 registry。
- 条目按生态隔离；npm 端点不能因为主机相同而自动成为 PyPI 或 Cargo 端点。
- 代码 URL 观察器无法推断生态时，仅可回退匹配全部生态中的 `official` 或 `approved_private` 条目：`canonical_url` 条目仍要求 host/path 一致，`exact_host` 条目本身没有路径约束，因此只要求主机名一致；两者仍必须通过 HTTPS、端口与用途校验。未命中时按 `unknown_host` 拒绝。已明确推断为 npm/PyPI/Cargo/NuGet 时仍严格执行生态隔离。
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

来源观察来自 npm `package-lock.json` / `npm-shrinkwrap.json` / `yarn.lock` / `pnpm-lock.yaml` / `.npmrc`、Python requirements / `Pipfile.lock` / `poetry.lock` / Poetry source 配置，以及 Cargo lock/source 配置。依赖文件中的 integrity/checksum 会保留在规范化记录中，但当前改动没有新增依赖制品下载或哈希复算，因此不能把“存在 integrity 字段”表述为“制品完整性已验证”。
