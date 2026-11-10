# worse_query 验证工程（wqverify）

在 **iPhone 17 Pro Max / iOS 27.0.1** 上验证 worse_query 沙盒逃逸的最小 App。

原项目：[forcequitOS/worse_query](https://github.com/forcequitOS/worse_query)（GPL-3.0）。
`Sources/worse_query.m` 保持原样，本仓库只加了诊断、可视化和构建脚本。

---

## 1. 这个 PoC 做了什么

不是内核漏洞，不是越狱，是 **containermanagerd 解析路径时跟随符号链接**：

1. App 必须拥有一个 **App Group**，因此有 `com.apple.security.application-groups` entitlement。
2. 把 App Group 容器里的 `Library/Caches` 删除，替换成指向任意目标路径的符号链接。
3. 调用私有库 `libsystem_containermanager.dylib` 的 `container_query_*`：
   - `class = 7`（App Group）
   - `part = 3`（Library/Caches）
   - 查询自己有权访问的 App Group。
4. containermanagerd 生成 sandbox extension token 时跟随了符号链接，token 的授权路径变成目标路径。
5. `sandbox_extension_consume(token)` 把目标路径加入本进程的沙盒白名单。

结果：可以读取/枚举原项目列出的容器路径：

```
/var/containers/Data/System                         (iOS 27)
/var/containers/Shared/SystemGroup/*                (iOS 27)
/var/mobile/Containers/Data/Application/*
/var/mobile/Containers/Data/InternalDaemon/*
/var/mobile/Containers/Data/PluginKitPlugin/*
/var/mobile/Containers/Shared/AppGroup/*
/var/mobile/Containers/Shared/AppGroup              (iOS 27)
```

iOS 27.0.1 上，四个容器父路径（Application / InternalDaemon / PluginKitPlugin /
SystemGroup）会拒绝签发 token（返回 `-6`）。验证器会再用 `fsgetpath` 按 inode
扫出这些父路径的直接子容器，然后逐个消费子容器 extension——这也是 WQFiles 在
27.0.1 上的做法。AppGroup 根目录和 System 数据父路径仍然可以直接拿 token。

iOS 26 和 27 的 query flags 不同：

| 系统 | flags |
|---|---|
| iOS 26.x | `0x0000000800000000` |
| iOS 27.x | `0x0000008000000000` |

---

## 2. iOS 27.0.1 / iPhone 17 Pro Max 适不适用

**结论：高度适用，但必须实机跑一次。**

- 原 README 标注支持 `iOS 26.0 - 26.7.2 / 27.2`，仓库创建于 2026-11-08。
- 前代 `bad_query` 标注支持到 `27.0b4`，说明 27.0 系列本来就是目标。
- 27.0.1 夹在 27.0b4 和 27.2 之间；Apple 不会在 27.0.1 修掉又在 27.2 复发。
- PoC 没有硬件偏移、内核地址或机型判断，A19 Pro 不构成额外变量。

剩下的小概率是 27.0.1 单独改了 containermanagerd 的 query 校验，只能实测排除。

---

## 3. 硬性前置条件

1. **能创建 App Group 的开发者账号**。Apple 官方能力矩阵（`developer.apple.com/help/account/reference/supported-capabilities-ios/`，2026-11-10 抓取）里 `App groups` 在 **ADP / ADEP / 免费 Apple Developer** 三列都支持。企业证书（ADEP）已确认可用。
2. **显式 App ID**（不能是通配符 `*`），并勾选 **App Groups**。
3. 在该 App ID 下注册 App Group，例如：
   - App ID：`com.yourcompany.wqverify`
   - App Group：`group.com.yourcompany.wqverify`
4. 启用 App Groups 后**重新生成** In-House / development profile；旧 profile 不会自动带上。
5. 确认 profile 的 Entitlements 里有 `com.apple.security.application-groups`。`ios.yml` 会打印并强校验这一项，没有直接失败。
6. 导出带私钥的 **Apple Distribution / iPhone Distribution `.p12`**。

> 通配符 App ID 的 profile 一定带不了 App Groups，这是最常见的翻车点。
> 企业证书只用于你所在组织的内部设备，别对外分发。

### 3.1 group 是签名注入的，不是写死的

App 启动时用 `SecTaskCopyValueForEntitlement` 读取自己签名里的
`com.apple.security.application-groups`，逐个调用
`containerURLForSecurityApplicationGroupIdentifier:`，用真正能解析出容器的那个。
这和 [WQFiles](https://github.com/kolbicz/WQFiles) 的做法一致。

所以：

- **AltStore / SideStore / Sideloadly + Apple ID**：签名工具会自动创建并注入 group，直接可用。
- **企业证书 + provisioning profile**：profile 必须包含一个 App Group；通配符 profile 不行。
- `Info.plist` 里的 `WQAppGroup` 和构建变量 `APP_GROUP` 只在读不到签名 entitlement 时当兜底提示，**不会覆盖签名里实际拿到的 group**。
- 如果 Stage 1 显示“签名里没有 application-groups entitlement”，那就是签名工具把 entitlement 丢了，换签名方式，跟漏洞无关。

---

## 4. 构建

### 4.1 GitHub Actions：unsigned（`build.yml`）

`workflow_dispatch` 手动触发。仓库变量：

| 变量 | 示例 |
|---|---|
| `BUNDLE_ID` | `com.yourcompany.wqverify` |
| `APP_GROUP` | `group.com.yourcompany.wqverify` |

产物 `app-ipa`。这个 IPA **没有签名**，必须用包含该 App Group 的企业 profile 重签后才能安装。

### 4.2 GitHub Actions：企业签名（`ios.yml`）

`workflow_dispatch` 手动触发。仓库变量同上，另加：

| 变量 | 默认 | 说明 |
|---|---|---|
| `SIGNING_METHOD` | `enterprise` | In-House 用 `enterprise`；development profile 用 `development` |
| `CERT_IDENTITY` | `Apple Distribution` | 老账号可能是 `iPhone Distribution`，按 `security find-identity` 输出填 |

Repository secrets：

| Secret | 内容 |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | `.p12` 的 Base64 |
| `P12_PASSWORD` | `.p12` 导出密码 |
| `KEYCHAIN_PASSWORD` | 随便一个临时密码，CI 内部用 |
| `PROVISIONING_PROFILE_BASE64` | `.mobileprovision` 的 Base64 |
| `TEAM_ID` | 10 位 Team ID |
| `PROFILE_NAME` | profile 的 **Name**（不是文件名） |

Windows 下生成 Base64（PowerShell，避免换行）：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\dist.p12")) | Set-Clipboard
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\wqverify.mobileprovision")) | Set-Clipboard
```

产物 `wqverify-signed`。导出后会反查 `codesign --entitlements`，确认 App Group 真的在包里；不在就红。
这里的 `APP_GROUP` 必须与 profile 里授权的 group 一致，因为 `ios.yml` 走的是 Xcode 的 entitlements 文件，不是外部签名工具。运行时仍以签名实际注入的 group 为准。

### 4.3 本地 Mac + Xcode

直接用 `wqverify.xcodeproj`：

1. 打开工程，选 target `wqverify`。
2. Signing & Capabilities 里设置 Team，确认 Bundle Identifier 和 App Groups。
3. 如果没有 App Groups 这一项，点 `+` 添加，group 用你自己的。
4. 选 iPhone 17 Pro Max，Run。

默认启动直接进诊断面板。`dvt launch "<BUNDLE_ID> --hello"` 仍走原来的 argv/home 分支。

---

## 5. 安装与运行

- **Windows**：3uTools / iMazing 直接安装已签名的 IPA，**不要重新签名**（重签会把 App Group 丢掉）。
- **macOS**：Apple Configurator 2 → Add → Apps → 选 IPA；或 Xcode → Window → Devices and Simulators → `+`。
- 首次启动前：`设置 → 通用 → VPN 与设备管理 → 信任企业开发者`。
- 打开 App 自动跑；右上角刷新按钮可重跑。

---

## 6. 面板怎么看

顶部大卡片直接给结论：

| 颜色 | 结论 | 含义 |
|---|---|---|
| 绿 | 沙盒逃逸生效 | 至少一次真实文件内容读取（`read=...B` 或 metadata plist） |
| 橙 | 逃逸部分生效 | 只拿到 extension / id xattr / 目录列表，没有真实文件读取 |
| 红 | 沙盒逃逸未生效 | 全部没拿到 extension，可能已修复或 flags 不对 |
| 灰 | 无法验证 | App Group entitlement 没生效，先修签名/profile |

下面依次是：

- 四个数字：`严格 PASS`（有真实文件读取的目标数）、`文件读取`（`read=...B` 或 metadata plist）、`id 访问`（只读到 container id xattr）、`扫描容器`（27.0.1 上父路径 -6 时找到的子容器数）。
- 阶段检查：App Group → 私有符号 → 路径逃逸 → 跨容器读取，每行带绿/红/橙图标。
- 每个目标路径一张卡：右侧 `PASS / WARN / FAIL / SKIP`，下面写 `handle` 和「消费前 EPERM / 消费后可读 N 项」。
- 子容器读取成功会绿色显示 `read=...B`。
- 底部折叠 `原始日志`；工具栏可分享完整报告。
- 报告同时写到 `Documents/wq_report.txt`，可用 `pymobiledevice3 apps pull` 取回。

### 6.1 这不是漏洞的上限

当前面板的覆盖范围是**诊断器的限制**，不是 worse_query 的上限：

- 每个父路径最多取 8 个子容器，fsgetpath 扫描预算 30 秒。
- SystemGroup 不依赖扫描，直接试一组已知容器名（`systemgroup.com.apple.*`）。
- 每个容器会试 `Library/Preferences`、`Documents`、`Library/Caches`、`tmp`，读到第一个文件就停。
- `container id` xattr 只显示 `id ok`，**不算严格 PASS**；metadata plist 是真实文件读取，算。

继续扩的话：全量多线程 inode 扫描、按 LaunchServices 数据库取全部 App、读更多文件类型。这些是工程量，不是漏洞边界。

> 现已实现：全量多线程扫描、目录浏览、文件读取（≤1MB）、文本/Hex/Plist 查看、文本保存、单文件备份/恢复、写能力探针。见第 10 节。
> 未实现：LaunchServices App 名称/图标、结构化 plist 编辑、Hex 编辑、整 App 备份/恢复。

### 6.2 `父级 token 2/6` 和 `严格 PASS` 不是一回事

- **父级 token**：直接对父目录调用 `worse_query()` 成功的数量。iOS 27.0.1 只给
  `AppGroup` 根目录和 `System 数据` 签发，所以是 2/6。
- **严格 PASS**：只有读到真实文件内容（Preferences / Documents / Caches / tmp
  或 metadata plist）的目标才算。只拿到 extension、只列目录、只读 id xattr 都算 WARN。
- 那四个父路径返回 `-6` 是 iOS 27.0.1 的系统行为，不是失败；它们的子容器仍然
  可以逐个拿 extension，并读到真实文件（iBooks / Notes / Maps 已实测）。
- `id ok` 表示只读到 container id xattr，`read=...B` 才是文件内容。严格模式下
  前者只给 WARN，后者才给 PASS。

---

## 7. 返回码与判定

```
至少一次真实文件读取（read=...B 或 metadata）  -> PASS
只拿到 extension / id xattr / 目录列表            -> PARTIAL
什么都没拿到                                      -> FAIL
```

| 返回值 | 含义 |
|---|---|
| `-1` | 拿不到 App Group 容器（entitlement/profile 问题） |
| `-2` | `dlopen`/`dlsym` 失败（系统改了符号） |
| `-3` | `container_query_create` 失败 |
| `-4` | 符号链接创建失败（App Group 里 `Library` 不存在） |
| `-5` | containermanagerd 拒绝 query（最可能是已修复或 flags 不对） |
| `-6` | 内核拒绝签发 extension token |
| `>0` | 成功拿到 extension handle |

---

## 8. 风险与边界

- 每次调用会删除并重建 **你自己 App Group** 的 `Library/Caches`，别在里面放数据。
- 成功后可以枚举并读取其他 App 容器中的内容，这是真实的数据访问能力。**只在你自己的设备上跑。**
- 这不是越狱，不能提权到 root；原 README 也明确说了不构成 jailbreak。
- 企业签名 App 依赖证书有效期；证书被吊销后 App 直接打不开。

---

## 9. 容器浏览 / 全量枚举 / 写测试

诊断面板底部的 **浏览容器 / 全量扫描 / 写测试** 进入新页面。

### 9.1 全量多线程扫描

- 用 `fsgetpath` 按 inode 扫六个父目录的直接子容器：
  AppGroup、Data/Application、Data/InternalDaemon、Data/PluginKitPlugin、SystemGroup、containers/Data/System。
- inode 上限取临时文件 inode + 1,000,000；inode 范围按 40 万一块切分，`dispatch_apply` 多线程扫，结果加锁合并。
- 每个父目录最多保留 3000 个，总预算 90 秒。超时/超限会少结果，重跑即可。
- 找到的容器按路径排序；点进去直接对该容器消费 extension 并浏览。

### 9.2 目录浏览与文件查看

- 进入容器后列出根目录；点目录继续下钻，点文件打开查看器。
- 列目录和读文件都会单独对该路径 `worse_query()` 拿 token，不依赖父路径 token。
- 文件读取上限 1MB；超过部分截断（Hex 只显示前 4KB）。
- 查看器三种模式：
  - **文本**：UTF-8；可切换到编辑，保存时先自动备份原始内容到 App `Documents/Backups/`，再 `O_TRUNC` 写回（保留 inode）。
  - **Hex**：只读，前 4KB。
  - **Plist**：解析后递归展开；只读。XML plist 想改就切文本模式。
- 容器顶部显示 `com.apple.containermanager.identifier`（bundle id）。App 名称/图标需要解析 lsd 数据库，未做。

### 9.3 写能力探针（风险中）

- 只在所选容器的 **`tmp`** 下写一个唯一文件 `wq_probe-<UUID>.txt`，读回校验后立即 `unlink`。
- 结果三种：
  - `读写 token 确认`：写入 + 读回一致，token 是 read-write。
  - `写入失败 errno ...`：token 只读，或 `tmp` 不存在。
  - `拿不到 tmp 的 extension`：路径不可达。
- **只在你拥有的、可牺牲的设备上跑。** 不碰 `tmp` 以外的任何文件，不创建目录。

### 9.4 没做的部分

- LaunchServices 元数据（App 名称、图标、大小）。
- 结构化 plist 编辑器（增删改排序、二进制/XML 互转）。
- Hex 编辑。
- 整 App 容器备份/恢复；目前只有单文件备份和本次会话内恢复。

---

## 10. 文件结构

```
wqverify/
├── .github/workflows/
│   ├── build.yml                 # unsigned IPA
│   └── ios.yml                   # 企业签名 IPA
├── Signing/ExportOptions.plist   # 导出模板
├── wqverify.xcodeproj            # 唯一的 Xcode 工程
├── wqverify/
│   ├── wqverifyApp.swift
│   └── ContentView.swift         # 默认进 Dashboard，--hello 走旧分支
└── Sources/
    ├── DashboardView.swift       # 可视化面板
    ├── BrowserView.swift         # 全量扫描 / 目录浏览 / 查看器 / 写探针
    ├── Diagnostics.swift         # 分阶段验证逻辑
    ├── worse_query.m/h           # 原 PoC，未改
    ├── wq_diag.m/h               # 探测辅助（含多线程扫描、写/删）
    ├── Info.plist
    ├── wqverify.entitlements
    └── wqverify-Bridging-Header.h
```