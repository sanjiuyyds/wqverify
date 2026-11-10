# worse_query 验证工程（WQDiag）

给 **iPhone 17 Pro Max / iOS 27.0.1** 用的最小化实机验证程序。

原项目：[forcequitOS/worse_query](https://github.com/forcequitOS/worse_query)（GPL-3.0）。
本目录只增加了一个自动诊断壳，PoC 本体 `Sources/worse_query.m` 保持原样。

---

## 1. 这个 PoC 到底做了什么

它不是内核漏洞，不是越狱，是 **containermanagerd 的路径解析问题 + sandbox extension 滥用**：

1. 应用必须拥有一个 **App Group**，因此有 `com.apple.security.application-groups`  entitlement。
2. 代码把自己的 App Group 容器里的 `Library/Caches` 删除，替换成一个 **符号链接**，指向任意目标路径（例如别的 App 容器）。
3. 调用私有库 `libsystem_containermanager.dylib` 的 `container_query_*`：
   - `class = 7`（App Group）
   - `part = 3`（Library/Caches）
   - 查询自己有权访问的 App Group。
4. containermanagerd 按 `Library/Caches` 生成 sandbox extension token 时，**跟随了符号链接**，token 的授权路径变成了符号链接的目标。
5. 应用 `sandbox_extension_consume(token)`，于是内核把目标路径加入本进程的沙盒白名单。

结果：应用可以读取原项目列出的这些目录：

```
/var/containers/Data/System                         (iOS 27)
/var/containers/Shared/SystemGroup/*                (iOS 27)
/var/mobile/Containers/Data/Application/*
/var/mobile/Containers/Data/InternalDaemon/*
/var/mobile/Containers/Data/PluginKitPlugin/*
/var/mobile/Containers/Shared/AppGroup/*
/var/mobile/Containers/Shared/AppGroup              (iOS 27)
```

`iOS 26.x` 和 `iOS 27.x` 的 query flags 不同，所以原代码按 `majorVersion == 26` 分支：

| 系统 | flags |
|---|---|
| iOS 26.x | `0x0000000800000000` |
| iOS 27.x | `0x0000008000000000` |

---

## 2. iOS 27.0.1 / iPhone 17 Pro Max 适不适用

**结论：高度适用，但必须实机跑一次才算数。**

依据：

- 原 README 标注支持 `iOS 26.0 - 26.7.2 / 27.2`；仓库创建于 2026-11-08，作者已经在 27.2 上验证过。
- 前代 `bad_query` 标注支持到 `27.0b4`，说明 27.0 系列本身就是目标。
- `27.0.1` 位于 `27.0b4` 和 `27.2` 之间。Apple 不会在 27.0.1 修掉又在 27.2 复发，所以该 bug 大概率仍然存在。
- 这个 PoC 是纯 API 滥用，**没有任何硬件偏移、内核地址或机型判断**，A19 Pro / iPhone 17 Pro Max 不构成额外变量。

剩下的小概率：27.0.1 单独改了 containermanagerd 的 query 校验，而 27.2 又换回了旧行为。只能实测。

三种结果：

| 结果 | 含义 |
|---|---|
| `RESULT: PASS` + child read | 漏洞真实生效，可以读别的 App 容器 |
| `RESULT: PARTIAL` | token 发了，但目录不可读，可能是 extension 语义变了 |
| `RESULT: FAIL` | 27.0.1 已修，或 flags/class 变了，或 App Group 配错 |

---

## 3. 硬性前置条件（企业证书路线）

企业证书可以做，但必须满足：

1. **能创建 App Group 的开发者账号**。已核对 Apple 官方能力矩阵（`developer.apple.com/help/account/reference/supported-capabilities-ios/`，2026-11-10）：`App groups` 在 **ADP / ADEP / 免费 Apple Developer** 三列都是支持。企业证书（ADEP）确认可用。免费账号的主要差别是 profile 7 天过期、设备和 App ID 数量限制，不是 entitlement 本身。
2. **显式 App ID**（不能是通配符 `*`），并勾选 **App Groups**。
3. 在该 App ID 下注册 App Group，例如：
   - App ID：`com.yourcompany.wqdiag`
   - App Group：`group.com.yourcompany.wqdiag`
4. 用该 App ID 生成 **In-House 分发 profile**（Profiles → Distribution → In House）。
5. 导出带私钥的 **Apple Distribution / iPhone Distribution `.p12`**。
6. 确认 profile 的 Entitlements 里有 `com.apple.security.application-groups`。工作流会自动打印这一项，没有就直接失败。

> 通配符 App ID 的 profile 一定带不了 App Groups，这是最常见的翻车点。
> 企业证书只用于你所在组织的内部设备，别对外分发。

**In-House profile 不需要 UDID**，任何设备都能装，装完要在
`设置 → 通用 → VPN 与设备管理` 里信任企业证书。
如果你用的是企业团队的 **development** profile，则需要把设备 UDID 加进 profile，并把 `SIGNING_METHOD` 设为 `development`。

---

## 4. 构建

### 4.1 GitHub Actions（推荐，免费）

仓库可以是 public（macOS runner 对 public 仓库免费）。企业证书私钥放 Secrets 里是加密的，fork PR 拿不到；介意的话用 private 仓库，2000 分钟/月够跑几次。

**Repository variables：**

| 变量 | 示例 | 说明 |
|---|---|---|
| `BUNDLE_ID` | `com.yourcompany.wqdiag` | 必须与显式 App ID 一致 |
| `APP_GROUP` | `group.com.yourcompany.wqdiag` | 必须已在 portal 注册并挂到 App ID |
| `SIGNING_METHOD` | `enterprise` | In-House 用 `enterprise`；development profile 用 `development` |
| `CERT_IDENTITY` | `Apple Distribution` | 老账号可能是 `iPhone Distribution`，按 `security find-identity` 输出填 |

**Repository secrets：**

| Secret | 内容 |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | `.p12` 的 Base64 |
| `P12_PASSWORD` | `.p12` 导出密码 |
| `KEYCHAIN_PASSWORD` | 随便一个临时密码，CI 内部用 |
| `PROVISIONING_PROFILE_BASE64` | `.mobileprovision` 的 Base64 |
| `TEAM_ID` | 10 位 Team ID |
| `PROFILE_NAME` | profile 的 **Name**（不是文件名），可用 `PlistBuddy -c 'Print :Name'` 查看 |

Windows 下生成 Base64（PowerShell，避免换行）：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\dist.p12")) | Set-Clipboard
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\wqdiag.mobileprovision")) | Set-Clipboard
```

推上去后 Actions 会产出两个 artifact：

- `WQDiag-unsigned`：只证明能编译，不能装。
- `WQDiag-signed`：企业签名 IPA，可直接安装。工作流在导出后会反查 `codesign --entitlements`，确认 App Group 真的在包里；不在就红。

### 4.2 本地 Mac + Xcode

```bash
brew install xcodegen
# 编辑 Config.xcconfig：BUNDLE_ID / APP_GROUP / TEAM_ID
xcodegen generate
open WQDiag.xcodeproj
```

选中你的 iPhone 17 Pro Max，Signing 里确认 Team 和 App Groups，直接 Run。
本地跑比 Actions 少一层证书搬运，调试最快。

---

## 5. 安装与运行

- **Windows**：3uTools / iMazing 直接安装 `WQDiag-signed.ipa`，**不要重新签名**（重签会把 App Group 丢掉）。
- **macOS**：Apple Configurator 2 → Add → Apps → 选 IPA；或 Xcode → Window → Devices and Simulators → `+`。
- 首次启动前：`设置 → 通用 → VPN 与设备管理 → 信任企业开发者`。
- 打开 App 会自动跑，也可以点 `Run verification`；跑完点 `Share report` 导出文本。

---

## 6. 验证程序做了什么

只读，不写目标路径：

1. **Stage 1**：`containerURL(forSecurityApplicationGroupIdentifier:)` 是否为 nil。
   nil 就直接结束，说明签名/profile 没带 App Group，后面不用看。
2. **Stage 2**：`dlopen` + `dlsym` 检查 8 个 `container_query_*` 和 2 个 `sandbox_extension_*`。
3. **Stage 3**：对 6 个路径逐个测试：
   - 消费前先 `opendir`，记录是否被沙盒拒绝（差分证据）。
   - `worse_query()` 主 flags；`-255` 时用 `create_dir=true` 绕过 lstat 门；仍失败再试 iOS 26 的 alt flags。
   - 成功后再次 `opendir`，对比前后。
4. **Stage 4**：对 AppGroup / Application / InternalDaemon / PluginKitPlugin / SystemGroup 的前两个子容器：
   - 再消费一次子容器 extension；
   - 读 `com.apple.containermanager.identifier`；
   - 读 `.com.apple.mobile_container_manager.metadata.plist`；
   - 列 `Library/Preferences` 并真实 `read()` 一个 plist。

判定：

```
handles > 0 && (listings > 0 || child reads > 0)  -> PASS
handles > 0 但读不到任何东西                       -> PARTIAL
handles == 0                                      -> FAIL
```

返回码对照：

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

## 7. 风险与边界

- 每次调用会删除并重建 **你自己 App Group** 的 `Library/Caches`，别在里面放数据。
- 成功后可以枚举并读取其他 App 容器中的内容，这是真实的数据访问能力。**只在你自己的设备上跑。**
- 这玩意不是越狱，也不能提权到 root；原 README 也明确说了不构成 jailbreak。
- 企业签名 App 依赖证书有效期；证书被吊销后 App 直接打不开。
- 如果 Stage 1 就挂，先别怀疑漏洞，先查 profile 的 App Groups。

---

## 8. 文件结构

```
wq-verify/
├── .github/workflows/ios.yml     # 免费编译 + 企业签名
├── Config.xcconfig               # 本地构建参数
├── project.yml                   # XcodeGen 工程描述
├── Signing/ExportOptions.plist   # 导出模板
└── Sources/
    ├── App.swift                 # SwiftUI 壳
    ├── Diagnostics.swift         # 分阶段验证逻辑
    ├── worse_query.m/h           # 原 PoC，未改
    ├── wq_diag.m/h               # 只读探测辅助
    ├── Info.plist
    ├── WQDiag.entitlements
    └── WQDiag-Bridging-Header.h
```