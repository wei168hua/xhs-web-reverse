# 小红书 Web 签名参数逆向全流程技术文档

> 任务 ID：`xhs-web-xs-sign-2026`
> 目标：还原 `x-s / x-t / x-s-common / x-rap-param` 及厘清 `X-Mns / Sc-T` 的生成算法
> 用途：个人技术研究与理解，全程脱敏，不用于未授权自动化

---

## 0. 技术背景与元信息（写作时快照）

| 项 | 值 | 说明 |
|---|---|---|
| 研究日期 | 2026-07-25 ~ 2026-07-26 | 分两阶段，见 §1 |
| 客户端 | `xhs-pc-web`，`webBuild=6.34.4` | bundle 内常量 `x4="6.34.4"` |
| 签名内部版本 | `x0/x1 = "4.3.7"`（i8 常量） | 与 x-s / x-s-common 内层版本 |
| API 域 | `edith.xiaohongshu.com` / `so.xiaohongshu.com` | 业务接口 |
| 风控域 | `as.xiaohongshu.com`（`/api/sec/v1/*`） | 动态下发 VM 脚本 |
| 主签名 bundle | `fe-static.xhscdn.com/formula-static/xhs-pc-web/.../vendor-dynamic.ae665ebb.js` | 明文可读，含调用链与确定性编码器 |
| 风控 VM 脚本 | `fe-static.xhscdn.com/as/v1/3e44/public/*.js`、`as/v2/ds/*.js`（如 `6545c70e...js`） | jsvmp + 字符串数组混淆 |
| 本地 bundle 副本 | `/tmp/xhs_js/*.js` | 与浏览器同源公开静态 JS |
| 参照实现 | 开源 `xhshow`（github `Cloxl/xhshow`），版本常量 6.3.0/4.3.5 | 作算法字典，非直接采信 |
| 逆向工具 | JSReverser-MCP（attach 模式，`--browserUrl http://127.0.0.1:9222`） | 见 §1 连接方式 |
| 环境无 WASM | ✅ | 核心保护为 JS 层 jsvmp 混淆 VM |

**可信度标注**：✅ 实测/逐字节验证 ｜ 🟡 强推断 ｜ 🔴 假设

**成果文件**（同目录 `rebuild/`）：
- `env.js` — 确定性原语（CRC32 / UTF-8 / 自定义 base64）
- `mnsv2.js` — x-s 核心 `window.mnsv2`（`mns0301_`）离线编码 + 解码
- `xrap.js` — x-rap-param 生成器 + 解码器（xxHash32 + SM4 变体 + gzip + 信封）
- `entry.js` — 组装完整 x-s / x-s-common / x-t
- `verify.js` / `verify_mnsv2.js` / `verify_xrap.js` — 自校验（全 PASS）

---

## 1. 环境搭建与连接（前置）

1. 起 Chrome：`--remote-debugging-port=9222 --user-data-dir=<profile>`，登录小红书。
2. 逆向工具以 **attach 模式**接 9222（关键：不是自启动 pipe，否则 Hook / evaluate 不可用）。
3. 判据：`list_pages` 正常返回、能在页面上下文执行 JS、`probe_runtime_capabilities` 显示 `window/document/localStorage` 等齐全。

**两阶段说明**（决定能做什么）：
- **阶段 A（2026-07-25，pipe 只读）**：MCP 以 `--remote-debugging-pipe` 启动，交互工具不可用 → 只能静态 bundle 分析，还原了确定性外壳（x-t / x-s-common / 编码器）。
- **阶段 B（2026-07-26，attach 可交互）**：修复为 TCP 9222 attach，`replay_page_flow` 的 `evaluate` 可执行页面 JS → 才完成 mnsv2 差分分析、逐字节对齐、x-rap-param 采样。

**页面内取数技巧（贯穿全程）**：evaluate 的返回值不可见，用 `fetch('/marker/'+encodeURIComponent(data))` 把结果编码进 URL，再从 `network_request` / `export_har_snapshot` 读回（页面对未知路径 302→404，不影响）。差分计算全部在页面内做，只回传紧凑结论，避免上下文膨胀。

---

## 2. 总体调用链

全部签名在 axios 的 dispatch 拦截器（webpack 模块 `crawler-spam` / `AntiSpam`）中，对命中 `shouldSign(url)` 的请求发出前统一注入：

```
axios dispatch interceptor
  └─ signAdaptor(e, a):
       shouldSign(url) ? xhsSign(e,a)      → 设置 X-s / X-t
       xsCommon(e,a)                        → 设置 X-S-Common
       (!disableMns) mns 分支               → 设置 X-Mns（默认关闭）
       shouldToken(a) ? xhsToken(e,a)       → 设置 Sc-T（条件）
       logSec({name:"anti_spam_sign_cost", type: window._webmsxyw ? "sign_new":"sign_old"})
```

`shouldSign(url)`：URL 命中本站 host / `sit.xiaohongshu.com` → 签；否则查 `o8` 忽略表。
`getRealUrl`：去掉 origin 的 path+query，`'` 替换为 `%27`，经 `buildURL` 序列化 params。

存在新旧两套签名并存：新链路 `seccore_signv2`（`XYS_` 前缀，依赖 `window.mnsv2`），旧链路 `window.sign`/`window._webmsxyw`（`sign_old`）。运行时以 `window._webmsxyw` 是否存在区分。

---

## 3. 逆向方法论（六阶段，可复用）

1. **黑盒定界**：观察哪些 XHR 带签名头、谁签、签什么、何时签。产出入口函数名与核心黑盒。
2. **拆外壳**：能静态提取的确定性逻辑逐字吃干净（编码器、外层 JSON 结构、时间戳）。
3. **Hook 采样**：透明包裹黑盒函数，记录 `(args, return)`，钉死 I/O 合同与确定性性质。
4. **原语指纹识别**：不读懂 VM，先"认常量"——AES S-box / RCON、`0xEDB88320`(CRC32)、murmur3 常量、xxHash32 primes、乱序 64 字符表。
5. **抠密钥 + 还原明文结构**：差分分析（冻结/差分输入、逐字节归类）定位可控字段；交叉参照开源实现拿常量；**逐字节解码真实输出对齐**。
6. **复刻 + 验证**：本地重建 + 真实浏览器输出逐字节对齐（比服务器 `code:0` 更强的同构证明）。

**关键教训**：原语判断要靠**运行时差分实测（雪崩测试）**确认，不能只靠"能解密"就断言 AES（见 §5 的纠错）。

---

## 4. X-t（毫秒时间戳）✅ 完全还原

```js
a.headers["X-t"] = +new Date + "";   // String(Date.now())
```
- 13 位毫秒时间戳字符串。零依赖，纯离线可产出。
- 与 x-s 内部的时间字段独立（x-s 明文里另有自己的 timestamp / pageLoadTs）。

**流程**：阶段 2 静态提取即得。**失效风险**：几乎不会变；除非改成服务器时钟对齐或加偏移。

---

## 5. X-s（核心，`XYS_` + 自定义 base64(JSON)）✅ 逐字节还原

### 5.1 外壳（bundle 明文，确定性）
```js
function seccore_signv2(realUrl, data){
  let c = realUrl;
  if (typeof data === "object") c += JSON.stringify(data);
  else if (typeof data === "string") c += data;
  const u = MD5(c);          // W.Pu
  const p = MD5(realUrl);    // W.Pu
  const v = window.mnsv2(c, u, p);   // ★ 核心黑盒
  const S = { x0:"4.3.7", x1:"xhs-pc-web", x2: window[mj]||"PC", x3:v, x4: data?typeof data:"" };
  return "XYS_" + b64Encode(encodeUtf8(JSON.stringify(S)));  // 自定义字母表 base64
}
```
- 自定义 base64 字母表（x-s / x-s-common 用）：
  `ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5`
- 除 `x3` 外全部确定性可复现；问题收敛到"还原 `mnsv2` 一个函数"。

### 5.2 核心 `window.mnsv2`（`mns0301_`）—— 完整还原

**方法**：阶段 B 在 attach 浏览器上对 `window.mnsv2` 做差分分析（同输入多次采样 + 变输入采样 + 逐字节归类），交叉参照 xhshow，最终用真实浏览器输出**逐字节双向对齐**（编码 + 解码）。

**关键纠错**（相对早期 AES 假设）：核心**不是 AES**。`mns0301_` 载荷解码后是 **144 字节结构化明文**，与一个**硬编码 144 字节密钥 `HEX_KEY`** 逐字节 **XOR**，再用 **X3 自定义 base64** 编码。证据：同输入多次输出**字节局部变化、无雪崩效应**（分组密码不可能如此）；`window.mnsv2.toString()` 是 jsvmp 薄封装，函数对象上带**内部单调计数器 `ΙII++`**（这解释了冻结 `Date.now`/`Math.random`/`getRandomValues` 仍不确定——熵来自内部计数器 + 随机 seed）。

**144 字节明文布局**（小端整数，全部在真实浏览器样本上逐字节验证 ✅）：

| 偏移 | 字段 | 说明 |
|---|---|---|
| `[0:4]` | VERSION_BYTES | 常量 `[121,104,96,41]` |
| `[4:8]` | seed | 随机 u32；`seedByte = seed & 0xFF`（多处 XOR 掩码） |
| `[8:16]` | timestamp_ms | `Date.now()` LE 8B |
| `[16:24]` | pageLoadTs | = `loadts` cookie（页面加载时间戳）LE 8B |
| `[24:28]` | sequence | 单调序列 |
| `[28:32]` | window_props_length | 环境相关计数 |
| `[32:36]` | uri_length | `len(utf8(content))` |
| `[36:44]` | `MD5(content)[0:8] ^ seedByte` | **唯一输入派生字段**（仅 MD5 前 8 字节入编码） |
| `[44]` | a1_len | = 52 |
| `[45:97]` | a1 | cookie a1（截断/补齐 52B） |
| `[97]` | app_len | = 10 |
| `[98:108]` | app_id | `"xhs-pc-web"` |
| `[108:124]` | part11 | `[1, seedByte^ENV_TABLE[0], ENV_TABLE[i]^ENV_CHECKS[i] (i=1..14)]` |
| `[124:128]` | A3_PREFIX | 常量 `[2,97,51,16]` |
| `[128:144]` | `custom_hash_v2(ts_bytes ++ md5_path_bytes) ^ seedByte` | 16B 自定义哈希（murmur3 风格 IV） |

变换：`payload XOR HEX_KEY(144B)` → X3-base64 → `"mns0301_" + body`；再包进 `XYS_`。

**核心常量**：
- `HEX_KEY`(144B)：`71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277516db7116035439730fa61e9822a0eca7bff72d8`
- X3 字母表：`MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G`
- `custom_hash_v2` IV（murmur3）：`[1831565813, 461845907, 2246822507, 3266489909]`
- `ENV_TABLE`：`[115,248,83,102,103,201,181,131,99,94,4,68,250,132,21]`

**验证**（`node rebuild/verify_mnsv2.js` 全 PASS）：两个真实浏览器输出，离线 `decodeMnsv2()` 还原 version/uri_length/md5Head(=注入的 u 前 8B)/a1(=真实 cookie)/app_id/pageLoadTs(=真实 loadts)/A3_PREFIX 全命中；`custom_hash_v2` 逐字节重算命中 16B 尾部；用 live 解码的 seed/timestamp/sequence 前向重建 `mnsv2()` 输出与浏览器 **byte-identical**。唯一差异 `part11` env-check 向量（idx5=1,idx7=2 vs xhshow 默认全 0），属环境指纹正常差异，用实测向量后 100% 一致。

**离线依赖**：需喂入运行时值 `a1`(设备 cookie) 与 `loadts`(页面加载时间戳)——它们是输入，不是要破解的密钥。

---

## 6. X-S-Common ✅ 完全还原

```js
const en = { s0:getPlatformCode(platform), s1:"", x0:localStorage[b1b1]||fI("1"),
  x1:"4.3.7", x2:platform||"PC", x3:"xhs-pc-web", x4:"6.34.4", x5:cookie a1,
  x6:"", x7:"", x8:localStorage[b1]/*指纹*/, x9:crc32(R+I+G), x10:V, x11:"normal",
  x12:localStorage[dsllt]+";"+window._dsl };
a.headers["X-S-Common"] = b64Encode(encodeUtf8(JSON.stringify(en)));
```
- 编码器三件套（bundle 内逐字提取）：**CRC32**（反射多项式 `0xEDB88320`，KAT `crc32("123456789")==0xCBF43926`）、UTF-8 字节化、自定义字母表 base64（同 x-s 字母表）。
- 全部确定性；`X-S-Common` 可反解回原始 `{s0..x12}` JSON（`verify.js` 已证）。
- `x8/x9` 在命中 `xhsFingerprintV3` + UA 规则时会用 `getCurMiniUa` 回调覆写。

**离线依赖**：`localStorage[b1]`(设备指纹)、cookie `a1`、`window._dsl` 等运行时字段。

---

## 7. x-rap-param（`ByQB...`）✅ 信封结构还原 + xxh32 逐字节验证

**性质**：独立于 x-s 的反爬参数，出现在 feed / 搜索 / 互动类 POST。多层管线：

```
body TLV → gzip(OS 字节 patch=0x03) → cyclic-XOR(16B 会话密钥)
        → SM4 变体分组密码(自定义 S 盒 + 预扩展 10 轮 round keys, ECB)
        → 信封(header + content) → base64
```

- 哈希 = **xxHash32**（非 CRC/MD5；KAT `xxh32("")=0x02cc5d05`、`xxh32("abc")=0x32d153ff`）。
- 分组密码 = **SM4 变体**（自定义 256B S 盒、预扩展 10 轮轮密钥、末轮 `SBOX + last_round_key`），**非标准 AES**。

**信封字节布局**（`base64(header(36B)+content)`，真实浏览器样本逐字节验证）：

| 偏移 | 字段 | 样本值 |
|---|---|---|
| `[0:3]` | magic | `07 24 01` |
| `[3]` | salt_len | `5` |
| `[4:8]` | 常量 1 (u32be) | `1` |
| `[8:12]` | 常量 2 (u32be) | `20` |
| `[12:16]` | cipher_body 长度 | `212` |
| `[16:20]` | **content_hash = xxh32(content)** | `ff30ab81` ✅ 独立实现逐字节命中 |
| `[20:24]` | protocol_version | `10301` |
| `[24:28]` | enc_time | `16` |
| `[28:36]` | 8×`00` | — |
| content | `salt + encryptBlock16(sessionKey)(16) + u32be(16) + cipherBlocks + u32be(origGzipLen)` | — |

**body TLV**：`>H` tag + 值；前缀 `0x03E8` ts(u64) / `0x03E9` nonce(u32) / `0x03EA` sessionKey(blob) / `0x03EB` `xxh32(api+body)`(u32) + 一组布尔能力位(1051–1073) + 计时字段(1075–1097) + `interaction_trace` / `environment_snapshot` 两个 blob；**前 16 字节明文，其余整体 XOR 单字节 mask**。

**最强证据**：header 里的 `content_hash` 用独立 xxHash32 对 `content` 重算，逐字节命中 `ff30ab81`——错误布局不可能命中。

**验证**（`node rebuild/verify_xrap.js` 全 PASS）：真实样本信封字段 + `content_hash==xxh32(content)` + 生成器 round-trip 自洽。**未断言整串逐字节等于浏览器**：内层 gzip 体积 + trace/env 快照随运行时环境变化（同 mnsv2 env-check 类），整串对齐需 pin VM 内部生成的 `sessionKey/salt/mask/nonce/trace/env`。与 xhshow 唯一差异：`protocol_version=10301`（线上）vs `10300`。

---

## 8. X-Mns / Sc-T ⚪ 可选风控 token（定性完成，默认不需要）

**结论**：均为**可选、条件性**风控 token，**默认不参与签名、服务器不要求**。实测多个 `code:0` 请求（search/onebox、search/notes、user/me）只带 `x-s/x-t/x-s-common(+x-rap-param)`，无 X-Mns、无 Sc-T；`window.mns`、`window.__xhs_sc__` 当前均 `undefined`。

**X-Mns**（bundle 逐字提取）：
```js
if (!0 !== e.disableMns) try {            // AntiSpam 默认 disableMns:true → 跳过
  if (window.mns) a.headers["X-Mns"] = window.mns.getMnsToken(realUrl, data, MD5(realUrl+JSON(data)));
  else            a.headers["X-Mns"] = "unload";   // SDK 未加载 → 字面量
} catch(e) { a.headers["X-Mns"] = "error"; }
```
调用约定与 `mnsv2` 同族（3 参、第 3 参 MD5）。

**Sc-T**：
```js
function xhsToken(e,a){
  if (!(...&& shouldSign(url))) return a;   // 与 x-s 同一 shouldSign 门控
  try { a.headers["Sc-T"] = window.__xhs_sc__.getXHSToken() || ""; } catch(e){}  // 无参；缺失静默不设
}
```
二者由风控 VM 运行时注入（字符串数组混淆，`as/*.js` 明文不可见）。**离线做法**：X-Mns 用 `"unload"` 或省略、Sc-T 省略即可，与实测浏览器行为一致。

---

## 9. 未来失效时的排查指南（按可能性排序）

签名体系失效通常表现为：服务器返回非 `code:0`（如 `-1`/`406`/`461` 风控页、验证码）。按"最可能→最少见"排查：

### 9.1 【最高频】自定义 base64 字母表 / 硬编码常量被轮换 🟡
- **症状**：x-s / x-s-common 结构正确但服务器拒；`mns0301_` 前缀变化。
- **原因**：小红书定期轮换 X3 / x-s 字母表、`HEX_KEY`、`ENV_TABLE`、`A3_PREFIX`、`VERSION_BYTES`。
- **再研究**：重新从当前 `vendor-dynamic.*.js`（hash 会变）提取编码器字母表；对 `window.mnsv2` 重跑差分分析取新 `HEX_KEY`/版本字节（方法见 §5.2）。**这是最常见的失效点，且是最省力的修复**——只需重抠常量。

### 9.2 【高频】bundle 文件名 hash 变化 → 静态提取脚本失链 ✅必然发生
- **症状**：`/tmp/xhs_js/vendor-dynamic.ae665ebb.js` 404。
- **原因**：前端每次发版文件 hash 变（`ae665ebb` 只是这一版）。
- **再研究**：从 `/explore` 页面 HTML / `webpackChunkxhs_pc_web` 找当前主 bundle URL 重新下载。调用链函数名（`seccore_signv2`/`xsCommon`/`xhsToken`）相对稳定，可 grep 定位。

### 9.3 【中频】客户端版本号提升 → 明文常量漂移 🟡
- **症状**：签名结构对但被拒；或 `x4="6.34.4"`、`protocol_version=10301` 等版本字段过期。
- **原因**：`webBuild` / 内部版本 `4.3.7` / SDK 版本号随发版提升（x-rap-param 已见 10300→10301）。
- **再研究**：从新 bundle 更新 `x4`(webBuild)、`x0/x1`(内部版本)、`XRAP_SDK_VERSION`；这些是明文常量，易更新。

### 9.4 【中频】mnsv2 明文布局 / custom_hash_v2 变更 🔴
- **症状**：`decodeMnsv2()` 还原出的字段错位（version 不再是 `[121,104,96,41]`、a1 位置变）。
- **原因**：风控升级改字段顺序 / 新增字段 / 换哈希。
- **再研究**：重跑 §5.2 差分分析（冻结 entropy → 逐字节归类 → 变输入定位派生字段 → 逐字节解码真实输出对齐）。`window.mnsv2.toString()` 若结构大变说明 VM 换代。

### 9.5 【中低频】env-check / 环境指纹判定收紧 🟡
- **症状**：能过一段时间后被风控；`part11` env 向量、`interaction_trace`/`environment_snapshot` 被服务器交叉校验。
- **原因**：小红书加强环境真实性校验（headless 检测、指纹熵）。
- **再研究**：从真实浏览器采样当前 env 向量替换默认值（本研究已见 idx5/idx7 差异）；必要时在真实浏览器上下文代理调用而非纯离线。

### 9.6 【低频】X-Mns / Sc-T 从可选变必需 🔴
- **症状**：过去无需的接口开始要求 X-Mns（非 `"unload"`）或 Sc-T。
- **原因**：`disableMns` 默认改 false，或服务器对特定接口强校验风控 token。
- **再研究**：需进一步逆向风控 VM（`as/v2/ds/*.js`）里的 `getMnsToken`/`getXHSToken`，或在装载了 `window.mns`/`__xhs_sc__` 的浏览器里代理调用。调用约定已在 §8 钉死。

### 9.7 【低频】签名链路整体换代（新 VM / WASM）🔴
- **症状**：`window.mnsv2` 消失或改名；出现 WASM；`_webmsxyw` 链路变化。
- **原因**：风控大版本升级。
- **再研究**：回到 §3 阶段 1 重新黑盒定界。注意本研究确认**当前无 WASM**；若未来引入 WASM 需换工具链。

### 通用再研究清单
1. 确认 attach 模式连通（§1），`window.mnsv2` 等仍为 function。
2. 重新下载当前主 bundle，grep 调用链函数名定位注入点。
3. 对黑盒函数重跑差分分析（同输入多采样定位 entropy 字段、变输入定位派生字段）。
4. 用真实浏览器输出逐字节对齐（比服务器 `code:0` 更强）。
5. 更新 `rebuild/*.js` 常量并跑 `verify_*.js` 回归。

---

## 10. 本质总结

小红书 Web 签名不是密码学强函数，而是 **"一组可识别的标准原语（MD5 / CRC32 / murmur3 / xxHash32 / 自定义 base64 / SM4 变体）+ 硬编码密钥/字母表 + 明文里可控的时间/序列/指纹字段"**，外加 **jsvmp 混淆**抬高工程成本。一旦拿到硬编码常量，即可完整复刻与解密。**可逆本质未变**：失效基本都是"常量/版本/布局漂移"，重抠常量即可修复；只有整体换代（新 VM / WASM）才需从头逆向。

---

## 11. 附录：文件与证据索引

| 文件 | 内容 |
|---|---|
| `report.md` | 完整技术分析报告（§1–§11 章节化） |
| `reproduction-guide.md` | 探索思路速览 |
| `rebuild/env.js` | CRC32 / UTF-8 / 自定义 base64 |
| `rebuild/mnsv2.js` | x-s 核心离线编码 + 解码 |
| `rebuild/xrap.js` | x-rap-param xxHash32 + SM4 变体 + gzip + 信封 |
| `rebuild/generators.js` | a1 / web_id / trace id / xy-direction(murmur3) / URL 助手 |
| `rebuild/session.js` | SessionManager（stateful mnsv2：pageLoadTs/sequence/windowProps） |
| `rebuild/entry.js` | 组装 x-s / x-s-common / x-t + `signHeaders()` 完整 header 集 |
| `rebuild/verify*.js` | 自校验（`verify` / `verify_mnsv2` / `verify_xrap` / `verify_full`，全 PASS） |
| `observe.jsonl` / `analysis.jsonl` / `runtime-evidence.jsonl` | 分阶段证据 |
| `/tmp/xhs_js/*.js` | 本地 bundle 副本（hash 随发版变） |

> 本地实现已与开源 `xhshow` 公开 API 一一对应（唯一未做 `sign_xyw` 的 XYW_ 数据接口路径，属另一条独立链路）。它是**纯签名生成器 + 解码器，不内置接口路径、不发请求**。
> 敏感值（web_session / 账号数据 / 完整签名值）全程未落盘；a1 为设备 cookie、loadts 为页面加载时间戳，均非账号凭证，仅作对齐证据。
