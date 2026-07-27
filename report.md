# 小红书 Web 签名参数（x-s / x-t / x-s-common / x-rap-param）技术分析报告

- 任务 ID: `xhs-web-xs-sign-2026`
- 目标页面: https://www.xiaohongshu.com/explore
- 目标接口（观察对象）: `POST https://edith.xiaohongshu.com/api/sns/web/v1/homefeed` 等
- 客户端版本: `xhs-pc-web 6.34.4`（bundle 内常量）
- 采集时间: 2026-07-25
- 用途: 个人技术研究与理解，敏感字段全部脱敏，不用于未授权自动化。

---

## 1. 结论摘要

小红书 Web 在 axios 的 dispatch 拦截器（webpack 模块 `crawler-spam`）中，对命中签名规则的请求统一注入以下请求头：

| Header | 来源函数 | 是否可离线确定性重建 |
|---|---|---|
| `X-t` | `xhsSign` | ✅ 完全可以：`String(Date.now())` |
| `X-S-Common` | `xsCommon` | ✅ 完全可以：结构化对象 + 自定义 base64（本报告已复现并自校验通过） |
| `X-s` | `xhsSign` → `seccore_signv2` | ✅ **本次已完全还原**：外壳/编码 + 核心 `x3=window.mnsv2(...)` 均可离线产出，且与浏览器逐字节一致（见 §9） |
| `X-Mns` | `window.mns.getMnsToken` | ⚪ **可选/默认关闭**：`disableMns:true`；未加载时值为 `"unload"`。调用约定已还原（见 §11），服务器不要求 |
| `Sc-T` | `xhsToken` → `window.__xhs_sc__.getXHSToken()` | ⚪ **可选/条件**：`shouldSign(url)` 门控 + 运行时注入；未加载时静默不设。调用约定已还原（见 §11） |

`x-rap-param`：**本轮已还原信封结构并用真实浏览器样本逐字节验证**（见 §10）。它是独立于 x-s 的反爬参数：TLV body → gzip → cyclic-XOR → SM4 变体分组密码 → base64 信封。核心哈希为 **xxHash32**（非 CRC/MD5），分组密码为**自定义 S 盒的 SM4 变体**（非 AES）。

---

## 2. 代码定位与调用链

全部签名逻辑位于同一个静态包：

```
https://fe-static.xhscdn.com/formula-static/xhs-pc-web/public/resource/js/vendor-dynamic.ae665ebb.js
```

调用链（拦截器 → 分发 → 各签名器）：

```
axios http.interceptors.dispatch.use(  // 模块 name:"crawler-spam"
  encryptToken(...)                      // 命中特定 url 时的 token 头
  window.shouldSign(url) ?               // 旧链路（_webmsxyw / window.sign）
    headers = merge(headers, window.sign(realUrl, data), window.f())
) 
signAdaptor():
  shouldSign(a) ? xhsSign(e,a)           // 设置 X-s / X-t
  xsCommon(e,a)                          // 设置 X-S-Common
  shouldToken(a) ? xhsToken(e,a)         // 设置 Sc-T（token）
  logSec({name:"anti_spam_sign_cost", type: window._webmsxyw ? "sign_new":"sign_old"})
```

存在**两套并存**的签名实现：
- 新链路 `seccore_signv2`（`X-s` 以 `"XYS_"` 前缀，依赖 `window.mnsv2`）
- 旧链路 `window.sign` / `window._webmsxyw`（`sign_old`）

运行时通过 `window._webmsxyw` 是否存在来区分 `sign_new` / `sign_old`。

---

## 3. 各参数生成算法

### 3.1 X-t
```js
a.headers["X-t"] = +new Date + "";   // 毫秒时间戳字符串
```

### 3.2 X-s（seccore_signv2）
```js
function seccore_signv2(realUrl, data){
  let c = realUrl;
  if (typeof data === "object") c += JSON.stringify(data);
  else if (typeof data === "string") c += data;
  const u = MD5(c);          // W.Pu
  const p = MD5(realUrl);    // W.Pu
  const v = window.mnsv2(c, u, p);   // ★ 受保护核心（外部 VM），本包内无定义
  const S = { x0:"4.3.7"/*w.i8*/, x1:"xhs-pc-web", x2: window[w.mj]||"PC", x3:v, x4: data? typeof data : "" };
  return "XYS_" + b64Encode(encodeUtf8(JSON.stringify(S)));  // 自定义 base64
}
// xhsSign 中：a.headers["X-s"] = seccore_signv2(getRealUrl(url,params,serializer), data)
```
`getRealUrl`：去掉 origin 的 path+query，并将 `'` 替换为 `%27`。

**关键限制**：`X-s` 的有效性完全由 `window.mnsv2(c,u,p)` 决定，其余（MD5、外壳 JSON、自定义 base64）都是确定性的、已复现。`window.mnsv2` 不在 formula-static 包里，由 `as.xiaohongshu.com/api/sec/v1/ds?appId=xhs-pc-web` 加载的 `fe-static.xhscdn.com/as/v1/3e44/public/*.js` 在运行时安装。这些 SDK 是 jsvmp/字符串数组混淆（非 WASM）的受保护核心。

### 3.3 X-S-Common（xsCommon）
```js
// R="" , I="" (源码中即为空)
const en = {
  s0: getPlatformCode(platform),  // Windows0 iOS1 Android2 MacOs3 Linux4 other5
  s1: "",
  x0: localStorage[z7("b1b1")] || fI("1"),
  x1: "4.3.7",                    // i8
  x2: platform || "PC",
  x3: "xhs-pc-web",
  x4: "6.34.4",                   // 客户端版本
  x5: await getCookieValue(o4="a1"),   // cookie a1
  x6: R,                          // ""
  x7: I,                          // ""
  x8: G = localStorage[q2("b1")], // 指纹 b1（含 xhsFingerprintV3.getCurMiniUa 覆写分支）
  x9: crc32(R + I + G),           // tb = CRC32
  x10: V,                         // 与设备指纹 V 相关
  x11: "normal",
  x12: localStorage[br("dsllt")] + ";" + window._dsl,
};
a.headers["X-S-Common"] = b64Encode(encodeUtf8(JSON.stringify(en)));  // xE(lz(...))
```
其中当命中 `xhsFingerprintV3` 且 UA 规则匹配时，会用 `getCurMiniUa` 回调覆写 `x8`/`x9` 后再赋值。

### 3.4 确定性编码器（本包内完整定义，已逐字提取）
- `tb`/`w` = **CRC32**，标准反射多项式 `0xEDB88320`
- `lz`/`encodeUtf8` = 字符串 → UTF-8 字节数组（`encodeURIComponent` 分解）
- `xE`/`b64Encode` = base64，但使用**自定义字母表**：
  ```
  ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5
  ```
- `Pu`/`S` = 打包进来的 **MD5**（供 `X-Mns` / `seccore_signv2` 使用）

---

## 4. 依赖环境

| 依赖 | 说明 |
|---|---|
| `window.mnsv2(c,u,p)` | X-s 核心；由风控 SDK 运行时注入 |
| `window.mns.getMnsToken` | X-Mns 核心；运行时注入 |
| `window.__xhs_sc__.getXHSToken` | Sc-T token；运行时注入 |
| `window._dsl` | 进入 X-S-Common 的 x12 |
| `window.xhsFingerprintV3.getCurMiniUa` | 覆写 x8/x9 的指纹 |
| `localStorage["b1"]`, `localStorage["b1b1"]`, `localStorage["dsllt"]` | 设备指纹/存储键 |
| `cookie a1` | X-S-Common x5 |
| `document`/`navigator`/`window` | 指纹与平台判定 |

无 WebAssembly；核心保护为 JS 层混淆 VM（`as/*.js`）。

---

## 5. 本地 Rebuild 工程

目录：`artifacts/tasks/xhs-web-xs-sign-2026/rebuild/`
- `env.js` — 确定性原语（crc32 / encodeUtf8 / b64Encode + 自定义字母表），逐字对齐 bundle
- `entry.js` — `buildXSCommon()` / `seccoreSignV2()` / `signRequest()`；`mnsv2` 作为可注入外部依赖
- `verify.js` — 自校验脚本
- `package.json` — `type: commonjs`

运行 `node verify.js`，全部通过：
```
PASS custom-base64 round-trip
PASS crc32 KAT "123456789"==0xCBF43926
PASS X-t is ms timestamp
PASS X-s starts with XYS_
PASS X-S-Common non-empty
PASS X-S-Common has s0..x12 envelope
```
`X-S-Common` 可反解回原始 `{s0..x12}` JSON，证明编码链忠实。

---

## 6. 已知限制（更新）

1. ~~**X-s 不能纯离线产出**~~ → **已解除**：本轮在 attach 模式浏览器上完整还原 `window.mnsv2`，可纯离线产出与浏览器逐字节一致的 `x3`（见 §9）。核心并非受保护到不可逆——它是"结构化明文 XOR 固定 144 字节密钥"，一旦拿到密钥即可完全复刻。
2. **X-Mns / Sc-T** 仍依赖运行时注入对象（本次未展开，属另一条链路）。
3. **x-rap-param** 本轮已在真实客户端签名请求中确认存在（互动类/feed POST 携带），算法未逐字节还原（独立二进制 base64 链路），列为后续。
4. **env-check 指纹差异**：`mnsv2` 明文 `part11` 含 15 字节环境检测向量，会随浏览器/会话正常变化（本会话实测 idx5=1、idx7=2，异于 xhshow 默认全 0）。这是环境指纹的正常差异，非算法差异；用浏览器实测向量后前向重建 100% 逐字节一致。

---

## 9. X-s 核心 `window.mnsv2`（mns0301_）完整还原 ✅

> 本节是"最后一公里"。方法：在 **attach 模式（TCP 9222）** 的已登录浏览器上对 `window.mnsv2` 做差分分析（冻结/差分输入、逐字节归类），交叉参照开源 `xhshow` 模型，最终**用真实浏览器输出逐字节双向对齐验证**（编码 + 解码均 byte-identical）。

### 9.1 关键结论（修正此前 AES 假设）

**核心不是 AES。** `mns0301_` 载荷解码后是 **144 字节结构化明文**，与一个**硬编码 144 字节密钥 `HEX_KEY`** 做**逐字节 XOR**，再用 **X3 自定义 base64** 编码。实测证据：
- 相同输入多次输出：**字节局部变化、无雪崩效应**（AES 分组密码不可能如此）→ 是 XOR-keystream / 流式构造。
- `window.mnsv2.toString()` = jsvmp 解释器薄封装，函数对象上带**内部单调计数器 `ΙII++`**——这解释了"冻结 Date.now/Math.random/getRandomValues 仍不确定"（熵来自内部计数器 + 随机 seed，而非时间）。

（AES-128-CBC 确实存在，但属**另一条 `XYW_` 数据接口路径**，用于绕过某些接口的 406，与 `mns0301_`/`XYS_` 主签名路径无关。）

### 9.2 144 字节明文布局（小端整数；全部经真实浏览器输出验证）

| 偏移 | 字段 | 说明 |
|---|---|---|
| `[0:4]` | `VERSION_BYTES` | 常量 `[121,104,96,41]` |
| `[4:8]` | `seed` | 随机 u32；`seedByte = seed & 0xFF`（后续多处 XOR 掩码） |
| `[8:16]` | `timestamp_ms` | `Date.now()` LE 8 字节 |
| `[16:24]` | `pageLoadTs` | = `loadts` cookie（页面加载时间戳）LE 8 字节 |
| `[24:28]` | `sequence` | 单调序列（每次签名递增） |
| `[28:32]` | `window_props_length` | 环境相关计数 |
| `[32:36]` | `uri_length` | `len(utf8(content))`，content = realUrl(+body) |
| `[36:44]` | `MD5(content)[0:8] ^ seedByte` | **唯一输入派生字段**（仅 MD5 前 8 字节入编码） |
| `[44]` | `a1_len` | = 52 |
| `[45:97]` | `a1` | cookie a1（截断/补齐到 52 字节） |
| `[97]` | `app_len` | = 10 |
| `[98:108]` | `app_id` | `"xhs-pc-web"` |
| `[108:124]` | `part11` | `[1, seedByte^ENV_TABLE[0], ENV_TABLE[i]^ENV_CHECKS[i] (i=1..14)]` |
| `[124:128]` | `A3_PREFIX` | 常量 `[2,97,51,16]` |
| `[128:144]` | `custom_hash_v2(ts_bytes ++ md5_path_bytes) ^ seedByte` | 16 字节自定义哈希（murmur3 风格 IV） |

变换：`payload XOR HEX_KEY(144B)` → `X3-base64` → `"mns0301_" + body`；
再 `x3` 包进 `X-s = "XYS_" + customB64(JSON({x0,x1,x2,x3,x4}))`。

### 9.3 核心常量（逐字提取）

- `HEX_KEY`（144B）：`71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277516db7116035439730fa61e9822a0eca7bff72d8`
- `X3 字母表`：`MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G`
- `X-s / X-S-Common 字母表`：`ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5`
- `HASH_IV`（custom_hash_v2）：`[1831565813, 461845907, 2246822507, 3266489909]`（murmur3 常量）
- `ENV_TABLE`：`[115,248,83,102,103,201,181,131,99,94,4,68,250,132,21]`

### 9.4 逐字节验证（ground truth）

用两个真实浏览器 `mnsv2` 输出（样本 A：`c=/api/sns/web/v1/test`；样本 B：`c=/api/sns/web/v2/homefeed_verify_2026`）：
- **解码方向**：离线 `decodeMnsv2()` 还原出的 `version / uri_length / md5Head(=注入的 u 前 8 字节) / a1(=真实 cookie) / app_id / pageLoadTs(=真实 loadts) / A3_PREFIX` 全部命中；`custom_hash_v2` 逐字节重算命中 16 字节 a3 尾部。
- **编码方向**：用从 live 解码出的 seed/timestamp/sequence 前向重建 `mnsv2()`，输出与浏览器原值 **byte-identical**（两个样本均通过）。

运行 `node rebuild/verify_mnsv2.js` → 全 PASS。`rebuild/entry.js` 已接入离线 `mnsv2`，`signRequest()` 现可纯离线产出完整 `X-s`。

---

## 10. `x-rap-param` 信封结构还原 ✅

> 本轮攻克的第二个难关。方法：在 attach 浏览器上 navigate 到 `search_result` 触发真实签名 POST（`/api/sns/web/v2/search/notes`，正常搜索浏览、无写操作），用 `network_request` 读到真实 `x-rap-param` + 其 `(api, body, x-t)` 上下文，离线解码信封并用**独立实现的 xxHash32 逐字节命中 header 校验和**，再交叉参照开源 `xhshow` 的 `xrap.py`。

### 10.1 关键结论

`x-rap-param` 是独立于 x-s 的反爬参数，**核心既不是 AES 也不是 mnsv2 那套 XOR-key**，而是一条多层管线：

```
body TLV  →  gzip(OS字节 patch=0x03)  →  cyclic-XOR(16B 会话密钥)
          →  SM4 变体分组密码(自定义 S 盒 + 预扩展 10 轮 round keys, ECB)
          →  信封(header + content)  →  base64
```

- 哈希原语 = **xxHash32**（不是 CRC32/MD5）。KAT 已过：`xxh32("")=0x02cc5d05`、`xxh32("abc")=0x32d153ff`。
- 分组密码 = **SM4 变体**：自定义 256 字节 S 盒、预扩展 10 轮轮密钥、末轮 `SBOX + last_round_key` 变换（不是标准 AES/SM4）。

### 10.2 信封字节布局（在真实浏览器样本上逐字节验证）

`base64( header(36B) + content )`：

| 偏移 | 字段 | 实测值（样本）|
|---|---|---|
| `[0:3]` | magic | `07 24 01` |
| `[3]` | salt_len | `5` |
| `[4:8]` | 常量 1 (u32be) | `1` |
| `[8:12]` | 常量 2 (u32be) | `20` |
| `[12:16]` | cipher_body 长度 | `212` |
| `[16:20]` | **content_hash = xxh32(content)** | `ff30ab81` ✅ 逐字节命中 |
| `[20:24]` | protocol_version | `10301` |
| `[24:28]` | enc_time | `16` |
| `[28:36]` | 8×`00` | `00…00` |
| content | `salt("pwnon") + encryptBlock16(sessionKey)(16) + u32be(16) + cipherBlocks(208=16×13) + u32be(origGzipLen)` | — |

**最强证据**：header 里的 `content_hash` 用我方独立 xxHash32 实现对 `content` 重算，逐字节命中 `ff30ab81`。错误的字节布局不可能哈希命中，故信封结构被钉死。

### 10.3 body TLV 结构（`>H` tag + 值）

固定前缀标签：`0x03E8` ts(u64) / `0x03E9` nonce(u32) / `0x03EA` sessionKey(blob) / `0x03EB` `xxh32(api+body)`(u32)；随后一组布尔能力位(1051–1073)、计时字段(1075–1097)、`interaction_trace` 与 `environment_snapshot` 两个 blob、`0x00 00 ff ff` 等。**前 16 字节明文，其余整体 XOR 单字节 mask。**

### 10.4 验证与限制

- 运行 `node rebuild/verify_xrap.js` → 全 PASS：真实样本信封字段 + `content_hash==xxh32(content)` + 生成器 round-trip 自洽。
- 唯一与 xhshow 常量差异：`protocol_version = 10301`（线上）vs `10300`（xhshow）——小版本号提升。
- **未断言整串逐字节等于浏览器**：内层 gzip 体积 + `interaction_trace`/`environment_snapshot` 快照随运行时环境变化（与 mnsv2 的 env-check 向量同类差异）。要整串对齐需 pin 浏览器内部生成的 `sessionKey/salt/mask/nonce/trace/env`，而这些在风控 VM 内部生成、无法从外部注入。**已确认**：信封字段布局、xxHash32、cyclic-XOR、SM4 变体分组密码、TLV 结构。

---

## 11. `X-Mns` 与 `Sc-T`：可选风控 token（本轮定性完成）✅

> 结论先行：这两个头都是**可选、条件性**的风控 token，**默认不参与签名，服务器不要求**。实测多个 `code:0` 请求（`search/onebox`、`search/notes`、`user/me` 等）只带 `x-s/x-t/x-s-common(+x-rap-param)`，**既无 `X-Mns` 也无 `Sc-T`**。当前会话 `window.mns` 与 `window.__xhs_sc__` 均为 `undefined`（懒加载/未安装）。

### 11.1 X-Mns（来自 `vendor-dynamic.ae665ebb.js`，逐字提取）
```js
// AntiSpam 默认配置：{ ..., disableMns: true, ... }  ← 默认关闭
if (!0 !== e.disableMns) try {
  if (window.mns) {
    var B  = getRealUrl(r,c,u);
    var K  = isObjectOrArray(G);             // G = data(payload)
    var et = W.Pu([B, K ? JSON.stringify(G) : ""].join(""));  // W.Pu = MD5
    a.headers["X-Mns"] = window.mns.getMnsToken(B, G, et) || "";
  } else a.headers["X-Mns"] = "unload";      // SDK 未加载 → 字面量 "unload"
} catch(e) { a.headers["X-Mns"] = "error"; }
```
- 调用约定：**`X-Mns = window.mns.getMnsToken(realUrl, data, MD5(realUrl + JSON(data)))`**（与 `mnsv2` 同族，3 参、第 3 参是 MD5）。
- 默认 `disableMns:true` → 整段跳过；启用但 `window.mns` 未加载 → 头值就是字符串 `"unload"`（服务器接受）；异常 → `"error"`。
- `window.mns` / `getMnsToken` 由风控 VM 运行时注入，字符串在 `as/*.js` 里被数组混淆，明文不可见（同 `mnsv2`）。

### 11.2 Sc-T（来自同一 bundle）
```js
function xhsToken(e, a) {
  var r = a.url, c = e.xsIgnore;
  if (!(!c.some(x => r.indexOf(x) >= 0) && v.hF(r))) return a;  // v.hF == shouldSign
  try { a.headers["Sc-T"] = window.__xhs_sc__.getXHSToken() || ""; } catch(e) {}
  return a;
}
```
- 调用约定：**`Sc-T = window.__xhs_sc__.getXHSToken()`**（**无参数**）。
- 门控：与 x-s 同一个 `shouldSign(url)` 谓词；且被 `try/catch` 包裹——`__xhs_sc__` 不存在时**静默不设**该头。
- `window.__xhs_sc__` / `getXHSToken` 同样由风控 VM 运行时注入，明文不可见，当前 `undefined`。

### 11.3 为什么不做离线复刻
- 二者**默认不发**且**服务器不校验**（已用真实 `code:0` 请求证明）。离线复刻收益低。
- 真要产出真实值，需和 `mnsv2` 一样对风控 VM 做进一步逆向或在装载了 `window.mns`/`__xhs_sc__` 的浏览器里代理调用。调用约定与门控已在此钉死；**若需要，等价物**：`X-Mns` 走 `getMnsToken(realUrl,data,MD5(realUrl+JSON(data)))`、`Sc-T` 走无参 `getXHSToken()`。
- 实用建议：离线签名器对 `X-Mns` 用 `"unload"`（或省略）、`Sc-T` 省略即可，与实测浏览器行为一致。

---

## 12. 辅助生成器套件（补齐"签名生成器"缺口）✅

> 至此本地实现与开源 `xhshow` 的公开 API 一一对应：本套件是**纯签名生成器 + 解码器，不内置任何接口路径、不发请求**——把哪个 URL/body 喂进来就为它算签名头，与接口语义无关（与实测结论一致：签名只对 URL+body 整串做）。

### 12.1 新增文件
- `rebuild/generators.js` — `generateA1()`(52位)、`generateWebId(a1)=md5(a1)`、`getB3TraceId()`、`getXrayTraceId(ts,seq)`、`getSearchId()`、`getSearchRequestId()`、`getShardingKey(userId)`(xy-direction，MurmurHash3 变体 %100+1)、`extractUri()`、`buildUrl()`(XHS 规则：仅 `=`→`%3D`)。
- `rebuild/session.js` — `SessionManager` / `SignState`：维护 `pageLoadTimestamp`(固定)、`sequenceValue`(单调递增)、`windowPropsLength`(缓增)，对应 mnsv2 明文里 `[16:24]/[24:28]/[28:32]` 三个随会话演化的字段。
- `rebuild/entry.js` 新增 `signHeaders({url,method,data,ctx,session,userId,xRap,xMns,mnsv2})` — 一步产出**完整浏览器等价 header 集**：`x-s / x-t / x-s-common / x-b3-traceid / x-xray-traceid / x-mns(默认 "unload") / xy-direction`，`xRap:true` 时附 `x-rap-param`。

### 12.2 与 xhshow 公开 API 对应表

| xhshow | 本地实现 | 状态 |
|---|---|---|
| `sign_headers / _get / _post` | `entry.signHeaders(...)` | ✅ |
| `sign_xs / _get / _post` | `mnsv2.buildXS()` / `entry.seccoreSignV2()` | ✅ |
| `sign_xs_common / sign_xsc` | `entry.buildXSCommon(ctx)` | ✅ |
| `get_x_t` | `String(Date.now())` | ✅ |
| `get_b3_trace_id / get_xray_trace_id` | `generators.getB3TraceId / getXrayTraceId` | ✅ |
| `decode_xs / decode_x3` | `mnsv2.decodeMnsv2()` | ✅（逐字节验证，比 xhshow 更强） |
| x-rap-param 生成/解码 | `xrap.xRapParam / decodeEnvelope` | ✅ |
| `generate_a1 / generate_web_id` | `generators.generateA1 / generateWebId` | ✅ |
| `get_search_id / get_search_request_id` | `generators.getSearchId / getSearchRequestId` | ✅ |
| `build_url / extract_uri` | `generators.buildUrl / extractUri` | ✅ |
| `SessionManager / SignState` | `session.SessionManager` | ✅ |
| `sign_xyw`（XYW_ 数据接口路径，AES-128-CBC） | 未实现 | ⚪ 未做（另一条独立链路，非本任务四头） |

### 12.3 验证
- `node rebuild/verify_full.js` → 全 PASS：crc32 KAT、a1 长度/字符集、web_id=md5(a1)、trace id 形态、xy-direction 确定性且 ∈[1,100]、URL 规则、SessionManager 单调性、完整 header 集齐全、x-s 内嵌 x3 解码回 session 的 pageLoadTs/a1。
- 四个 verify 脚本（`verify.js` / `verify_mnsv2.js` / `verify_xrap.js` / `verify_full.js`）全部通过。

**边界**：trace id / xy-direction 是装饰性/遥测值，**不进入 x-s / x-rap 签名**，服务器不校验其精确值，故只保证形态正确与哈希确定性；唯一未实现的是 `sign_xyw`（XYW_ 数据接口路径，属另一条独立签名链路，不在本任务"四头"范围内）。

---

## 7. 方法论说明

- 遵循 Observe-first：先建请求/脚本地图，确认签名头出现点。
- **第一阶段（早期会话）**：MCP 浏览器为 `--remote-debugging-pipe`，交互工具不可用，故走静态 bundle 分析还原确定性外壳。
- **本阶段（当前会话）**：MCP 已修复为 **attach 模式（`--browserUrl http://127.0.0.1:9222`）**，可用 `replay_page_flow` 的 `evaluate` 在真实页面执行 JS。读回通道用 `fetch('/marker/'+data)` 再从 `network_request`/`export_har_snapshot` 读 URL（页面对未知路径返回 302→404，不影响取数）。差分分析全部在页面内完成、仅回传紧凑结论，避免上下文膨胀。
- 交叉参照开源 `xhshow`（`github Cloxl/xhshow`）作为算法字典，但**所有字段以真实浏览器输出为准逐字节校验**，非直接采信第三方实现。

---

## 8. 证据落盘

- `observe.jsonl` — 登录态确认、脚本地图、风控 SDK 线索
- `analysis.jsonl` — 签名调用链、各参数算法、自定义 base64 字母表、核心依赖
- `runtime-evidence.jsonl` — Live Hook mnsv2 I/O、写接口验证、**mnsv2 完整还原 + 逐字节对齐**、**x-rap-param 信封还原 + xxh32 逐字节验证**、**X-Mns/Sc-T 调用约定与门控**
- `rebuild/env.js` `entry.js` — 确定性外壳 + 离线 mnsv2 + `signHeaders()` 完整 header 集
- `rebuild/mnsv2.js` — **X-s 核心离线复刻（编码 + 解码）**
- `rebuild/xrap.js` — **x-rap-param 离线复刻（xxh32 + SM4 变体 + TLV + gzip + 信封生成/解码）**
- `rebuild/generators.js` — a1 / web_id / trace id / xy-direction / URL 助手
- `rebuild/session.js` — `SessionManager`（stateful mnsv2 signing）
- `rebuild/verify.js` `verify_mnsv2.js` `verify_xrap.js` `verify_full.js` — 自校验（全 PASS）
- 原始 bundle 本地副本：`/tmp/xhs_js/*.js`；参照实现：`github Cloxl/xhshow`（临时 clone 已删）
