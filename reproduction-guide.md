# 小红书 Web 签名算法逆向：完整探索思路

> 任务：`xhs-web-xs-sign-2026` ｜ 目标：`x-s / x-t / x-s-common / x-rap-param`
> 客户端：`xhs-pc-web 6.34.4`，API 域 `edith.xiaohongshu.com`
> 日期：2026-07-26 ｜ 性质：个人技术研究，敏感值全程脱敏
>
> 可信度标注：✅ 实测 ｜ 🟡 强推断 ｜ 🔴 假设

---

## 一、如何连接（简）

- 起 Chrome：`--remote-debugging-port=9222 --user-data-dir=<profile>`，登录小红书。
- 逆向工具以 **attach 模式**接 9222（关键：不是自启动，否则 Hook/evaluate 用不了）。
- 判据：能 `list_pages` 正常返回页面、能在页面上下文执行 JS。
- 打开 `/explore`，首屏 SSR 渲染出真实内容 = 登录态有效。

> 一句话：**必须是 TCP(9222) + attach**，pipe 模式只能只读、无法 Hook。

---

## 二、核心：探索完整签名算法的思路

整个逆向可拆成 **6 个递进阶段**。前 3 步我们已实测走通；后 3 步是还原"最后一公里"（x-s 核心 VM）的思路。

### 阶段 1 — 黑盒定界：先搞清"谁签、签什么、何时签" ✅

不要一上来读代码。先观察：
1. **建请求地图**：滚动/搜索触发带签名的 XHR，看哪些请求带 `x-s`。发现签名在 axios 拦截器里**请求发出前统一注入**，与读/写无关，只看 URL 是否命中规则。
2. **建脚本地图**：签名逻辑集中在 `vendor-dynamic.ae665ebb.js`；而 `window.mnsv2/mns` 由 `as.xiaohongshu.com` + `fe-static/as/*.js` 运行时注入（jsvmp 混淆核心）。

**产出**：知道入口函数 `seccore_signv2 / xsCommon`，知道核心黑盒是 `window.mnsv2`。

### 阶段 2 — 拆解"外壳"：能静态提取的部分先吃干净 ✅

x-s / x-s-common 的**外层**都是明文可读的确定性逻辑，从 bundle 逐字提取即可：
- `x-t = Date.now()`
- `x-s = "XYS_" + 自定义base64(JSON({x0,x1,x2, x3:mnsv2(...), x4}))`
- `x-s-common = 自定义base64(utf8(JSON({s0..x12})))`
- 编码器三件套：**CRC32(0xEDB88320)、UTF-8 编码、自定义字母表 base64**（`ZmserbB...RX5`），外加 **MD5**。

**关键**：`x-s` 里除了 `x3` 之外全是可复现的；`x3 = mnsv2(c, MD5(c), MD5(url))` 是唯一黑盒。**问题被收敛到"还原 mnsv2 一个函数"**。

### 阶段 3 — Hook 采样：把黑盒的输入输出关系钉死 ✅

在页面里透明包裹 `window.mnsv2`，记录每次 `(args, return)`：
- 确认签名 `mnsv2(c, u, p)` 恒 3 参；
- 实测 `u = MD5(c)`、`p = MD5(realUrl)`（用 GET 无 body 的请求最干净：此时 c===realUrl 故 u===p，再用 Node crypto 交叉验证 MD5 命中）；
- 返回值 `mns0301_` + ~192 字符载荷；
- **非确定性**：同一 `(c,u,p)` 两次输出不同，但前缀 `mns0301_gRaKq` 稳定 → 内部混入 **timestamp / nonce / 计数器**。

**产出**：mnsv2 的 I/O 合同 + "它不是纯函数"这个关键性质——决定了后面必须把"时间/序列"当作明文里的可控字段来还原。

### 阶段 4 — 原语指纹识别：不用读懂每条指令 🟡

反 jsvmp 最省力的切入点不是"读懂 VM"，而是"**认常量**"。在 VM 的数据段/内存里找特征：
- 256 字节 **AES S-box** + RCON → 用了 AES；
- 32 位 hex 输出 → MD5；`0xEDB88320` → CRC32；
- `(1831565813,461845907,2246822507,3266489909)` → MurmurHash3（`xy-direction` 用它）；
- 乱序 64 字符表 → 自定义 base64。

**决定性线索**🟡：开源实现里存在 `decode_x3()/decode_xs()`——**能解密就说明核心是"固定密钥对称加密"而非单向哈希**。这把难度从"破解"降为"抠常量"。

### 阶段 5 — 抠密钥 + 还原明文结构（还原"最后一公里"）🔴

两条路子拿到 AES key/IV 和拼装逻辑：
- **动态断点法（省力）**：在识别出的 AES 加密调用处断下，直接从参数/内存读 key、IV、明文 buffer。
- **反虚拟化法（彻底）**：dump jsvmp 字节码 → 写 disassembler 把自定义指令还原成可读逻辑 → 直接读出 `AES_KEY / IV / 144字节XOR key / VERSION_BYTES / A3_PREFIX` 等字面量。

拿到 key 后，**解密若干真实 x-s**，逐字节对齐字段，推测明文布局大致为：
```
[version bytes][MD5派生字节][timestamp 小端8B][sequence 计数器][env指纹][checksum]
```
（timestamp/sequence 正好解释阶段 3 观察到的非确定性——它们是明文里每次变化的字段。）

### 阶段 6 — 复刻 + 服务器验证（ground truth）✅思路

- 复刻"填时间戳 + 自增序列 → AES 加密 → 组装 XYS_ 信封"；
- 用登录会话打**只读接口**（如 `user/selfinfo`），看 `code:0`；
- 服务器是最终裁判：接受即证明字节序、padding、base64 变体、字段布局全对。
- 长期稳定性靠模拟真实节奏（页面加载时间戳固定 + 序列单调递增，即 `SessionManager` 思路）。

---

## 三、本研究到达的位置（已更新 — 全部完成）

- ✅ **阶段 1–3 全部实测走通**：外壳完全还原、mnsv2 I/O 与 MD5 关系钉死、非确定性证实。
- ✅ **确定性部分本地重建 + 自校验通过**（`rebuild/`：crc32 KAT、自定义 base64 round-trip、x-s-common 反解）。
- ✅ **服务器验证**：用开源库 xhshow 打只读接口 `code:0`，多写接口签名结构实测一致。
- ✅ **阶段 4–6 本轮完成**（关键突破）：在 **attach 模式**浏览器上对 `window.mnsv2` 做差分分析 + 交叉参照 xhshow，**完整还原核心并用真实浏览器输出逐字节双向对齐**（编码 + 解码均 byte-identical）。

**核心结论修正**：`mns0301_` 核心**不是 AES**，而是 **144 字节结构化明文 XOR 一个硬编码 144 字节密钥（`HEX_KEY`）再 X3 自定义 base64**。之前"固定密钥 AES"的推断被实测否定（无雪崩、字节局部变化 = XOR 流式构造）。AES-128-CBC 仅存在于另一条 `XYW_` 数据接口路径。

- 产物：`rebuild/mnsv2.js`（离线编码 + 解码）、`rebuild/verify_mnsv2.js`（真实浏览器输出双向逐字节校验，全 PASS）、`entry.js` 已接入离线核心 → `signRequest()` 现可**纯离线产出完整 `X-s`**。
- 明文布局与常量、验证细节见 `report.md §9`。

### x-rap-param（第二个难关，本轮攻克）✅

- ✅ **信封结构在真实浏览器样本上逐字节验证**：`ByQB` 信封 = header(magic `07 24 01`/salt_len/const1=1/const2=20/cipher_body_len/`xxh32(content)`/protocol_version=10301/enc_time/8×00) + content(salt + `encryptBlock16(sessionKey)` + u32(16) + cipherBlocks + u32(origGzipLen))。
- ✅ **最强证据**：header 的 `content_hash` 用独立 xxHash32 实现逐字节命中（`ff30ab81`）。
- ✅ **管线还原**：body TLV → gzip(OS 字节 0x03) → cyclic-XOR(16B key) → **SM4 变体分组密码**（自定义 S 盒 + 预扩展轮密钥，非 AES）→ 信封 → base64。哈希为 **xxHash32**（非 CRC/MD5）。
- 产物：`rebuild/xrap.js`（生成器 + 解码器）、`rebuild/verify_xrap.js`（全 PASS）。详见 `report.md §10`。
- 限制：整串未逐字节对齐浏览器（内层 gzip 体积 + trace/env 快照随运行时环境变化，需 pin VM 内部随机量）。信封字段/xxh32/SM4 变体/cyclicXor/TLV 已确认。

### X-Mns / Sc-T（可选风控 token，本轮定性完成）✅

- ⚪ **默认不参与签名、服务器不要求**：实测多个 `code:0` 请求（search/onebox、search/notes、user/me）只带 `x-s/x-t/x-s-common(+x-rap-param)`，无 X-Mns、无 Sc-T。`window.mns`/`window.__xhs_sc__` 当前均 `undefined`。
- **X-Mns** = `window.mns.getMnsToken(realUrl, data, MD5(realUrl+JSON(data)))`；`AntiSpam` 默认 `disableMns:true`，SDK 未加载时头值为字面量 `"unload"`，异常为 `"error"`。
- **Sc-T** = `window.__xhs_sc__.getXHSToken()`（无参），由 `shouldSign(url)` 门控 + `try/catch`，SDK 未加载则静默不设。
- 二者由风控 VM 运行时注入（同 mnsv2/mns，字符串数组混淆），默认不发；离线签名器对 X-Mns 用 `"unload"` 或省略、Sc-T 省略即可。详见 `report.md §11`。

---

## 四、为什么这个算法可被还原（本质 — 已用实测修正）

核心**不是密码学强函数，也不是 AES**，而是 **"结构化明文（版本/时间/序列/MD5前8字节/a1/appId/环境指纹/自定义哈希）逐字节 XOR 一个硬编码 144 字节密钥，再自定义 base64"**。JSVMP 混淆只抬高了"抠 `HEX_KEY` 和还原拼装逻辑"的工程成本，并未改变可逆本质——一旦拿到硬编码密钥，就能解密任意 `mns0301_`、看到明文、完整复刻（本轮已做到编码/解码双向逐字节等价）。

之前"固定密钥 AES"的假设方向对（对称、可逆、抠常量），但**具体原语判断错误**：实测差分显示无雪崩效应，是 XOR-keystream 而非分组密码。教训：原语指纹要用**运行时差分实测**确认（雪崩测试），不能只靠"能解密"反推 AES。
