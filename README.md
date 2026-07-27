# xhs-web-reverse · 小红书 Web 动态签名逆向

> 对小红书（xiaohongshu.com）Web 端请求签名头 `x-s / x-t / x-s-common / x-rap-param` 及 `X-Mns / Sc-T` 的算法逆向研究。**纯个人技术研究与学习用途。**

面向 `xhs-pc-web`（`webBuild=6.34.4`，签名内部版本 `4.3.7`），研究时间 2026-07。本仓库是一个**签名生成器 + 解码器**——它不内置任何接口路径、不发任何网络请求；喂给它 URL / body，它算出签名头。签名只对 `URL + body` 整串做，与接口语义无关。

## 亮点

- **x-s 核心 `window.mnsv2`（`mns0301_`）完整还原**：证实核心**不是 AES**，而是「144 字节结构化明文 XOR 一个硬编码 144 字节密钥 → X3 自定义 base64」的流式构造。编码 / 解码双向实现。
- **x-rap-param 信封结构还原**：`TLV → gzip → cyclic-XOR → SM4 变体分组密码 → base64` 信封；哈希为 **xxHash32**（非 CRC/MD5），分组密码为**自定义 S 盒的 SM4 变体**（非 AES）。含 `content_hash == xxh32(content)` 的字节级校验。
- **x-t / x-s-common 完全离线还原**：CRC32 / UTF-8 / 自定义字母表 base64 三件套。
- **X-Mns / Sc-T 定性**：可选风控 token，默认不参与签名、服务器不要求（调用约定与门控见文档）。
- **辅助生成器套件**：a1 / web_id / trace id / xy-direction(MurmurHash3 变体) / SessionManager 状态化签名 / URL 助手。

## 目录结构

```
rebuild/
  env.js            CRC32 / UTF-8 / 自定义 base64（确定性编码器）
  mnsv2.js          x-s 核心（mns0301_）离线编码 + 解码
  xrap.js           x-rap-param（xxHash32 + SM4 变体 + gzip + 信封）生成 + 解码
  generators.js     a1 / web_id / trace id / xy-direction / URL 助手
  session.js        SessionManager / SignState（状态化签名）
  entry.js          组装 x-s / x-s-common / x-t + signHeaders() 完整 header 集
  verify*.js        自校验脚本（全 PASS）
report.md             完整技术分析报告（分章节）
TECHNICAL-WRITEUP.md  每个参数的逆向全流程 + 未来失效再研究指南
reproduction-guide.md 探索思路速览
```

## 快速开始

```bash
cd rebuild
node entry.js          # 演示：产出完整 header 集
npm run verify         # 运行全部自校验（env / mnsv2 / xrap / full）
```

一步产出完整 header 集：

```js
const { signHeaders, SessionManager } = require('./rebuild/entry');

const session = new SessionManager({ pageLoadTimestamp: Date.now() });
const headers = signHeaders({
  url: '/api/sns/web/v1/homefeed',
  method: 'POST',
  data: { num: 18 },
  session,
  xRap: true,
  ctx: { a1: '<你的 a1 设备 cookie>', b1: '<设备指纹>', dsl: '<window._dsl>' },
});
// -> { 'x-s', 'x-t', 'x-s-common', 'x-b3-traceid', 'x-xray-traceid', 'x-mns', 'xy-direction', 'x-rap-param' }
```

解码（验证「可逆」）：

```js
const M = require('./rebuild/mnsv2');
console.log(M.decodeMnsv2('mns0301_...'));   // 还原 144 字节明文结构化字段

const X = require('./rebuild/xrap');
console.log(X.decodeEnvelope('ByQB...'));    // 拆解 x-rap-param 信封
```

## 各签名头一览

| Header | 来源 | 状态 |
|---|---|---|
| `x-t` | `String(Date.now())` | 完全还原 |
| `x-s` | `seccore_signv2` → `mns0301_`（144B XOR-key 流式） | 完整还原（双向） |
| `x-s-common` | 结构化对象 + 自定义 base64 | 完全还原 |
| `x-rap-param` | TLV → gzip → cyclic-XOR → SM4 变体 → 信封 | 信封结构还原 + xxh32 字节级验证 |
| `X-Mns` | `window.mns.getMnsToken(url,data,MD5(url+JSON))` | 可选/默认关闭（`disableMns:true`） |
| `Sc-T` | `window.__xhs_sc__.getXHSToken()` | 可选/条件（`shouldSign` 门控） |

详见 [`TECHNICAL-WRITEUP.md`](./TECHNICAL-WRITEUP.md)，含**每个参数的逆向全流程**与**未来失效时的排查指南**（按可能性排序：字母表/常量轮换 → bundle hash 变化 → 版本号提升 → 明文布局变更 → 环境指纹收紧 → 整体换代）。

## 关于数据（隐私说明）

本仓库中的所有验证脚本使用**合成占位输入**（假的 a1、整数时间戳、示例 body），不含任何真实设备 cookie、会话凭证或抓取到的真实签名样本。原研究曾用真实浏览器输出做逐字节对齐，那部分对齐结论记录在 `report.md`，但真实值未纳入本仓库。

- `HEX_KEY` / S 盒 / 字母表 / VERSION_BYTES 等是**小红书的算法常量**（非个人信息）。
- `a1` 是设备级标识 cookie（非账号密码）；算法本身不依赖其具体值——喂任意 a1 都能运行。

## 免责声明

本项目仅用于**安全研究、算法理解与学习**。不得用于未授权的自动化访问、绕过风控、批量抓取或任何违反小红书服务条款/相关法律法规的用途。使用者需自行承担责任。签名算法常量会随小红书发版轮换，本仓库为特定版本的研究快照，可能随时失效。

## 参考

- 交叉参照了开源实现 [`Cloxl/xhshow`](https://github.com/Cloxl/xhshow) 作为算法字典；但所有字段以真实浏览器输出为准逐字节校验，非直接采信第三方实现。
