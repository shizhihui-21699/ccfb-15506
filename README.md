# SafeFinder

匿名寻物网络的**反跟踪检测后台**（Elixir / OTP）。当一个陌生标签长时间跟随某人移动时，及时提醒被跟踪者并帮助其找到标签，同时不破坏寻物网络既有的匿名性。

完整威胁模型、设计论证与隐私不变量见 [DESIGN.md](DESIGN.md)。

## 它解决什么

寻物标签会被塞进他人的车、包、口袋用于长期跟踪，而被跟踪者往往不知情、用别家品牌手机、身边还有家人的正常同行标签，跟踪者还会频繁更换标签来规避检测。本服务针对三个难点：

1. **家人朋友同行** —— 所有者设备在场证明 + 家庭密钥签名凭证，双重、失败关闭的抑制，且只对确切的 `(受害者, 标签)` 对生效。
2. **跟踪者频繁换标签** —— 账户硬关联 + 受害者作用域的时空软关联，后继标签继承前驱证据，告警以"取代"而非新建的方式保持时间线连续。
3. **受害者用别家品牌手机** —— 遵循 Apple/Google 非自愿跟踪告警互通规范，设备端本地检测为主，后台通过标准化互通通道兜底，载荷不含所有者身份与精确位置。

## 模块结构

| 模块 | 职责 | 进程? |
| --- | --- | --- |
| `SafeFinder.Pipeline` | 摄入编排，串联各阶段 | GenServer |
| `SafeFinder.CoMovement` | 共移动聚类、静止过滤、置信度评分（纯函数） | 否 |
| `SafeFinder.Companion` | 家人/所有者设备同行抑制（纯函数） | 否 |
| `SafeFinder.Rotation` | 标签轮换的硬/软关联（纯函数） | 否 |
| `SafeFinder.Crypto` | 家庭安全清单的 RSA 签名凭证 | 否 |
| `SafeFinder.Alerts` / `.Policy` | 告警生命周期、去重、限流、升级、取代 | GenServer + 纯策略 |
| `SafeFinder.CrossPlatform` | 跨品牌互通告警载荷与投递通道 | 否 |
| `SafeFinder.Retention` | 数据裁剪、冷簇删除、密钥轮换（纯函数） | 否 |
| `SafeFinder.Hashing` / `GeoCell` | 伪名化 HMAC 与隐私网格 | 否 |

所有安全判定都是纯函数，进程只负责编排——安全策略因此可被穷举式单测，不依赖并发时序。

## 运行

需要 Elixir 1.15+ / OTP（在 Elixir 1.20 / OTP 29 上开发验证）。**零外部依赖**。

```bash
mix compile          # 编译
mix test             # 71 个测试，覆盖三个难点与反滥用
mix run demo/anti_stalking_demo.exs   # 四个场景的端到端演示
```

开发环境启动 OTP 监督树：

```bash
MIX_ENV=dev mix run -e 'IO.inspect(Process.whereis(SafeFinder.Pipeline) != nil); System.stop(0)'
```

## 关键隐私边界

- 后台只存 `HMAC(密钥, 轮换BLE伪名)` 句柄，不存硬件 id；finder 用一次性 ephemeral id，批处理后即删。
- 空间比较只在密钥哈希后的隐私网格单元上进行，簇内不保留原始经纬度。
- 家庭关系不落库：后台只验签短时 attestation，不存储关系图，私钥不出手机。
- 告警只寻址受害者，**没有任何所有者反馈通道**；跨平台载荷显式 `owner: nil`、`precise_locations: nil`。
- HMAC 密钥定期轮换，旧密钥销毁后历史伪名与新伪名不可链接；观测明细 7 天裁剪、冷簇 14 天删除。

## 生产化路线

判定模块保持不变，替换外围：进程内状态 → 按受害者哈希分区的 `PartitionSupervisor` 或 Broadway 消费者；等距网格 → H3/S2（接口已隔离）；内存存储 → 带 TTL 的持久化存储并复用 `Retention` 纯函数做清理；阈值用真实标注数据校准。详见 DESIGN.md 第 6 节。
