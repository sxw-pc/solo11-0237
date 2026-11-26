# 弹性容量承诺账房

面向离线云资源池的时窗承诺、节点供给和缩容保护。`demand` 管预测、合同及终止归还，`node` 管开机计划与健康容量，`capacity` 管放置故障域与缩容。SQLite 持久化版本、放置及事件证据；不依赖外部云账号。

无需第三方依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 核对模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

每个子系统有正常和失败 fixture。删除演示数据库即可重放；测试使用独立临时数据库。

## 物理机箱身份与容量凭证（chassis identity）

代理号（`N1`/`N2`）、管理卡证书（`card-a`/`card-b`）和物理机箱是三种不同身份；相同的序列尾段 `44` 不能当作整机序列号。核心决定在以下模块：

- `hardware_capture.py`：不可变清点原件——整页字节与摘要、采录分钟、机架照片摘要、完整机箱号的可见部分、管理卡更换单、一次性随机数实机签认（重放旧 nonce 抛 `NonceReplay`）。同页同内容重送返回 `replayed`，同页异内容抛 `hardware_page_conflict` 并保留冲突记录。旧的 `import_page`/`issue`（按代理号签 16 CPU）行为保持不变。
- `identity.py`：`open_scene` 同时保留 `same_chassis`（换卡一机，8 CPU）与 `distinct_chassis`（同架两机，16 CPU）两种相容解释及各自实物下界/补证路径；`prove_same_chassis`/`prove_distinct_chassis` 处理厂家迟到证明；`joint_binding` 要求完整机箱号与新随机数签认共同绑定 CPU 规格和机架；`proven_cpu` 只合计已实体证明且未隔离的机箱；同机箱合并会为旧代理号上的在用副本写 `migration_todos`，但不删除原放置。
- `capacity_certificate.py`：`issue_version`/`issue_replacement` 签发固定原件摘要与相容解释的新版本凭证（只增不改），并对旧凭证写 `certificate_obligations` 欠交付义务；`cover_obligations`/`fulfill_obligation` 记录补救。旧的 `issue` 仍按代理号汇总（种子测试中的 16 CPU 历史凭证），永不被回写。
- `supply.py`：`quarantine_agent` 隔离代理号；`install_chassis` 只在“独立完整机箱号 + 实测 CPU + 新随机数签认”齐备时计入 Q，并记录机架位/启动额度占用；预热上报、采购单或安装失败都不增加容量，也不会用被隔离的 N2 充数。`available_cpu` 排除被隔离代理，并把绑定到同一机箱的多个代理号折叠为一份物理 CPU。
- `demand.py`/`rebalance.py`：合同承诺与放置改用实体感知的可用容量；同一物理机箱范围内的 CPU 不能在旧号/新号下重复出售（合同层 `capacity_shortfall`，放置层 `physical_chassis_capacity_exhausted`）。

统一入口见 `cloudctl/chassis.py`。场景测试在 `tests/test_chassis_identity.py`。

```sh
python -B -m unittest discover -s tests -q
```
