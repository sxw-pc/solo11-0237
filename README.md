# 弹性容量承诺账房

面向离线云资源池的时窗承诺、节点供给和缩容保护。`demand` 管预测、合同及终止归还，`node` 管开机计划与健康容量，`capacity` 管放置故障域与缩容。SQLite 持久化版本、放置及事件证据；不依赖外部云账号。

无需第三方依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 核对模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

每个子系统有正常和失败 fixture。删除演示数据库即可重放；测试使用独立临时数据库。

## 数据法域与处理许可（data_residency）

`cloudctl/data_residency.py` 在同一本可恢复的 SQLite 账里把**原件采录、真实字节血缘、许可版本、处理计划、节点迁移、临时/备份/恢复点副本与对外交付**相互校验，回答“原始字节、恢复点和结果实际出现在哪个法域”，而不只是“算力放在哪里”。

- 数据集固定来源方、法域、敏感类别、许可版本与允许目的（`residency.dataset`）；应用读取多份输入时取许可的**真实交集**（`residency.access` / `residency.bind_app`）。
- 许可 `residency.license_issue|license_revoke|license_correct` 以 `[effective_from, effective_to)` 与签发时刻为生效边界；旧采录页、晚到写入按**字节落地时刻**裁判，新许可不能追认旧复制，违规记录与已交付旧报告及其许可快照、删除义务永久保留。
- `residency.ingest_page` 直接读取 `storage_capture` 写入的 `storage_copies` 并逐页累计；所有副本（原件/缓存/临时/备份/恢复点/迁移双活）持续在册，直到 `residency.erase` 验证删除。删除失败的旧副本仍可读并阻断合法交付，但历史违规不消失。
- `residency.anonymize` 生成**新摘要 + 可复算证明**；把原摘要换标签或伪造证明会被拒绝并记违规。
- 出境/迁移走 `residency.transfer`，原始数据申请走 `residency.raw_request`；`residency.backup`、`residency.guard_placement`、`residency.place_guarded`、`residency.recover_guarded`、`residency.complete_drain_guarded` 把缓存、备份、恢复与 `rebalance` 迁移纳入同一法域闸门。北美节点有空余 CPU 从不构成先复制后补许可的理由。
- `residency.deliver` 在同一 `BEGIN IMMEDIATE` 事务内复核许可边界、不得存在仍可读的未授权副本、制品证明与收件法域，然后固化许可快照和删除义务；`residency.trace` 给出客户可追溯视图与每份副本的存续/清理责任，`residency.reconcile` 用于控制面断电后的纯持久化恢复。

验收双路径（欧盟受限统计 vs. 事后批准指定字段跨境的可追溯完整报告）及九类对抗情形均在 `tests/test_data_residency.py` 覆盖：

```sh
python -B -m unittest discover -s tests -q
```

