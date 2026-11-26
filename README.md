# 弹性容量承诺账房

面向离线云资源池的时窗承诺、节点供给和缩容保护。`demand` 管预测、合同及终止归还，`node` 管开机计划与健康容量，`capacity` 管放置故障域与缩容。SQLite 持久化版本、放置及事件证据；不依赖外部云账号。

无需第三方依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 核对模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

每个子系统有正常和失败 fixture。删除演示数据库即可重放；测试使用独立临时数据库。

## P1 母排转供安全账（feed_capture / power_gate）

`power_gate.energize` 是早期“单节点、单来源、最近一次读数”的临时许可原语，
`tests/test_power_seed.py` 固定了它的行为（因此同一母排两张独立 6/10 permit
仍会被原样保留）。安全转供由新的不可变票证层负责：

- `feed_capture` 保存触点回读、调度命令/回执、停电起止、电池报告与每分钟实际
  耗量、母排/带载测量、服务事件；所有原件进 `ev_evidence` 并按自增 `seq`
  保留到达次序。同号同文重放幂等，同号异文隔离到 `evidence_conflicts` 并抛
  `*_conflict`；`seal_archive` 固化事故留档。
- `power_gate.sign_transfer` 只在以下证据同时成立时签 `signed` 票，否则留下
  `held` 票：其他外部来源均有“已到达的、最新的”物理断开回读（分闸命令和调度
  成功不算数；焊死/仍闭合报 `backfeed_risk`）、目标来源合闸回读与带载测量到齐、
  同一分钟的可供功率覆盖票内节点加母排在服节点的合计负载、所选电池桥接由实测
  荷电量/最大放电功率/逐分钟实际耗量核验。迟到或缺分钟的电池回报不得推断连续
  服务；迟到的乐观遥测不会回补已扣电量。
- 票号不可变：同号同请求重放返回原决定，异内容冲突；条件变化后须用新票号。
  SQLite 文件重启后，两张历史危险 permit、held/signed 票和封存档案都仍在。

`fixtures/p1_power_transfer.json` 是固定 P1 事故原件（按到达次序），
`power_gate.replay_messages` 可整体幂等重放；两种预批处理分别由
`tests/test_power_transfer.py` 的 `ApprovedPlanATests` 与
`ApprovedPlanBTests` 用同一组真实证据门驱动，不存在策略开关。

```sh
python -B -m unittest discover -s tests -q
```

