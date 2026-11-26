# 弹性容量承诺账房

面向离线云资源池的时窗承诺、节点供给和缩容保护。`demand` 管预测、合同及终止归还，`node` 管开机计划与健康容量，`capacity` 管放置故障域与缩容。SQLite 持久化版本、放置及事件证据；不依赖外部云账号。

无需第三方依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 核对模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

每个子系统有正常和失败 fixture。删除演示数据库即可重放；测试使用独立临时数据库。

## 地址租约核对与可恢复端点切换

`lease_capture.import_page` 保存整页摘要及租约的发放代理物理身份、网络域
（`domain`，页号不代表网络域）、租约代次、起止时间、客户端确认、现场邻居缓存
与代理应用回执；同号重传按整页摘要识别，改字纸页报 `lease_page_conflict`。

`route_publish` 会核对同一网络域内相同地址的重叠租期：冲突窗口为
`[max(start), min(expires))`，按租约时钟确定唯一临时归属（不按采录/调用顺序删
租约），`executable_endpoints` 保证每个 `(domain, address)` 至多一个可执行端点；
只有证明双侧隔离的不同网络域才允许相同数值地址。`assess_risks` 追加不可变的冲突
窗口、已发布路由串扰与错投方向结论，时钟校准只产生新结论，旧结论/错投事件/修复
动作均可追溯。

两种运维修复都走 `prepare_handoff` → 双侧代理回执/分步 checkpoint →
`commit_handoff`，断电重开用 `recover_handoff`/`reopen` 识别已应用代理：

* **改址 `readdress`**：实测 beta 的 `.8`、收齐 b 的新租约与客户端确认、两侧回执，
  且旧 `.7 -> n2` 邻居缓存失效后才完成；app 的 `.7/n1` 不动。
* **隔离 `isolation`**：建立网络域 `W` 与转换槽（对外 `.8 -> W:.7/n2`），双侧隔离
  回执与隔离实测、转换表实测齐备后才切外部路由；两侧内部 `.7` 均保留。

迟到纸页、重传与租户终止只追加/撤销当前可执行投影，不删除 `endpoint_routes`
中已执行的旧路由，也不冲掉另一租户的地址责任。

```sh
python -B -m unittest tests.test_address_handoff -v
python -B -m unittest discover -s tests -q   # 含原有 14 项，共 40 项
```
