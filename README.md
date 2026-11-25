# 弹性容量承诺账房

面向离线云资源池的时窗承诺、节点供给和缩容保护。`demand` 管预测、合同及终止归还，`node` 管开机计划与健康容量，`capacity` 管放置故障域与缩容。SQLite 持久化版本、放置及事件证据；不依赖外部云账号。

无需第三方依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 核对模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

每个子系统有正常和失败 fixture。删除演示数据库即可重放；测试使用独立临时数据库。
