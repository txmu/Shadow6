# 本机 iperf3 压测流程

此流程测量本机 loopback TCP 基线，不经过 Shadow6。与 Core 链路结果比较时，必须同时注明两者的路径和负载不同。测试只监听 `127.0.0.1`，服务端处理一次连接后退出，不修改路由、防火墙或系统服务。

## 记录环境

```sh
date -u
uname -a
lscpu
nproc
iperf3 --version
```

## 运行有界的 12 流测试

从仓库根目录运行。`-P 12` 是 12 条并发 TCP 流，不表示 12 个 CPU 核心；`-t 15` 把发送时间限制为 15 秒。按实际 CPU 数、内存和负载调整并发与时长，避免干扰其他服务。

```sh
result_dir=$(mktemp -d /tmp/shadow6-iperf.XXXXXX)
iperf3 -s -B 127.0.0.1 -p 15201 -1 > "$result_dir/server.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
sleep 1
iperf3 -c 127.0.0.1 -p 15201 -P 12 -t 15 --json > "$result_dir/iperf3-p12.json"
python3 - "$result_dir/iperf3-p12.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if "error" in report:
    raise SystemExit(report["error"])
received = report["end"]["sum_received"]
print(f"streams={len(report['end']['streams'])}")
print(f"received_Gbit_per_second={received['bits_per_second'] / 1e9:.3f}")
PY
```

保留 `iperf3-p12.json`、UTC 时间和环境信息，记录是否同时运行其他负载。测试结束后仅删除本次由 `mktemp -d` 创建的目录。若要保存结果，先把文件复制到独立报告目录。

## 解读

`sum_received.bits_per_second` 是接收侧汇总速率。loopback 数值受内核、CPU 配额、调度和内存拷贝影响，不能表示网卡带宽、WAN 吞吐或 Shadow6 加密链路吞吐。Shadow6 链路使用 `Benchmark/benchmark.py --role network-chain --require-network` 另行测量；其最高单次并发由测试程序限制为 8。
