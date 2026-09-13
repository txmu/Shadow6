# Shadow6 Benchmark Report

真实原生进程实测结果；`unavailable`/`failed` 未被转换为成功。

| Core | Role | Repeat | Status | Seconds | CPU s | Peak RSS KiB |
|---|---|---:|---|---:|---:|---:|
| go | feature-report | 1 | ok | 0.071249 | 0.010882 | 12956 |
| go | feature-report | 2 | ok | 0.004375 | 0.004274 | 12956 |
| go | feature-report | 3 | ok | 0.004192 | 0.004180 | 12956 |
| rust | feature-report | 1 | ok | 0.019667 | 0.003875 | 12956 |
| rust | feature-report | 2 | ok | 0.002352 | 0.002176 | 12956 |
| rust | feature-report | 3 | ok | 0.001971 | 0.001847 | 12956 |
| zig | feature-report | 1 | ok | 0.009983 | 0.001947 | 12956 |
| zig | feature-report | 2 | ok | 0.001623 | 0.001312 | 12956 |
| zig | feature-report | 3 | ok | 0.001371 | 0.001086 | 12956 |
| ada | feature-report | 1 | ok | 0.048950 | 0.009104 | 12956 |
| ada | feature-report | 2 | ok | 0.004979 | 0.004727 | 12956 |
| ada | feature-report | 3 | ok | 0.004747 | 0.004498 | 12956 |
| d | feature-report | 1 | ok | 0.005498 | 0.003055 | 12956 |
| d | feature-report | 2 | ok | 0.003591 | 0.003176 | 12956 |
| d | feature-report | 3 | ok | 0.003069 | 0.002832 | 12956 |
| nim | - | - | unavailable | 0.000000 | 0.000000 | - |
| cpp | feature-report | 1 | ok | 0.020459 | 0.005063 | 12956 |
| cpp | feature-report | 2 | ok | 0.004083 | 0.003764 | 12956 |
| cpp | feature-report | 3 | ok | 0.003736 | 0.003516 | 13084 |
| pony | feature-report | 1 | ok | 0.058894 | 0.016691 | 21364 |
| pony | feature-report | 2 | ok | 0.041266 | 0.016694 | 21384 |
| pony | feature-report | 3 | ok | 0.040024 | 0.016050 | 21384 |
| hare | feature-report | 1 | ok | 0.006016 | 0.001567 | 21384 |
| hare | feature-report | 2 | ok | 0.001311 | 0.001079 | 21384 |
| hare | feature-report | 3 | ok | 0.001106 | 0.000880 | 21384 |
| carp | feature-report | 1 | ok | 0.002664 | 0.001067 | 21384 |
| carp | feature-report | 2 | ok | 0.001040 | 0.000844 | 21384 |
| carp | feature-report | 3 | ok | 0.000983 | 0.000781 | 21384 |
| gleam | feature-report | 1 | ok | 0.253542 | 0.230517 | 75028 |
| gleam | feature-report | 2 | ok | 0.149862 | 0.242636 | 76540 |
| gleam | feature-report | 3 | ok | 0.156789 | 0.222773 | 77092 |
| idris | - | - | unavailable | 0.000000 | 0.000000 | - |
