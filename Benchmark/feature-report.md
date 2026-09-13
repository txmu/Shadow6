# Shadow6 Benchmark Report

真实原生进程实测结果；`unavailable`/`failed` 未被转换为成功。

| Core | Role | Repeat | Status | Seconds | CPU s | Peak RSS KiB |
|---|---|---:|---|---:|---:|---:|
| go | feature-report | 1 | ok | 0.003999 | 0.003882 | 13004 |
| go | feature-report | 2 | ok | 0.004250 | 0.004342 | 13004 |
| go | feature-report | 3 | ok | 0.004357 | 0.004408 | 13004 |
| rust | feature-report | 1 | ok | 0.001850 | 0.001800 | 13004 |
| rust | feature-report | 2 | ok | 0.001794 | 0.001703 | 13004 |
| rust | feature-report | 3 | ok | 0.001642 | 0.001591 | 13132 |
| zig | feature-report | 1 | ok | 0.001009 | 0.000863 | 13132 |
| zig | feature-report | 2 | ok | 0.001058 | 0.000915 | 13132 |
| zig | feature-report | 3 | ok | 0.000991 | 0.000841 | 13132 |
| ada | feature-report | 1 | ok | 0.004377 | 0.004187 | 13132 |
| ada | feature-report | 2 | ok | 0.004525 | 0.004169 | 13132 |
| ada | feature-report | 3 | ok | 0.005233 | 0.005024 | 13132 |
| d | feature-report | 1 | ok | 0.002641 | 0.002433 | 13132 |
| d | feature-report | 2 | ok | 0.002633 | 0.002429 | 13132 |
| d | feature-report | 3 | ok | 0.002653 | 0.002436 | 13132 |
| nim | feature-report | 1 | failed | 0.000725 | 0.000553 | 13132 |
| nim | feature-report | 2 | failed | 0.000816 | 0.000547 | 13132 |
| nim | feature-report | 3 | failed | 0.000637 | 0.000494 | 13132 |
| cpp | feature-report | 1 | ok | 0.003390 | 0.003243 | 13132 |
| cpp | feature-report | 2 | ok | 0.003410 | 0.003240 | 13132 |
| cpp | feature-report | 3 | ok | 0.003336 | 0.003082 | 13132 |
| pony | feature-report | 1 | ok | 0.037532 | 0.013948 | 21496 |
| pony | feature-report | 2 | ok | 0.039056 | 0.014588 | 21496 |
| pony | feature-report | 3 | ok | 0.040678 | 0.015059 | 21520 |
| hare | feature-report | 1 | ok | 0.001274 | 0.001000 | 21520 |
| hare | feature-report | 2 | ok | 0.001312 | 0.000961 | 21520 |
| hare | feature-report | 3 | ok | 0.001046 | 0.000880 | 21520 |
| carp | feature-report | 1 | ok | 0.005656 | 0.001114 | 21520 |
| carp | feature-report | 2 | ok | 0.001152 | 0.000948 | 21520 |
| carp | feature-report | 3 | ok | 0.001012 | 0.000841 | 21520 |
| gleam | feature-report | 1 | ok | 0.159382 | 0.207560 | 74692 |
| gleam | feature-report | 2 | ok | 0.158325 | 0.220203 | 76280 |
| gleam | feature-report | 3 | ok | 0.167243 | 0.228354 | 76280 |
| idris | - | - | unavailable | 0.000000 | 0.000000 | - |
