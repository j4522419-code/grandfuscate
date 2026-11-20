# V4 high-entropy benchmarks — size and literal share

Measured 2026-11-19T07:53:19.786964+00:00. Fixture `tests/cases/hello_world.luau`. `string%` = bytes inside quoted/long-bracket string literals / total; `encoded%` = string + numeric literal bytes / total. `base` = exact zero-padding build for that (preset, seed); `pad` = inert symbol soup actually emitted; `gate` = v3 baseline x 1.15.

preset seed          bytes  v3 base     gate     base     pad  string%  encoded%    vs_v3
light  20261118     147673   156438   179903   108331   40000   37.97%    53.74%    -5.6%
light  7            168509   156438   179903   133170   35938   31.55%    47.62%     7.7%
light  99991        215807   156438   179903   215807       0    7.57%    28.50%    38.0%
medium 20261118     209143   196415   225877   149748   60000   48.21%    61.38%     6.5%
medium 7            211678   196415   225877   173076   39248   38.68%    53.06%     7.8%
medium 99991        263959   196415   225877   263959       0   15.38%    34.92%    34.4%
heavy  20261118     657027   610864   702493   557639  100000   78.55%    84.00%     7.6%
heavy  7            659733   610864   702493   575637   84706   76.07%    81.68%     8.0%
heavy  99991        684457   610864   702493   684457       0   60.87%    70.14%    12.0%

## Before / after (canonical seed)

| Preset | v3 baseline | V4 bytes | Change | V4 string% | V4 encoded% |
|---|---:|---:|---:|---:|---:|
| light | 156,438 | 147,673 | -5.6% | 37.97% | 53.74% |
| medium | 196,415 | 209,143 | +6.5% | 48.21% | 61.38% |
| heavy | 610,864 | 657,027 | +7.6% | 78.55% | 84.00% |

## Interpretation (lower_target / gate wins)

- The 90–95% encoded-literal-share target is **not** reached: heavy peaks at 84.00%, light/medium are 28–61%. Raw `!@^&#%...` outside string literals is a Luau parse error, so all entropy must live inside literals; reaching 90% would require padding that breaks the <=15% size gate. Per the plan, the gate wins and the achieved maximum is recorded — no 99% claim and no multi-megabyte padding.
- padding is clamped to the exact zero-padding base of each build. For seeds whose third-pass VM base already exceeds the fixed gate (e.g. light/99991), v4 adds **zero** padding.
- All outputs parse, run with identical behaviour, stay < 1 MiB, start with the required top banner, then a `return`-first body with no other comments, and contain no `loadstring`/`HttpGet` self-decoding wrapper.
