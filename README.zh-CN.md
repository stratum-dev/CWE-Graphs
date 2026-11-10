# CWE 编号体系 DAG（CWE 4.0 – 5.0）

[English](README.md) | **简体中文**

把 MITRE 官方 CWE 4.0 到 5.0 的每个版本全部解析成有向无环图，并用 Graphviz 渲染。**每个版本一个独立子目录**，各自包含完整 DAG、按 Pillar 拆分的子图，以及机器可读的节点/边数据。

本子项目最初为研究论文 **SIGMA: Semantic Imbalance-Guided Matching with Adaptive Retrieval for Vulnerability Detection** 开发，旨在通过可视化图谱展示 CWE 体系的层级结构及语义关联，辅助研究人员分析 CWE 弱点类别之间的结构关系与语义特征。

为便于学术交流、研究复现及其他相关课题的探索，本项目现作为独立子项目开源发布，供研究人员参考和使用。

使用浏览器，打开 `out/index.html` 查看版本矩阵和导航。如果读者不想在本地构建，直接下载最新包：

**[cwe-graphs.zip — 最新 Release](https://github.com/stratum-dev/CWE-Graphs/releases/latest/download/cwe-graphs.zip)**

解压后打开 `out/index.html`。包内包含所有版本、两种完整 DAG 布局、各 Pillar 子图，以及 CSV/JSON 数据。

## 数据来源

| 项目 | 值 |
| --- | --- |
| 来源模式 | `https://cwe.mitre.org/data/xml/cwec_v<version>.xml.zip` |
| 版本 | 4.0、4.1、…、4.21、5.0（共 23 个目录） |
| 本地文件 | `data/v<version>/cwec_v<version>.xml`（同时保留 zip） |
| Schema | CWE 4.x：schema 6/7，使用 `<Category>`；CWE 5.0：schema 8，使用 `<Grouping>` |
| 规范层级 | 所有版本均为 View 1000 |

CWE 5.0 把原来的 **Category** 层改名为 **Grouping**，脚本两者都支持。5.0 的 984 个 Weakness 中，956 个有效，28 个已弃用。

## 版本矩阵

| 版本 | 发布日期 | Weakness | ChildOf 边 | 根 | 深度 | 多父节点 | Category/Grouping 层 | View 1000 名称 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.0 | 2020-02-24 | 862 | 970 | 34 | 5 | 132 | 347 | Research Concepts |
| 4.1 | 2020-06-25 | 898 | 1009 | 34 | 5 | 135 | 347 | Research Concepts |
| 4.2 | 2020-08-20 | 914 | 1031 | 33 | 5 | 140 | 351 | Research Concepts |
| 4.3 | 2020-12-10 | 939 | 1056 | 33 | 5 | 140 | 351 | Research Concepts |
| 4.4 | 2021-03-15 | 941 | 1058 | 33 | 5 | 140 | 351 | Research Concepts |
| 4.5 | 2021-07-20 | 945 | 1062 | 33 | 5 | 140 | 351 | Research Concepts |
| 4.6 | 2021-10-28 | 947 | 1067 | 33 | 5 | 143 | 361 | Research Concepts |
| 4.7 | 2022-04-28 | 950 | 1070 | 34 | 5 | 144 | 386 | Research Concepts |
| 4.8 | 2022-06-28 | 951 | 1072 | 34 | 5 | 145 | 387 | Research Concepts |
| 4.9 | 2022-10-13 | 957 | 1071 | 34 | 5 | 140 | 387 | Research Concepts |
| 4.10 | 2023-01-31 | 958 | 1068 | 35 | 5 | 138 | 387 | Research Concepts |
| 4.11 | 2023-04-27 | 958 | 1068 | 35 | 5 | 138 | 409 | Research Concepts |
| 4.12 | 2023-06-29 | 958 | 1070 | 35 | 5 | 139 | 409 | Research Concepts |
| 4.13 | 2023-10-26 | 959 | 1072 | 35 | 5 | 140 | 409 | Research Concepts |
| 4.14 | 2024-02-29 | 963 | 1076 | 35 | 5 | 140 | 409 | Research Concepts |
| 4.15 | 2024-07-16 | 964 | 1077 | 35 | 5 | 140 | 409 | Research Concepts |
| 4.16 | 2024-11-19 | 965 | 1078 | 35 | 5 | 140 | 409 | Research Concepts |
| 4.17 | 2025-04-03 | 968 | 1078 | 35 | 5 | 138 | 409 | Research Concepts |
| 4.18 | 2025-09-09 | 969 | 1080 | 35 | 5 | 139 | 410 | Research Concepts |
| 4.19 | 2025-12-11 | 969 | 1085 | 35 | 5 | 143 | 420 | Research Concepts |
| 4.20 | 2026-04-30 | 969 | 1086 | 35 | 5 | 144 | 422 | Research Concepts |
| 4.21 | 2026-10-28 | 984 | 1106 | 38 | 5 | 152 | 431 | Complete Weakness Hierarchy |
| 5.0 | 2026-10-28 | 984 | 1106 | 38 | 5 | 152 | 431 | Complete Weakness Hierarchy |

4.21 与 5.0 的 Weakness/边数相同；5.0 改变了 schema 命名空间，并把 category 改称 grouping。所有版本都是 DAG（0 环）。

## 图的结构（CWE 5.0，View 1000）

- **984 个节点，1106 条 `ChildOf` 边，0 个环。**
- 38 个根：10 个 Pillar + 28 个 Deprecated/孤立条目。
- 最大深度 5；719 个叶子节点。
- **152 个节点有多个父节点**（最大入度 3），所以它是 DAG 而不是树；235 个节点可以从不止一个 Pillar 到达。
- 30 个弱连通分量：一个 940 节点的主分量，一个 14 节点的分量（CWE-682 子树），一个 3 节点分量（弃用的 CWE-377 子树），其余 27 个是孤立弃用节点。

5.0 的层级规模：

| 深度 | 0 | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- | --- |
| 节点数 | 38 | 145 | 322 | 338 | 113 | 28 |

抽象层级分布：Pillar 10、Class 131、Base 536、Variant 300、Compound 7。

### Grouping 层（5.0）

Grouping 是**组织层**，不属于弱点的父子层次，因此单独出图：

- 377 / 431 个 Grouping 有成员，共 4350 条成员边（4242 条指向 Weakness，108 条指向另一个 Grouping）。
- Grouping 之间的包含关系构成一个 137 节点 / 108 边的小 DAG；其余 294 个 Grouping 没有下级 Grouping，只在 CSV 中列出。
- CWE 4.x 中同一层用 `<Category>` 存储，条目数通常更少（见版本矩阵）。

### 各 Pillar 子树

每个版本都有一套 Pillar 子图。5.0 的规模：

| Pillar | 名称 | 可达节点 | 子图边 | 深度 | 跨 Pillar 父链接（子图中省略） |
| --- | --- | --- | --- | --- | --- |
| CWE-664 | Improper Control of a Resource Through its Lifetime | 381 | 399 | 5 | 62 |
| CWE-710 | Improper Adherence to Coding Standards | 197 | 199 | 5 | 54 |
| CWE-284 | Improper Access Control | 183 | 198 | 5 | 32 |
| CWE-707 | Improper Neutralization | 146 | 153 | 5 | 21 |
| CWE-693 | Protection Mechanism Failure | 104 | 105 | 4 | 34 |
| CWE-691 | Insufficient Control Flow Management | 87 | 88 | 4 | 25 |
| CWE-703 | Improper Check or Handling of Exceptional Conditions | 59 | 58 | 4 | 24 |
| CWE-697 | Incorrect Comparison | 22 | 21 | 3 | 9 |
| CWE-435 | Improper Interaction Between Multiple Correctly-Behaving Entities | 18 | 17 | 3 | 5 |
| CWE-682 | Incorrect Calculation | 14 | 13 | 2 | 0 |

节点数之和大于 984，是因为共享节点会在多个 Pillar 子图中重复出现。

## 目录结构

```
cwe-graphs/
  data/v<version>/cwec_v<version>.xml(.zip)   原始 MITRE 数据
  out/index.html                              全版本矩阵
  out/v<version>/                             每个版本的完整产物
    index.html
    cwe-dag-full.svg
    cwe-dag-full-sfdp.svg / .png              默认生成
    cwe-dag-overview.svg / .png
    cwe-dag-deprecated.svg / .png
    cwe-grouping-dag.svg / .png
    cwe-legend.svg / .png
    pillars/*.dot|.svg|.png
    cwe_nodes.csv  cwe_edges.csv  cwe_edges_all_views.csv
    cwe_grouping_members.csv  cwe_stats.json  pillars_index.json
  scripts/fetch_cwe.py                        在线下载器
  scripts/build_cwe_dag.py                    单个目录 -> 图 + 数据
  scripts/render_graphs.py                    渲染一个版本目录
  scripts/make_index.py                       生成 HTML 索引
  scripts/build_all.py                        遍历所有版本
```

### 每个版本内的文件

| 文件 | 说明 |
| --- | --- |
| `cwe-dag-full.svg` | 完整 DAG，Graphviz `dot` 分层布局（左→右），父→子方向明确。文件较大，请用浏览器打开并缩放。 |
| `cwe-dag-full-sfdp.svg` / `.png` | 同一张图的力导向总览（不保留方向）。默认生成，HTML 页面可在两种布局间切换。 |
| `cwe-dag-overview.svg` / `.png` | 各 Pillar 及其直接子节点，用于快速定位。 |
| `cwe-dag-deprecated.svg` / `.png` | 无法从任何 Pillar 到达的弃用/孤立条目。 |
| `cwe-grouping-dag.svg` / `.png` | Grouping/Category 包含 DAG。 |
| `cwe-legend.svg` / `.png` | 颜色与线型图例。 |
| `pillars/` | 每个 Pillar 一个诱导子图，含 `.dot`、`.svg`、`.png`。 |
| `cwe_nodes.csv` | 全部条目：ID、类型、名称、抽象层级、状态、深度、父节点、所属根、子树规模、官方 URL |
| `cwe_edges.csv` | 规范 `ChildOf` 边（View 1000），含子/父名称 |
| `cwe_edges_all_views.csv` | 所有 `ChildOf` 关系及 `View_ID`；其他视图会重排父子关系 |
| `cwe_grouping_members.csv` | Category/Grouping 成员关系 |
| `cwe_stats.json` | 全部统计指标 |
| `pillars_index.json` | Pillar 子图索引 |
| `index.html` | 该版本的浏览页 |

## 阅读方式

- 箭头方向：**父 → 子**（`ChildOf`）。`dot` 布局中根在左侧。
- 颜色：深蓝 Pillar、蓝色 Class、浅蓝 Base、更浅的 Variant、橙色 Compound、灰色虚线 Deprecated、黄色虚线 Grouping。
- Pillar 子图是**从该 Pillar 向下可达的诱导子图**。共享节点在该视图中可能只显示一条父边；标题标明了被省略的跨 Pillar 父链接数量。完整边集以完整 DAG 为准。
- 只把 View 1000 视为规范层级。其他视图（1003、1305、1340、700、928 等）会按特定用途重排父子关系，混用会产生语义冲突，因此单独导出。
- 每个版本的 `index.html` 同时提供两种完整图布局，可在 **Layered** 与 **Force-directed** 之间切换；页面内嵌图片全部使用 SVG。
- 分层完整图只生成 SVG（PNG 尺寸过大）；其他图同时有 SVG 和 PNG。

## 在线拉取数据

CLI 直接从 MITRE 下载，不需要手动 curl/unzip。

```bash
python -I scripts/fetch_cwe.py --versions all        # 4.0 ... 4.21、5.0
python -I scripts/fetch_cwe.py --versions 4.x        # 所有 CWE 4.x
python -I scripts/fetch_cwe.py --versions 5.0
python -I scripts/fetch_cwe.py --versions 4.0,4.21,5.0
python -I scripts/fetch_cwe.py --versions 5.0 --force  # 强制重新下载
```

文件写入 `data/v<version>/cwec_v<version>.xml`，zip 作为缓存保留。已存在的 XML 默认跳过，`--force` 可强制刷新；`--out DIR` 可指定其他目录。

## 复现

依赖：Python 3.9+（仅标准库）、Graphviz（`dot` 和 `sfdp`，测试版本 15.1.0）。

```bash
cd cwe-graphs
python -I scripts/build_all.py                  # 先在线补齐缺失版本，再全量构建
python -I scripts/build_all.py --only 5.0       # 只构建一个版本
python -I scripts/build_all.py --offline        # 只用本地数据，不联网
python -I scripts/build_all.py --no-sfdp        # 跳过力导向总览（更快）
```

`build_all.py` 会先为所选版本调用下载器，再生成 `out/v<version>/`。将来 MITRE 发布新版本时，运行 `fetch_cwe.py --versions <新版本>`，或直接 `build_all.py --only <新版本>`，下载器会自动获取。

手动构建单个版本：

```bash
python -I scripts/build_cwe_dag.py data/v5.0/cwec_v5.0.xml out/v5.0
python -I scripts/render_graphs.py out/v5.0
python -I scripts/make_index.py out
```

> 说明：`dot` 每个图约 1–4 秒；`sfdp` 每个版本约 1–2 分钟，因此 23 个版本全量构建约需 30–45 分钟。只想要分层图时加 `--no-sfdp`。
