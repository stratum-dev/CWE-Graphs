# CWE Numbering Hierarchy as a DAG (CWE 4.0 – 5.0)

**English** | [简体中文](README.zh-CN.md)

Parses every entry in each MITRE CWE catalog from 4.0 through 5.0 into a directed acyclic graph and renders it with Graphviz. **Each version has its own directory** with a complete DAG, per-pillar subgraphs, and machine-readable node/edge data.

This subproject was originally developed for the research paper *SIGMA: Semantic Imbalance-Guided Matching with Adaptive Retrieval for Vulnerability Detection*. It provides a visual knowledge graph of the CWE taxonomy to facilitate the analysis of hierarchical structures and semantic relationships among CWE weaknesses.

To support academic exchange, research reproducibility, and further exploration in related research areas, this subproject is released independently as an open-source project for researchers to reference and use.

Open the `out/index.html` in browser for the version matrix and navigation. If you do not want to build locally, download the latest build:

**[cwe-graphs.zip — latest release](https://github.com/stratum-dev/CWE-Graphs/releases/latest/download/cwe-graphs.zip)**

Unzip it and open `out/index.html`. The package contains all versions, both complete-DAG layouts, per-pillar subgraphs, and the CSV/JSON data.

## Data source

| Item | Value |
| --- | --- |
| Source pattern | `https://cwe.mitre.org/data/xml/cwec_v<version>.xml.zip` |
| Versions | 4.0, 4.1, …, 4.21, 5.0 (23 catalogs) |
| Local files | `data/v<version>/cwec_v<version>.xml` (zips kept alongside) |
| Schemas | CWE 4.x: schema 6/7 with `<Category>`; CWE 5.0: schema 8 with `<Grouping>` |
| Canonical hierarchy | View 1000 in every version |

CWE 5.0 renamed the old **Category** layer to **Grouping**; the parser accepts both. Of the 984 weaknesses in 5.0, 956 are active and 28 are deprecated.

## Version matrix

| Version | Released | Weaknesses | ChildOf edges | Roots | Depth | Multi-parent | Category/Grouping layer | View 1000 name |
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

4.21 and 5.0 carry the same weakness/edge counts; 5.0 changes the schema namespace and renames categories to groupings. Every version is a DAG (0 cycles).

## Graph structure (CWE 5.0, View 1000)

- **984 nodes, 1106 `ChildOf` edges, 0 cycles.**
- 38 roots: 10 pillars + 28 deprecated/orphan entries.
- Maximum depth 5; 719 leaves.
- **152 nodes have more than one parent** (maximum in-degree 3), so the hierarchy is a DAG, not a tree; 235 nodes are reachable from more than one pillar.
- 30 weakly connected components: one 940-node main component, one 14-node component (CWE-682 subtree), one 3-node component (deprecated CWE-377 subtree), and 27 isolated deprecated nodes.

Level sizes for 5.0:

| Depth | 0 | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- | --- |
| Nodes | 38 | 145 | 322 | 338 | 113 | 28 |

Abstraction mix: Pillar 10, Class 131, Base 536, Variant 300, Compound 7.

### Grouping layer (5.0)

Groupings are an organisational layer, not part of the weakness parent–child hierarchy, so they are drawn separately:

- 377 of 431 groupings have members, with 4350 membership edges (4242 to weaknesses, 108 to another grouping).
- Grouping-to-grouping containment forms a small DAG with 137 nodes and 108 edges; the other 294 groupings contain no sub-groupings and appear only in the CSV.
- In CWE 4.x the same layer is stored as `<Category>` and usually has fewer entries (see the matrix).

### Per-pillar subgraphs

Each version has one subgraph per pillar. For 5.0:

| Pillar | Name | Reachable nodes | Subgraph edges | Depth | Cross-pillar links omitted |
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

Node counts sum to more than 984 because shared nodes appear in several pillar subgraphs.

## Directory layout

```
cwe-graphs/
  data/v<version>/cwec_v<version>.xml(.zip)   raw MITRE catalogs
  out/index.html                              all-version matrix
  out/v<version>/                             one complete artifact set
    index.html
    cwe-dag-full.svg
    cwe-dag-full-sfdp.svg / .png              generated by default
    cwe-dag-overview.svg / .png
    cwe-dag-deprecated.svg / .png
    cwe-grouping-dag.svg / .png
    cwe-legend.svg / .png
    pillars/*.dot|.svg|.png
    cwe_nodes.csv  cwe_edges.csv  cwe_edges_all_views.csv
    cwe_grouping_members.csv  cwe_stats.json  pillars_index.json
  scripts/fetch_cwe.py                        online catalog downloader
  scripts/build_cwe_dag.py                    one catalog -> graphs + data
  scripts/render_graphs.py                    render a version directory
  scripts/make_index.py                       HTML indexes
  scripts/build_all.py                        loop over all versions
```

### Per-version files

| File | Description |
| --- | --- |
| `cwe-dag-full.svg` | Complete DAG, Graphviz `dot` layered layout (left to right), parent → child direction preserved. Large; open in a browser and zoom. |
| `cwe-dag-full-sfdp.svg` / `.png` | Force-directed poster of the same graph (direction not preserved). Generated by default; the HTML page toggles between this and the layered graph. |
| `cwe-dag-overview.svg` / `.png` | Pillars and their direct children, for quick orientation. |
| `cwe-dag-deprecated.svg` / `.png` | Deprecated/orphan entries unreachable from any pillar. |
| `cwe-grouping-dag.svg` / `.png` | Grouping/category containment DAG. |
| `cwe-legend.svg` / `.png` | Colour and line-style legend. |
| `pillars/` | One induced sub-DAG per pillar, with `.dot`, `.svg`, `.png`. |
| `cwe_nodes.csv` | All entries: ID, kind, name, abstraction, status, depth, parents, root, subtree size, official URL |
| `cwe_edges.csv` | Canonical `ChildOf` edges (View 1000), with child and parent names |
| `cwe_edges_all_views.csv` | Every `ChildOf` relation with `View_ID`; other views reorder parent links |
| `cwe_grouping_members.csv` | Category/grouping membership relations |
| `cwe_stats.json` | All statistics |
| `pillars_index.json` | Pillar subgraph index |
| `index.html` | Per-version browsing page |

## Reading the graphs

- Arrow direction: **parent → child** (`ChildOf`). Roots are on the left in the `dot` layout.
- Colours: dark blue Pillar, blue Class, light blue Base, paler Variant, orange Compound, grey dashed Deprecated, yellow dashed Grouping.
- A pillar subgraph is the **induced sub-DAG reachable downward from that pillar**. Shared nodes may show only one parent edge in that view; the title states how many cross-pillar parent links were omitted. The complete graph contains every edge.
- Only View 1000 is treated as canonical. Other views (1003, 1305, 1340, 700, 928, …) reorder parent links for specific purposes; mixing them would introduce semantic conflicts, so they are exported separately.
- Each version's `index.html` embeds both complete-DAG layouts and lets you switch between **Layered** and **Force-directed**; all embedded images are SVG.
- The layered complete graph is SVG-only (the PNG would be too large); other figures have both SVG and PNG.

## Fetching data online

The CLI downloads catalogs directly from MITRE; there is no manual curl/unzip step.

```bash
python -I scripts/fetch_cwe.py --versions all        # 4.0 ... 4.21, 5.0
python -I scripts/fetch_cwe.py --versions 4.x        # every CWE 4.x catalog
python -I scripts/fetch_cwe.py --versions 5.0
python -I scripts/fetch_cwe.py --versions 4.0,4.21,5.0
python -I scripts/fetch_cwe.py --versions 5.0 --force  # re-download
```

Files are written to `data/v<version>/cwec_v<version>.xml` (the zip is kept as a cache). Existing XML files are skipped unless `--force` is given. Use `--out DIR` to fetch elsewhere.

## Reproducing

Requirements: Python 3.9+ (standard library only) and Graphviz (`dot` and `sfdp`; tested with 15.1.0).

```bash
cd cwe-graphs
python -I scripts/build_all.py                  # fetch missing catalogs, then build all
python -I scripts/build_all.py --only 5.0       # one version
python -I scripts/build_all.py --offline        # use local data only, no network
python -I scripts/build_all.py --no-sfdp        # skip force-directed posters (faster)
```

`build_all.py` calls the fetcher automatically for the selected versions, then builds `out/v<version>/`. To add a future release, run `fetch_cwe.py --versions <new-version>` or pass it to `build_all.py --only <new-version>`; the downloader will pick it up.

Manual single-version run:

```bash
python -I scripts/build_cwe_dag.py data/v5.0/cwec_v5.0.xml out/v5.0
python -I scripts/render_graphs.py out/v5.0
python -I scripts/make_index.py out
```

> Note: `dot` takes 1–4 seconds per graph; `sfdp` takes roughly 1–2 minutes per version, so a full 23-version build is about 30–45 minutes. Pass `--no-sfdp` for a fast build with only the layered graphs.

> Linux note: if `sfdp` reports `There is no layout engine support for "sfdp"`, run `sudo dot -c` to register Graphviz plugins (some distro packages skip this in postinst). If overlap removal complains about a missing triangulation library, the renderer automatically retries without `-Goverlap=false`.
