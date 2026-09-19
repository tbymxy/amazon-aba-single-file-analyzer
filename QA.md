# 单文件网页版本 QA

执行日期：2026-09-19

| 检查项 | 结果 |
| --- | --- |
| HTML/Worker 脚本语法 | 通过 |
| GB 真实周报浏览器导入 | 通过：427,392 条 |
| GB `water bottle` 聚合 | 通过：TOP3 点击 20.38%、TOP3 转化 6.74% |
| 无分页虚拟滚动 | 通过：427,392 条结果仅渲染 29 个可见/预加载行 |
| Google Trends 图标 | 通过：Google favicon 服务返回 32×32 图标 |
| Trends 跳转 | 通过：`gruffalo granny` → `https://trends.google.com/trends/explore?geo=GB&q=gruffalo%20granny` |
| Amazon 跳转 | 通过：`gruffalo granny` → `https://www.amazon.co.uk/s?k=gruffalo%20granny` |
| 十站点映射 | 已配置 US、CA、MX、GB、DE、FR、IT、ES、JP、AU |
| TOP3 上限筛选 | 通过：点击与转化均按“小于等于”输入值筛选 |
| 数据列表字体 | 通过：数据行由 12px 调整为 13px |

边界：网页只处理一个当前选中的 CSV，数据仅保留在浏览器内存；Google Trends 图标及点击后的 Amazon/Google Trends 页面需要网络。
