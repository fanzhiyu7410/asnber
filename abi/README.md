# 导出符号基线

本目录保存各共享库的导出符号清单，供 `scripts/check_exports.py` 与 CI 校验。每个文件一个符号一行，`#` 开头为注释。

## 0.1.0 基线

| 包 | 符号文件 | 符号数 |
| --- | --- | --- |
| `asnber` | `asnber.symbols.txt` | 73 |
| `asnber-pkix` | `asnber-pkix.symbols.txt` | 57 |
| `asnber-pkcs1` | `asnber-pkcs1.symbols.txt` | 31 |
| `asnber-pkcs8` | `asnber-pkcs8.symbols.txt` | 27 |
| `asnber-pkcs10` | `asnber-pkcs10.symbols.txt` | 25 |
| `asnber-pkcs12` | `asnber-pkcs12.symbols.txt` | 37 |
| `asnber-cms` | `asnber-cms.symbols.txt` | 148 |

`asnber-pkcs` 不产库、不导符号。描述表格式版本为 `1.0`，`header_size = 108`。

## 版本门槛

- **patch 版本不得新增导出符号**。新增符号必须进入 minor 或 major。
- 删除、改名、改变既有符号签名或语义只能进入 major 版本；minor 版本只允许新增符号。
- 修改任一 `*.symbols.txt` 都视为 ABI 决策，必须同时更新本文件中的基线表，并在 CHANGELOG 说明属于哪个版本块。
- `scripts/check_exports.py` 校验“实际导出 == 基线”，它只负责发现漂移，不判断版本号是否合规；合规性由评审与 CHANGELOG 版本块保证。

## 校验方式

```sh
python scripts/check_exports.py --build-dir <共享库构建目录>
```

七个包全部一致时退出码为 0；缺少基线中的符号、或出现基线外符号时失败。
