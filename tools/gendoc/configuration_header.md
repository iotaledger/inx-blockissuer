---
description: This section describes the configuration parameters and their types for INX-Indexer.
keywords:
- IOTA Node 
- IOTA Core Node
- Block Issuer
- Configuration
- JSON
- Customize
- Config
- reference
---


# Core Configuration

INX-BlockIssuer uses a JSON standard format as a config file. If you are unsure about JSON syntax, you can find more information in the [official JSON specs](https://www.json.org).

You can change the path of the config file by using the `-c` or `--config` argument while executing `inx-blockissuer` executable.

For example:
```bash
inx-blockissuer -c config_defaults.json
```

You can always get the most up-to-date description of the config parameters by running:

```bash
inx-blockissuer -h --full
```

