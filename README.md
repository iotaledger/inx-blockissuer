# INX-BlockIssuer

[![Go](https://github.com/iotaledger/inx-blockissuer/actions/workflows/build.yml/badge.svg)](https://github.com/iotaledger/inx-blockissuer/actions/workflows/build.yml)

INX-BlockIssuer extends the [iota-core](https://github.com/iotaledger/iota-core) Core API with block issuing endpoints that accept transactions instead of signed blocks.
It allows users not having an own issuing-enabled account to use their mana to send blocks by allotting the required mana to the issuer running this node extension.

## Version compatibility
* `1.x` versions are compatible with with IOTA 2.0 and [iota-core](https://github.com/iotaledger/iota-core).

## Setup
We recommend not using this repo directly but using our pre-built [Docker images](https://hub.docker.com/r/iotaledger/inx-blockissuer).
