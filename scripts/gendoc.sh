#!/bin/bash
pushd ../tools/gendoc

# determine current inx-blockissuer version tag
commit_hash=$(git rev-parse --short HEAD)

BUILD_LD_FLAGS="-s -w -X=github.com/iotaledger/inx-blockissuer/components/app.Version=${commit_hash}"

go run -ldflags "${BUILD_LD_FLAGS}" main.go

popd
