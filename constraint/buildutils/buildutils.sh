#!/usr/bin/env bash

echo 'Starting tool build...'

echo 'controller-gen'
GO111MODULE=on go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0

echo 'client-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/client-gen@v0.20.5

echo 'deepcopy-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/deepcopy-gen@v0.20.5

echo 'conversion-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/conversion-gen@v0.20.5
