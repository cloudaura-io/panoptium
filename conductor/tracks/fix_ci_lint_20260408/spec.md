# Spec: Fix CI Linter Failures

## Overview

The CI lint pipeline (GitHub Actions, golangci-lint v1.64.8) is failing with 5 lint violations across 3 files. Additionally, the local Makefile pins golangci-lint at v1.61.0 while CI uses v1.64.8, creating a configuration mismatch that can cause local/CI divergence.

## Source

GitHub Actions run: https://github.com/cloudaura-io/INTERNAL-panoptium/actions/runs/24106096673/job/70329586332

## Lint Violations

### 1. goconst — `test/deploy/deploy_test.go:34`
String literal `../..` appears 3 times. Extract to a named constant.

### 2. unconvert — `test/utils/utils.go:95`
Unnecessary type conversion. Remove the redundant cast.

### 3. unconvert — `test/utils/utils.go:156`
Unnecessary type conversion. Remove the redundant cast.

### 4. dupl — `pkg/threat/matcher_test.go:175-220` ↔ `259-304`
Two test blocks contain duplicate logic. Extract shared logic into a helper function.

## Configuration Fix

### 5. Version mismatch — Makefile vs CI
- **Makefile:** `GOLANGCI_LINT_VERSION ?= v1.61.0`
- **CI (lint.yml):** `version: v1.64.8`

Update the Makefile to pin `v1.64.8` to match CI.

## Acceptance Criteria

- [ ] All 5 lint violations are resolved
- [ ] Local `make lint` passes with the same golangci-lint version as CI (v1.64.8)
- [ ] No new lint violations introduced
- [ ] Existing tests still pass (`make test`)

## Out of Scope

- Upgrading golangci-lint beyond v1.64.8
- Enabling additional linters
- Fixing lint issues not reported in this CI run
