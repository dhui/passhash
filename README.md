# Passhash ![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/dhui/passhash/go.yml?branch=master) [![Code Coverage](https://img.shields.io/codecov/c/github/dhui/passhash.svg)](https://codecov.io/gh/dhui/passhash) [![GoDoc](https://godoc.org/github.com/dhui/passhash?status.svg)](https://godoc.org/github.com/dhui/passhash) [![Go Report Card](https://goreportcard.com/badge/github.com/dhui/passhash)](https://goreportcard.com/report/github.com/dhui/passhash) [![GitHub Release](https://img.shields.io/github/release/dhui/passhash/all.svg)](https://github.com/dhui/passhash/releases) ![Supported Go versions](https://img.shields.io/badge/Go-1.19%2C%201.20-lightgrey.svg) [![HackerOne](https://img.shields.io/badge/HackerOne-ok-brightgreen.svg)](https://hackerone.com/passhash)

passhash addresses the dismal state of password management in Go by offering easy-to-use APIs to manage credentials (e.g. password hashes)

**Note: The exposed surfaces (e.g. interfaces, structs, and struct fields) are in flux until v1.0.0 is released**

## Features

* Simple, easy to use API
* Tunable work factors
* Auto-upgrading KDFs and work factors
* Password usage audit log
* Password policies


## Available Password Policies
Password Policy | Repo
----------------|-----
AtLeastNRunes | Included
NotCommonPasswordNaive | Included

## Available CredentialStores
Credential Store | Repo
-----------------|-----
DummyCredentialStore | Included
StringCredentialStore | Included (in examples)
StringCredentialPepperedStore | Included (in examples)


## Available AuditLoggers
Audit Logger | Repo
-------------|-----
DummyAuditLogger | Included
MemoryAuditLogger | Included
