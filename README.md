# Passhash
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