/*
Package passhash helps you safely hash passwords for storage
using well-known adaptive hash functions (a.k.a. key derivation functions e.g. KDFs) provided by golang.org/x/crypto

Features:
  - Simple, easy to use API
  - Tunable work factors
  - Auto-upgrading KDFs and work factors
  - Password usage audit log
  - Password policies

passhash gets out of your way, yet is also flexibile to meet your security needs.

Experts may modify defaults (e.g. via init()) but need to exercise caution to ensure that the new parameters (Kdf and CostFactor) are in fact secure.
*/
package passhash
