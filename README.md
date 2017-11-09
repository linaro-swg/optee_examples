# OP-TEE Sample Applications
## Contents
1. [Introduction](#1-introduction)
2. [List of sample applications](#2-list-of-sample-applications)


## 1. Introduction
This document describes the sample applications that are included in the OP-TEE,
that aim to showcase specific functionality and use case.

For sake of simplicity, all OP-TEE example test application are prefixed with
`optee_example_`.

---
## 2. List of sample applications

Directory **hello_world/**:
* A very simple Trusted Application to answer a hello command and incrementing
an integer value.
* Test application: `optee_example_hello_world`
* Trusted application UUID: 8aaaf200-2450-11e4-abe2-0002a5d5c51b

Directory **random/**:
* Generates a random UUID using capabilities of TEE API (`TEE_GenerateRandom()`).
* Test application: `optee_example_random`
* Trusted application UUID: b6c53aba-9669-4668-a7f2-205629d00f86

Directory **aes/**:
* Runs an AES encryption and decryption from a TA using the GPD TEE Internal
Core API. Non secure test application provides the key, initial vector and
ciphered data.
* Test application: `optee_example_aes`
* Trusted application UUID: 5dbac793-f574-4871-8ad3-04331ec17f24
