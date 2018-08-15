# OP-TEE Sample Applications
## Contents
1. [Introduction](#1-introduction)
2. [List of sample applications](#2-list-of-sample-applications)
3. [How to build a Trusted Application](#3-how-to-build-a-trusted-application)


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

Directory **secure_storage/**:
* A Trusted Application to read/write raw data into the
OP-TEE secure storage using the GPD TEE Internal Core API.
* Test application: `optee_example_secure_storage`
* Trusted application UUID: f4e750bb-1437-4fbf-8785-8d3580c34994

Directory **acipher/**:
* Generates an RSA key pair of specified size and encrypts a supplied string
 with it using the GPD TEE Internal Core API.
* Test application: `optee_example_acipher`
* Trusted application UUID: a734eed9-d6a1-4244-aa50-7c99719e7b7b

## 3. How to build a Trusted Application
[TA basics] documentation presents the basics for  implementing and building
an OP-TEE trusted application.

One can also refer to the examples provided: source files and make scripts.

[TA basics]:	./docs/TA_basics.md
