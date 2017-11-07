# OP-TEE Sample Applications
## Contents
1. [Introduction](#1-introduction)
2. [List of sample applications](#2-list-of-sample-applications)
3. [How to build a Trusted Application](#3-how-to-build-a-trusted-application)


## 1. Introduction
This document describes the sample applications that are included in the OP-TEE,
that aim to showcase specific functionality and use case.

---
## 2. List of sample applications
* **hello_world**: use Trusted Application for incrementing an integer value
* **random**: generate random UUID using capabilities of TEE API
(`TEE_GenerateRandom()`)

---
## 3. How to build a Trusted Application
[TA basics] documentation presents the basics for  implementing and building
an OP-TEE trusted application.

One can also refer to the examples provided: source files and make scripts.

[TA basics]:	./docs/TA_basics.md
