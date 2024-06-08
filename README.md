# SABRE Prototype Repository

## This repository is for SABRE: Security Analysis and Binary Repair Engine. This work is currently in submission and under peer review.

## Repository Structure

The repository is structured into three main directories: `ACFA`, `ISC-FLAT`, and `verifier`. `ACFA` and `ISC-FLAT` are for two open-source CFA architectures. `ACFA` is hardware-based and built aside MSP430 MCU, and `ISC-FLAT` is instrumentation-based and built to run on ARM Cortex-M33. We utilize these two open-source architectures for generating CFLogs that are used by SABRE for its analysis. All source codes within the `verifier` directory implement the functionality of our prototypes. 

### The `ACFA` and `ISC-FLAT` Directories

These directories contain the binaries for the selected BEEBs applications -- ported to MSP430/ARM Cortex-M33 from the [BEEBs repository](https://github.com/mageec/beebs) -- as a part of the evaluation in our paper. These applications were compiled (and instrumented for `ISC-FLAT`) in the ecosystem of the two open-source CFA architectures. As a result, the `ACFA` directory has binaries for the application compiled for MSP430, and the `ISC-FLAT` directory has the binaries for the application compiled for `ISC-FLAT`.

Of the available [BEEBs](https://github.com/mageec/beebs) applications we select to evaluate the following: `aha-compress`, `cover`, `crc_32`, `fibcall`, `jfdctint`, `lcdnum`, and `libbs`. As such, within `ACFA` and `ISC-FLAT` directories are subdirectories for each application. Within these directories are a `*.elf`, `*.lst` (or `*.list`) and `*.cflog` file. The `*.elf` has the compiled binary for the application, the `*.lst` (or `*.list`) file has the dissasembly of the application binary, and the `*.cflog` file is the CF-Log recorded by the CFA architecture while the application executed.

### The `verifier` Directory

The `verifier` directory contains the main source code for our prototype. Besides its main source code (implemented as `*.py` and `*.sh` files) are three subdirectories: `MSProbe`, `logs`, and `objs`. First, the MSProbe directory contains a modified version of the source code from the the [MSProbe repository](https://github.com/Swiftloke/MSProbe/tree/68883b82aa7a853c48463ef90fe5d1c64ceb0468). The `logs` directory is an empty directory that is populated as SABRE's scripts run. Similarly, `objs` file is populated with object files specific to a certain application as SABRE`s scripts run.

### Dependencies

### How to run
