# SABRE Prototype Repository

## This repository is for SABRE: Security Analysis and Binary Repair Engine. This work is currently in submission and under peer review.

## Repository Structure

SABRE current prototype is split into three branches for its separate features (to be merged together soon):
- [`ovf`](https://github.com/AnonymousAuthors706/SABRE/tree/ovf) branch for buffer overflow detection in MSP430 and ARM Cortex-M33;
- [`uaf-msp`](https://github.com/AnonymousAuthors706/SABRE/tree/uaf-msp) branch for use-after-free detection in MSP430;
- [`uaf-arm`](https://github.com/AnonymousAuthors706/SABRE/tree/uaf-arm) branch for use-after-free detection in ARM Cortex-M33.

Within each branch, the repository is structured into three main directories: `ACFA`, `TRACES`, and `verifier`. `ACFA` and `TRACES` are for two open-source CFA architectures. `ACFA` is hardware-based and built aside MSP430 MCU, and `TRACES` is instrumentation-based and built to run on ARM Cortex-M33. We utilize the open-source versions of [ACFA](https://github.com/RIT-CHAOS-SEC/ACFA) and [TRACES](https://github.com/RIT-CHAOS-SEC/TRACES) architectures for generating CFLogs that are used by SABRE for its analysis. All source codes within the `verifier` directory implement the functionality of our prototypes. 


### The `ACFA` and `TRACES` Directories

These directories contain the binaries for the selected [BEEBs](https://github.com/mageec/beebs) applications -- which we ported to MSP430/ARM Cortex-M33 -- as a part of the evaluation in our paper. These applications were compiled (and instrumented for `TRACES`) in the ecosystem of the two open-source CFA architectures. As a result, the `ACFA` directory has binaries for the application compiled for MSP430, and the `TRACES` directory has the binaries for the application compiled for `TRACES`.

Of the available [BEEBs](https://github.com/mageec/beebs) applications we select to evaluate the following: `aha-compress`, `cover`, `crc_32`, `fibcall`, `jfdctint`, `lcdnum`, and `libbs`. As such, within `ACFA` and `TRACES` directories are subdirectories for each application. Within these directories are a `*.elf`, `*.lst` (or `*.list`) and `*.cflog` file. The `*.elf` has the compiled binary for the application, the `*.lst` (or `*.list`) file has the disassembly of the application binary, and the `*.cflog` file is the CF-Log recorded by the CFA architecture while the application executed.

### The `verifier` Directory

The `verifier` directory contains the main source code for our prototype. Besides its main source code (implemented as `*.py` and `*.sh` files) are three subdirectories: `MSProbe`, `logs`, and `objs`. First, the MSProbe directory contains a modified version of the source code from the [MSProbe repository](https://github.com/Swiftloke/MSProbe/tree/68883b82aa7a853c48463ef90fe5d1c64ceb0468). The `logs` directory is an empty directory that is populated as SABRE's scripts run. Similarly, `objs` file is populated with object files specific to a certain application as SABRE`s scripts run.

### How to run

These instructions are for running on Ubuntu.

1) Clone this repository; Then, run `setup.sh` to check which dependencies are installed/missing. Install missing dependencies, then switch to the branch for the feature you want to test (see above).

2) `cd` into the `verifier` directory. Then, run `./run.sh <ARCH> <APP>` replacing `<ARCH>` with the selected architecture to run (either `msp430` or `arm`) and replacing `<APP>` with the selected BEEBs application to evaluate (`aha-compress`, `cover`, `crc_32`, `fibcall`, `jfdctint`, `lcdnum`, or `libbs`). If you are on `uaf-arm` branch, use `arm` for `<ARCH>`. If you are on `uaf-msp` branch, use `msp430` for `ARCH`. If you are on `ovf` branch, use either `msp430` or `arm` for `ARCH`.

3) While running the scripts, SABRE will first verify the CF-Log is valid, and in doing so will determine that it is invalid. Then perform backwards tracing and symbolic data-flow analysis (as described in our paper) to identify the memory corruption that caused the eventual control flow violation. Then, it will attempt to patch the vulnerability and verify that patch. The terminal window should show `[!] NO ATTACK DETECTED [!] Concluded at <INSTR>`

4) Once the patch is verified, a patched version of the binary (and its associated `*.lst` file) will be added to the subdirectory of the test. When the `msp430` was selected for `<ARCH>`, the patched binary will appear in the `ACFA` directory under the subdirectory of the BEEBs application. Similarly, when `arm` is selected for `<ARCH>`, the patched binary will appear in the subdirectory. In both cases, `patch.elf` and `patch.list` should appear in the `TRACES` subdirectories.
