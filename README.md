# EqGuide: Leveraging Synthesis Guidance for Equivalence Checking in Open-Source Flows

EqGuide is a specialized equivalence checking framework designed for open-source logic synthesis flows. It is implemented as a suite of front-end commands and analysis passes within [Yosys](https://github.com/YosysHQ/yosys), complemented by a lightweight extension to the [ABC](https://github.com/berkeley-abc/abc) import flow. By explicitly incorporating synthesis-derived metadata, EqGuide enables robust signal mapping and efficient problem decomposition for complex circuit verification.

## Quick Start Example

The following script demonstrates a typical RTL-to-netlist verification flow using EqGuide's `guide_check` command:

```tcl
# 1. Load the Golden Model (RTL/Reference)
read_verilog test.v
rename -recursive gold_ test

# 2. Load the Gate-Level Netlist (Implementation)
read_verilog test_netlist.v
rename -recursive gate_ test

# 3. Perform Guide-Driven Equivalence Checking
# -skip/k: BMC/Induction parameters
# -lib: Path to simulation primitives
guide_check -skip 10 -k 20 -lib sim.v \
	gold_test gold_ gate_test gate_
```

------

## Installation

### Prerequisites

EqGuide requires **Amulet2** for handling complex multiplier verification. Ensure it is installed and available in your `$PATH`.

- **Amulet2**: [d-kfmnn/amulet2](https://github.com/d-kfmnn/amulet2/)

  > *Note for Arch Linux users: You can find `amulet2-git` in the AUR.*

### Building EqGuide

Clone the repository and initialize all submodules (including the patched version of ABC):

Bash

```
# Clone the repository
git clone git@github.com:hkustgz-zhang-lab/eqguide.git
cd eqguide

# Initialize submodules (ensure your SSH keys are configured)
git submodule sync
git submodule update --init --recursive

# Configure and compile
make config-gcc
make -j$(nproc)
```
