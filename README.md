# EqGuide: EqGuide: Guiding  Equivalence Checking in Open-Source Logic Synthesis Flow

EqGuide is implemented as a set of new front-end commands and analysis passes in [Yosys](https://github.com/YosysHQ/yosys), together with a lightweight extension to the [ABC](https://github.com/berkeley-abc/abc) import flow to apply an explicit name mapping for circuit interfaces.

## Simplest Usage Example 

```tcl
# Read GOLD (RTL/reference)
read_verilog test.v
rename -recursive gold_ test

# Read GATE (netlist/implementation)
read_verilog test_netlist.v
rename -recursive gate_ test

# Guide-driven checking
guide_check -skip 10 -k 20 -lib sim.v \
  gold_test gold_ gate_test gate_
```

