# The Automated Cesar
The Automated Cesar is a rich set of static and dynamic binary analyses built for [Zynamics BinNavi](https://www.zynamics.com/binnavi.html).

## Features
- Classic control and dataflow analysis algorithms
- Abstract Interpretattion: Reaching definitions, value propagation, register and range tracking, and value set analysis.
- Abstract memory models: Load/store operations, dynamic memory regions and stack usage.
- Diet REIL: An optimization scheme for the [Reverse Engineering Intermediate Language](https://static.googleusercontent.com/media/www.zynamics.com/en//downloads/csw09-final.pdf), reducing in ~65% the IR for the most complex x86 instructions.
