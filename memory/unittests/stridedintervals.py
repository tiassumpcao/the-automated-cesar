import sys
import os
import time

import binnavi

from binnavi.memory.memoryregions import MemoryRegions
from binnavi.memory.memoryregions import LatticeElement as RegionElement
from binnavi.memory.stridedintervals import IntervalElement

from sets import Set
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph


# Build REIL instruction graph
reilCode = cg.view.reilCode
igraph = InstructionGraph.create(reilCode.graph)

# Generate the initial state vector.
Regions = MemoryRegions(igraph)

HEAP1 = Regions.heapAlloc()
HEAP2 = Regions.heapAlloc()

node = igraph.nodes[2]
cRegions = Regions.concretize(node)
for k in cRegions.iterkeys():
    print "Region set for: " + k
    print cRegions[k]
    print

e1 = Regions.getAbstractElement(node)
e2 = RegionElement()
e3 = RegionElement()

e2.alocEnv[HEAP1.name] = Set([HEAP1])
e3.alocEnv[HEAP2.name] = Set([HEAP2])

region = e1.combine(e2)
region = region.combine(e3)

print "Final element"
print region.alocEnv
print

s1 = IntervalElement(e2, 0, 4, 0, 32)
s2 = IntervalElement(e3, 0, 8, 0, 32)
s3 = s2.getTop(32)

print "-----\n"

print "Stride 1"
print s1
print s1.region.alocEnv
print s1.lbound
print s1.ubound
print s1.stride
print s1.bitwidth
print

print "Stride 2"
print s2
print s2.region.alocEnv
print s2.lbound
print s2.ubound
print s2.stride
print s2.bitwidth
print

print "Stride 3"
print s3
print s3.region.alocEnv
print s3.lbound
print s3.ubound
print s3.stride
print s3.bitwidth
print
stride = s1.add(s2)

print "-----\n"

print "Sum (Stride 1, Stride 2)"
print stride
print stride.region.alocEnv
print stride.lbound
print stride.ubound
print stride.stride
print stride.bitwidth
print

stride = s1.add(s3)

print "Sum (Stride 1, Stride 3)"
print stride
print stride.region.alocEnv
print stride.lbound
print stride.ubound
print stride.stride
print stride.bitwidth
print
