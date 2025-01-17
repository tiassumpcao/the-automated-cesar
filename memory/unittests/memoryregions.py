import sys
import os
import time

import binnavi

from binnavi.memory.memoryregions import MemoryRegions
from binnavi.memory.memoryregions import LatticeElement as RegionElement

from sets import Set
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph



print ""
print ""
print ""
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%% S T A R T %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""


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

print "Element 1"
print e1.alocEnv
print

print "Element 2"
print e2.alocEnv
print

print "Final element"
print region.alocEnv
print


