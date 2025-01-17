import os
import time

import binnavi
import binnavi.ai.regtracking as RegTracking

from binnavi.reil.dietreil import Transform

from sets import Set
from java.awt import Color as Color
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

# Optimize REIL instruction graph
T = Transform(igraph)
tfunction = T.transform()
tgraph = InstructionGraph.create(tfunction)

# Define the lattice used by the monotone framework.
lattice = RegTracking.SkeletonLattice()
		
# Generate the initial state vector.
startVector = RegTracking.generateStartVector(tgraph)

# Define the transformations used by the monotone framework.
transformationProvider = RegTracking.SkeletonTransformationProvider()

# Transfer function requires a forward analysis
walker = RegTracking.DownWalker()

# The solver
solver = RegTracking.MonotoneSolver(tgraph, lattice, startVector, transformationProvider, walker)
results = solver.solve()

# Process the results
used_register_set = Set()
		
for node in tgraph:
	used_register_set = used_register_set.union(results.getState(node).written_registers)
		
register_list = list(used_register_set)
register_list.sort()
joinedString = ", ".join(register_list)
			
print "This function modifies the registers %s.\n" % (joinedString)


print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% E N D %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

