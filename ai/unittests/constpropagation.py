import os
import time

import binnavi
import binnavi.ai.constpropagation as ConstPropagation

from binnavi.reil.dietreil import Transform

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

# Define the lattice used by the monotone framework.
lattice = ConstPropagation.Lattice()

# Generate the initial state vector.
startVector = ConstPropagation.generateStartVector(igraph)

# Define the transformations used by the monotone framework.
transformationProvider = ConstPropagation.TransformationProvider()

# Transfer function requires a forward analysis
walker = ConstPropagation.DownWalker()

# The solver
solver = ConstPropagation.MonotoneSolver(igraph, lattice, startVector, transformationProvider, walker)
results = solver.solve()

print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%% SOLVED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

REG = "eax"

# Process the results
from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers
for node in igraph:
	constants = results.getState(node).constants

	ex_address = node.instruction.address
	if (ex_address & 0xFF) != 0:
		continue
	address = ex_address >> 8
	instruction = ViewGraphHelpers.getInstruction(cg.view.graph, long(address))

	for k, v in constants.iteritems():
		if k != REG: continue

		print "[CP] %s\n%s <-- %s\n" % (instruction, k, constants[k])

