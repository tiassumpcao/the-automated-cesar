import sys
import os
import time

import binnavi

from binnavi.reil.dietreil import Transform
from binnavi.dfa.dfa import DataflowAnalysis

from java.awt import Color as Color
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph


######################
ADDRESS = "689B60D7" #
VAR = "eax"          #
######################


def ClearInstructionColors():
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			cnode.setInstructionColor(inode, 20000, Null)

def ColorInstruction(address, color):
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			if inode.address == address:
				cnode.setInstructionColor(inode, 20000, color)


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

# Execute analysis
dfa = DataflowAnalysis()
dfa.solveEquations(tgraph)

# Clear coloring of instructions
#ClearInstructionColors()
ADDRESS += "00"

for node in tgraph:
	if str(node.instruction.address).find(ADDRESS.lower()) != -1:
		meta_node = dfa.N[node.instruction.address >> 8]

		for k in dfa.defs[VAR]:
			ColorInstruction(k, Color.YELLOW)

		kill = meta_node.kill & dfa.defs[VAR]
		for k in kill:
			ColorInstruction(k, Color.RED)

		e_out = meta_node.e_out & dfa.defs[VAR]
		for k in e_out:
			ColorInstruction(k, Color.BLUE)

		e_in = meta_node.e_in & dfa.defs[VAR]
		for k in e_in:
			ColorInstruction(k, Color.GREEN)

		ColorInstruction(meta_node.index, Color.CYAN)

print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% E N D %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

