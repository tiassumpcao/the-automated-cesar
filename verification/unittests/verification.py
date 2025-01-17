import sys
import os
import time

import binnavi

from binnavi.reil.dietreil import Transform
from binnavi.dfa.dfa import DataflowAnalysis
from binnavi.cfx.cfx import ControlFlowEx
from binnavi.verification.verification import Verification

from java.awt import Color as Color
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph


#######################################
DATABASE = dbs.databases[0]           #
TAG_MANAGER = DATABASE.nodeTagManager #
ADDRESS = 0x689B60E6                  #
VAR = "eax"                           #
#######################################


def ClearInstructionColors():
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			cnode.setInstructionColor(inode, 20000, Color.WHITE)

def ColorInstruction(address, color):
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			if inode.address == address:
				cnode.setInstructionColor(inode, 20000, color)

def ColorInductionVariableUses(induction_variables):
	# FIXME: we should actually color any instruction that uses an induction variable
	for A in induction_variables.itervalues():
		for address in A:
			ColorInstruction(address, Color.BLUE)



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


# Build the extended control flow graph
cfx = ControlFlowEx(cg.view, TAG_MANAGER)

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

# Execute verification
verification = Verification(tgraph, cfx, dfa)

print ""
print ""

# XXX: Shall be replaced by the a-locs version
#print verification.decomposeIntoStackVariables(long(ADDRESS), VAR)

ColorInductionVariableUses(verification.induction_variables)

print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% E N D %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

