import sys
import os
import time

import binnavi

from binnavi.memory.stack import StackTracer
from binnavi.reil.dietreil import Transform

from sets import Set
from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph

from java.awt import Color as Color

NAVIDEBUG = 0 


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


def ColorInstruction(address, color):
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			if inode.address == address:
				cnode.setInstructionColor(inode, 20000, color)


# Build REIL instruction graph
reilCode = cg.view.reilCode
igraph = InstructionGraph.create(reilCode.graph)

ST = StackTracer(igraph)
STResult = ST.trace()

stack_pointer = {}
saved_stack_pointer = {}
dereference = {}
for node in igraph:
	state = STResult.getState(node)
	ex_address = node.instruction.address >> 8

	if ex_address not in stack_pointer:
		stack_pointer[ex_address] = int(state.stack_pointer)
		saved_stack_pointer[ex_address] = int(state.saved_stack_pointer)
		dereference[ex_address] = 0

	dereference[ex_address] += int(state.dereference)

	if NAVIDEBUG:
		print node
		print "   stack pointer ........ ", state.stack_pointer
		print "   saved stack pointer .. ", state.saved_stack_pointer
		print "   dereference .......... ", state.dereference

for cnode in cg.view.graph:
	for inode in cnode.instructions:
		trace = "[%03X] (%03X) | DEREF(%X)" % (long(stack_pointer[inode.address]),
											   long(saved_stack_pointer[inode.address]),
											   long(dereference[inode.address]))
		inode.appendComment(trace)

		if dereference[inode.address] < 0:
			ColorInstruction(inode.address, Color.RED)
		if dereference[inode.address] > 0:
			ColorInstruction(inode.address, Color.BLUE)



print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%% SOLVED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""


