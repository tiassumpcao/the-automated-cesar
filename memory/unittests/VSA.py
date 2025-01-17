

__author__ = 'Tiago Assumpcao'
__license__ = '_'


import sys
import os
import time

from sets import Set
from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph
from com.google.security.zynamics.binnavi.API.reil.mono import DefaultStateVector


import binnavi

from binnavi.memory.stack import StackTracer
from binnavi.reil.dietreil import Transform

from binnavi.memory.memoryregions import MemoryRegions
from binnavi.memory.memoryregions import LatticeElement as RegionElement
from binnavi.memory.stridedintervals import IntervalElement
from binnavi.memory.abstractstore import LatticeElement as AbstractStore


# Build REIL instruction graph
reilCode = cg.view.reilCode
igraph = InstructionGraph.create(reilCode.graph)


ST = None
STResult = None

def ColorInstruction(address, color):
	for cnode in cg.view.graph:
		for inode in cnode.instructions:
			if inode.address == address:
				cnode.setInstructionColor(inode, 20000, color)

def init():
	global ST
	global STResult

	ST = StackTracer(igraph)
	STResult = ST.trace()

	startVector = DefaultStateVector()

	for node in igraph:
		state = STResult.getState(node)
		if state.dereference != 0:
			element = AbstractStore()
			region = ST.stack.getState(node)
			aval = IntervalElement(region, 0, state.dereference, 0, 32)
			element.writeAloc(region, state.dereference, 32, aval)

			startVector.setState(node, element)
	return startVector

def execute():
	lattice = init()
	for node in igraph:
		astore = lattice.getState(node)
		ex_address = node.instruction.address >> 8
		if astore != None:
			stack_state = STResult.getState(node)
			region = ST.stack.getState(node)
			stride = astore.readAloc(region, stack_state.dereference, 32)

			print node
			print "== ABSTRACT VALUE FOR LOCAL VARIABLE =="
			print stride
			print " - OFFSET :: " + str(stack_state.dereference)
			print " - REGION :: " + str(stride.region.alocEnv)
			print " - LBOUND :: " + str(stride.lbound)
			print " - UBOUND :: " + str(stride.ubound)
			print " - STRIDE :: " + str(stride.stride)
			print " - WIDTH  :: " + str(stride.bitwidth)
			print "\n\n"

execute()

