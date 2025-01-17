

__author__ = 'Tiago Assumpcao'
__license__ = '_'


import sys
import os
import time

from sets import Set

import binnavi
from binnavi.reil.reilsemantics import RSemantics
from binnavi.reil.dietreil import Transform
from binnavi.misc.reductions import DataAccesses

from binnavi.ai import reachingdefinitions as ReachingDefinitions

from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph
from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers




def init():
	global reilCode
	global igraph

	# Build REIL instruction graph
	reilCode = cg.view.reilCode
	igraph = InstructionGraph.create(reilCode.graph)

	print "[+] Determining reaching definitions upon IR"
	# Define the lattice used by the monotone framework.
	lattice = ReachingDefinitions.Lattice()

	# Generate the initial state vector.
	startVector = ReachingDefinitions.generateStartVector(igraph)

	# Define the transformations used by the monotone framework.
	transformationProvider = ReachingDefinitions.TransformationProvider()

	# Transfer function requires a forward analysis
	walker = ReachingDefinitions.DownWalker()

	# The solver
	solver = ReachingDefinitions.MonotoneSolver(igraph, lattice, startVector, transformationProvider, walker)
	AIdomain = solver.solve()
	return AIdomain

def func_ptr_scan():
	AIdomain = init()
	DA = DataAccesses(AIdomain)
	RS = RSemantics()

	print "[+] Searching for function pointer calls in: " + str(cg.view)

	index = 0
	return_address = 0
	fptr_record = {}
	for node in igraph:
		# The signature is as follows
		# 
		# indirect_branch_operation = ({
		#	0: lambda x: dereferences_stack_pointer(x),
		#	1: lambda x: stores_stack_pointer(x),
		#	2: lambda x: pushes_to_stack(x),
		#	3: lambda x: branch_indirect(x)
		# })
		op = RS.indirect_branch_operation[index]
		print index, node.instruction, op(node.instruction)
		if not op(node.instruction):
			index = 0
			continue

		index += 1

		if index == 3:
			return_address = node.instruction.firstOperand
		if index == 4:
			print "[!] Match"
			print ""

			address = node.instruction.address
			register = node.instruction.thirdOperand

			reaching_definitions = AIdomain.getState(node).definitions
			memory_xrefs = DA.reduce_to_memory_access(reaching_definitions[register.value])

			fptr_record[node.instruction] = (return_address, register, memory_xrefs)
			index = 0

	print ""
	print "[+] Function pointer calls match the following instructions"

	for k,v in fptr_record.items():
		xrefs = []
		instruction = ViewGraphHelpers.getInstruction(cg.view.graph, k.address >> 8)

		return_address = v[0]
		base_register  = v[1]
		memory_xrefs   = v[2]

		for xref in memory_xrefs:
			address = xref.instruction.address >> 8
			insn_xref = ViewGraphHelpers.getInstruction(cg.view.graph, address)
			xrefs.append([insn_xref])

		print "=================="
		print instruction
		print "---"
		rc = instruction.getReilCode()
		print "Reil Code"
		print rc.nodes
		print "---"
		print "Return Address     :: %X" % (long(str(return_address)))
		print "Base Register      :: %s" % (base_register)
		print "Register Origin(s) :: %s" % (xrefs)

def execute():
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

	func_ptr_scan()

	print ""
	print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% E N D %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
	print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	print ""


execute()

