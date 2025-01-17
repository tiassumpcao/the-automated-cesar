

__author__ = 'Tiago Assumpcao'
__license__ = '_'

from sets import Set

from com.google.security.zynamics.binnavi.API.disassembly import Address
from com.google.security.zynamics.binnavi.API.reil import ReilGraph
from com.google.security.zynamics.binnavi.API.reil import ReilBlock
from com.google.security.zynamics.binnavi.API.reil import ReilEdge
from com.google.security.zynamics.binnavi.API.reil import ReilInstruction
from com.google.security.zynamics.binnavi.API.reil import ReilMnemonics
from com.google.security.zynamics.binnavi.API.reil import ReilOperand
from com.google.security.zynamics.binnavi.API.reil import OperandSize
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph

from reilsemantics import RSemantics




class Transform(RSemantics):
	"""This class implements REIL code-size optimization."""
	def __init__(self, graph):
		RSemantics.__init__(self)

		self.blocks = []
		self.edges = []

		self.propagated = None
		self.explicited = None

		self.graph = graph
		# The transformed graph
		self.Tgraph = None
		# Taux holds order-preserving relations between 'graph'
		# and its relocated version, 'blocks'.
		self.Taux = {}
		print "[!] Instruction graph length :: %u nodes | %u edges" % (graph.nodeCount(), graph.edgeCount())

	def check_propagated(self, operand):
		"""Checks if a given variable has been propagated through the flow graph."""
		if self.propagated.has_key(operand.value): return self.propagated[operand.value]
		return operand

	def undefine(self, operand):
		"""Undefines a variable reference in the propagation graph."""
		if self.propagated.has_key(operand.value):
			del self.propagated[operand.value]

	def explicited(self, operand):
		"""Checks if a given function was explicitly defined by previous instructions
		   in the flow graph."""
		return self.explicited.has_key(operand.value)

	def create_edges(self):
		"""Creates control-flow edges for the optimized instruction graph."""
		for node in self.blocks:
			aux_node = self.Taux[node.address][0]

			# temporary index
			index = self.blocks.index(node)

			# Branches of whatsoever nature, will lead to a an
			# entry instruction block, therefore having a '00'
			# address, which, regardless of relocation, does
			# exist for any existing instruction.
			# Thus, a node not collected in 'blocks' can only be
			# a relocated block, therefore being the subsequent
			# node to the current.
			#
			# Depending on how REIL decomposition works towards
			# such instructions, it may break with direct branches
			# on RISC based computers using fixed-length encoding
			# that aren't large enough to sustain the operation --
			# resulting in indirect calls via branching-registers.
			# Example, synthetic MIPS instructions like:
			# 'jal symbol' translated by the code generator into:
			# I)  'lw t9,$offset(gp)   ;  jr t9'
			# II) 'lui t9,high($symbol);  ori t9,low($symbol)  ;  jr t9'
			#
			# Such a specification is undefined in binnavi's docs.
			if len(aux_node.outgoingEdges) == 0:
				continue
			if (len(aux_node.outgoingEdges) == 1):
				if "jcc" in aux_node.instruction.mnemonic:
					taddr = aux_node.children[0].instruction.address
					# try/except used due to a bug in current REIL graph implementation
					try: aux_index = self.Taux[taddr][1]
					except: pass
					target = self.blocks[aux_index]
				if index < (len(self.blocks) - 1):
					target = self.blocks[index + 1]

				etype = aux_node.outgoingEdges[0].type
				edge = ReilEdge(node, target, etype)
				self.edges.append(edge)
			if len(aux_node.outgoingEdges) == 2:
				for outgoing in aux_node.outgoingEdges:
					taddr = outgoing.target.instruction.address
					etype = outgoing.type
					if str((taddr >> 8) & 0xFFFFFFFF).upper() == node.instructions[0].thirdOperand.value:
						aux_index = self.Taux[taddr][1]
						target = self.blocks[aux_index]
						edge = ReilEdge(node, target, etype)
						self.edges.append(edge)
					else:
						if index < (len(self.blocks) - 1):
							target = self.blocks[index + 1]
							edge = ReilEdge(node, target, etype)
							self.edges.append(edge)

	def create_node(self, node, address, mnemonic, firstOperand, secondOperand, thirdOperand):
		"""Creates a node in the optimized instruction graph."""
		self.explicited[thirdOperand.value] = address

		if (self.is_temporary_register(firstOperand) and not firstOperand.value in self.explicited) \
			and self.is_numeric(secondOperand.value):
			instruction = ReilInstruction(address, mnemonic, ReilOperand.EMPTY_OPERAND, secondOperand, thirdOperand)
		elif (self.is_temporary_register(secondOperand) and not secondOperand.value in self.explicited) \
			and self.is_numeric(firstOperand.value):
			instruction = ReilInstruction(address, mnemonic, firstOperand, ReilOperand.EMPTY_OPERAND, thirdOperand)
		else:
			instruction = ReilInstruction(address, mnemonic, firstOperand, secondOperand, thirdOperand)

		block = ReilBlock([instruction])
		self.blocks.append(block)
		self.Taux[address] = [node, len(self.blocks) - 1]

	def transform(self):
		"""Performs code transformation."""

		print "[!] Optimizing REIL code...."
		# Graph slide / node grained transformation
		for node in self.graph:
			instruction = None

			# truncate: propagated registers and explicited instructions
			if (node.instruction.address & 0xFF) == 0x00:
				self.propagated = {}
				self.explicited = {}
				address = (node.instruction.address)

			firstOperand = self.check_propagated(node.instruction.firstOperand)
			secondOperand = self.check_propagated(node.instruction.secondOperand)
			thirdOperand = self.check_propagated(node.instruction.thirdOperand)

			################################################################################################################
			# Transformation rules
			############################
			# Goals:
			# I.	utterly reduce the number of instructions with the minimum semantic impact
			# II.	reduce the number of references to temporary registers
			# III.	resolve non-explicit copy and constant and pointer propagations
			#
			# How:	the abstraction is defined based on algebraic quasi-identities (compositions that are of small
			#       relevance in the analysis to be performed).
			############################
			# Immediate change (STR)
			#	1- register / / temporary register => [ no-operation, propagate ]
			#	2- literal  / / temporary register => [ no-operation, propagate ]
			#	3- register / / native register => [ operation ]
			#	4- literal  / / native register => [ operation ]
			if self.immediate_store(node.instruction):
				# 3, 4
				if self.is_native_variable(thirdOperand):
					self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
					address = address + 1
				else: # 1, 2
					self.propagated[thirdOperand.value] = firstOperand
				continue

			# Indirect change (STM/LDM)
			#	1- / / / => [ operation, undefine ]
			if self.indirect_change(node.instruction):
				# We strip stack based loads/stores and make them direct access to
				# the propagated references
				if self.is_stack_reference(firstOperand):
					# load
					stack_variable = self.reference_to_variable(firstOperand)
					self.propagated[thirdOperand.value] = stack_variable
					continue
				elif self.is_stack_reference(thirdOperand):
					# store
					stack_variable = self.reference_to_variable(thirdOperand)
					self.create_node(node, address, "str", firstOperand, ReilOperand.EMPTY_OPERAND, stack_variable)
				else:
					# 1 ordinary load/store
					if self.is_numeric(firstOperand.value):
						operand = Address(long(firstOperand.value))
						firstOperand = ReilOperand(node.instruction.firstOperand.size, str(operand).upper())
					if self.is_numeric(thirdOperand.value):
						operand = Address(long(thirdOperand.value))
						thirdOperand = ReilOperand(node.instruction.thirdOperand.size, str(operand).upper())
					self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
					self.undefine(thirdOperand)
				address = address + 1
				continue

			# Undefine (UNDEF)
			#	XXX: such a transformation can lead to dubious assemblage, since register
			#            allocation doesn't get explicit via an operation nor is it propagated
			#
			#	1- / / register => [ no-operation, undefine ]
			if self.undefine_operation(node.instruction):
				# 1
				self.undefine(thirdOperand)
				continue

			# Arithmetic (ADD/SUB/MUL/DIV/MOD)
			#	* "MOD" is grouped here for simplicity sake.
			#	* sign inversion (SUB 0, reg, reg) is treated as substraction identity -- tests prove it effective.
			#
			#	1- identity => [ no-operation, propagate ]
			#	2- literal              / literal           / register => [ no-operation, compute, propagate ]
			#	3- temporary (implicit) / explicited|native / register => [ no-operation, propagate ]
			#	4- literal              / register          / register => [ operation, undefine ]
			#	5- register             / register          / register => [ operation, undefine ]
			if self.arithmetic_operation.has_key(node.instruction.mnemonic):
				# Basic alias analysis to keep track and properly propagate pointer accesses
				stack_reference = self.stack_pointer_reference(node.instruction)
				if stack_reference != None:
					self.propagated[thirdOperand.value] = stack_reference
					self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, stack_reference)
					address = address + 1
					continue
				# 1
				operand = self.is_identity(node.instruction)
				if operand != None:
					self.propagated[thirdOperand.value] = self.check_propagated(operand)
					continue
				# 2
				if self.is_numeric(firstOperand.value) and self.is_numeric(secondOperand.value):
					binop = self.arithmetic_operation[node.instruction.mnemonic]
					value = binop(long(firstOperand.value), long(secondOperand.value))
					self.propagated[thirdOperand.value] = ReilOperand(OperandSize.OPERAND_SIZE_DWORD, str(value))
					continue
				# 3
				if (self.explicited.has_key(firstOperand.value) or self.is_native_variable(firstOperand)) and \
				   (self.is_temporary_register(secondOperand) and not self.explicited.has_key(secondOperand.value)):
					self.propagated[thirdOperand.value] = firstOperand
					continue
				if (self.explicited.has_key(secondOperand.value) or self.is_native_variable(secondOperand)) and \
				   (self.is_temporary_register(firstOperand) and not self.explicited.has_key(firstOperand.value)):
					self.propagated[thirdOperand.value] = secondOperand
					continue
				# 4, 5
				self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
				self.undefine(thirdOperand)
				address = address + 1
				continue

			# Bitwise operations (AND/OR/XOR/BSH/BISZ)
			#	1- literal              / literal                      / temporary => [ no-operation, compute, propagate ]
			#	2- native|explicited    / literal|temporary (implicit) / temporary => [ no-operation, propagate ]
			#	3- temporary (implicit) / explicited|native            / temporary => [ no-operation, propagate ]
			#	4- explicited           /                              / temporary => [ no-operation, propagate ] ; bitset
			#	5- native               /                              / temporary => [ operation ]               ; bitset
			#	6- native|explicited    / native                       / temporary => [ operation ]               ; comparison
			#	7- literal              / explicited|native            / temporary => [ operation ]               ; comparison
			#	8-    *                 /       *                      / native => [ operation ]                  ; store
			if self.bitwise_operation.has_key(node.instruction.mnemonic):
				# 1
				if self.is_numeric(firstOperand.value) and self.is_numeric(secondOperand.value):
					binop = self.bitwise_operation[node.instruction.mnemonic]
					value = binop(long(firstOperand.value), long(secondOperand.value))
					self.propagated[thirdOperand.value] = ReilOperand(OperandSize.OPERAND_SIZE_DWORD, str(value))
					continue

				if not self.is_native_variable(thirdOperand):
					# 2
					if (self.explicited.has_key(firstOperand.value) or self.is_native_variable(firstOperand)) and \
					   (self.is_numeric(secondOperand.value) or (self.is_temporary_register(secondOperand) and \
										     not self.explicited.has_key(secondOperand.value))):
						self.propagated[thirdOperand.value] = firstOperand
						continue
					# 3
					if (self.explicited.has_key(secondOperand.value) or self.is_native_variable(secondOperand)) and \
					   (self.is_temporary_register(firstOperand) and not self.explicited.has_key(firstOperand.value)):
						self.propagated[thirdOperand.value] = secondOperand
						continue
					# 4
					if (self.explicited.has_key(firstOperand.value) and len(secondOperand.value) == 0):
						self.propagated[thirdOperand.value] = firstOperand
						continue
					# 5
					if self.is_native_variable(firstOperand) and len(secondOperand.value) == 0:
						self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
						address = address + 1
						continue

					# 6 -- for 'native', it works on the actual operands
					if (self.is_native_variable(node.instruction.firstOperand) or self.explicited.has_key(firstOperand.value)) and \
					   self.is_native_variable(node.instruction.secondOperand):
						self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
						address = address + 1
						continue

					# 7 -- it works on the actual firstOperand, not upon the propagated reference
					if (self.explicited.has_key(secondOperand.value) or self.is_native_variable(secondOperand)) and \
					   self.is_numeric(node.instruction.firstOperand.value):
						self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
						address = address + 1
						continue
				else:
					# 8
					# Turn align-store into store
					if node.instruction.mnemonic in ("and", "or"):
						if self.is_numeric(firstOperand.value):
							sourceOperand = secondOperand
						else:
							sourceOperand = firstOperand
						self.create_node(node, address, "str", sourceOperand, ReilOperand.EMPTY_OPERAND, thirdOperand)
					else:
						self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
					address = address + 1
					continue

			# Branches (JCC)
			#	=> [ operation ]
			if self.branch_operation(node.instruction):
				if self.is_numeric(thirdOperand.value):
					operand = Address(long(thirdOperand.value))
					thirdOperand = ReilOperand(node.instruction.thirdOperand.size, str(operand).upper())
				self.create_node(node, address, node.instruction.mnemonic, firstOperand, secondOperand, thirdOperand)
				self.undefine(thirdOperand)
				address = address + 1
			################################################################################################################

		# Create links
		self.create_edges()
		self.Tgraph = ReilGraph(self.blocks, self.edges)
		print "[!] Instruction graph length :: %u nodes | %u edges" % (self.Tgraph.nodeCount(), self.Tgraph.edgeCount())
		nodes_cardinality = (100 - ((self.Tgraph.nodeCount() * 100) / self.graph.nodeCount()))
		edges_cardinality = (100 - ((self.Tgraph.edgeCount() * 100) / self.graph.edgeCount()))
		m = (nodes_cardinality + edges_cardinality) / 2
		print "[!] Graph reduced in ~%u percent." % (m)
		print ""
		print ""
		return self.Tgraph

	def output(self, graph):
		for node in graph:
			for i in node.instructions:
				count = 0
				print "================================="
				print i
				print "---------------------------------"
				base = i.address & 0xFFFFFFFF
				address = (base << 8) | count

				while address in self.Taux:
					index = self.Taux[address][1]
					print self.blocks[index].instructions[0]
					count = count + 1
					address = (base << 8) | count


