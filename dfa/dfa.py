

__author__ = 'Tiago Assumpcao'
__license__ = '_'


from binnavi.reil.reilsemantics import RSemantics
from sets import Set


class DataflowAnalysis(RSemantics):
	"""This class implements the dataflow analyses."""
	def __init__(self):
		RSemantics.__init__(self)

		# Native (variables/registers) definitions
		# - dictionary indexed by the defined variable
		#   . set of literal addresses
		self.defs = {}
		# Native (variables/registers) uses
		# - dictionary indexed by the used variable
		#   . set of literal addresses
		self.uses = {}
		# Arithmetic objects
		# - dictionary indexed by address
		self.arithmetics = {}
		# Variable propagation scheme
		# - dictionary indexed by the propagated variable
		#   . the variable's reference
		self.propagated = None
		# Alias analysis not implemented
		self.pointers = None
		# Instruction graph meta-node
		# - dictionary indexed by an instruction node's address
		#   . meta information on a given node
		self.N = {}

	class Node:
		"""This class implements a node in the dataflow graph."""
		def __init__(self, node, gen, kill):
			self.head = node
			self.reil_code = [node]
			self.index = (node.instruction.address >> 8)
			self.gen = gen
			self.kill = kill
			self.e_in = Set()
			# out{} = gen{}
			self.e_out = gen

	class Arithmetic:
		"""This class represents inter-variable influences defined
		   by arithmetic operations."""
		def __init__(self, address, influences, variable):
			self.address = address
			self.influences = influences
			self.variable = variable

	def check_propagated(self, operand):
		"""Check if a given variable was propagated from a previous
		   node in the dataflow graph."""
		if operand.value in self.propagated:
			return self.propagated[operand.value]
		return operand

	def solveEquations(self, graph):
		"""Solve dataflow equations."""
		self.defineGenKillChains(graph)
		self.defineInOutChains(graph)

	def defineGenKillChains(self, graph):
		"""Create the gen-kill chains."""
		self.generateDUChains(graph)
		for node in graph:
			gen = Set()
			kill = Set()

			k = node.instruction.thirdOperand.value
			if k in self.defs:
				address = int(long(node.instruction.address >> 8))
				if address in self.defs[k]:
					gen |= Set([address])
					kill = self.defs[k] - gen

			# REIL data-flow propagation
			index = (node.instruction.address >> 8)
			if index in self.N:
				n = self.N[index]
				n.reil_code.append(node)
				n.gen |= gen
				n.kill |= kill
			else:
				n = self.Node(node, gen, kill)

			# update N
			self.N[n.index] = n

	def defineInOutChains(self, graph):
		"""Create the in-out chains."""
		# Chaotic iteration - MFP solution
		while (True):
			difference = Set()
			for node in graph:
				index = (node.instruction.address >> 8)
				# in{}  = for each p in pred(n): UNION out[p]
				# out{} = gen[n] + (in[n] - kill[n])
				e_in = Set()
				e_out = Set()

				for p in self.N[index].head.parents:
					p_index = (p.instruction.address >> 8)
					e_in |= self.N[p_index].e_out

				e_out = self.N[index].gen | (e_in - self.N[index].kill)
				difference |= e_out ^ self.N[index].e_out

				# update N
				self.N[index].e_in = e_in
				self.N[index].e_out = e_out

			if len(difference) == 0:
				break

	# This function generates the definition sets for native registers
	def generateDUChains(self, graph):
		"""The Def-Use chain herein created also abstracts (REIL) intra-instruction
		   operational semantics of relevance to our analysis --- e.g. arithmetics.
		   The reasons are three:
		   1) this is a strategic place, since we can answer the questions without
		      extra work --- an intra-instruction backwards analysis is viable from
		      the final 'store', so it can be propagated throughout the (non-optimized)
		      instruction graph; 
		   2) to keep the worklist as small as possible;
		   3) to make the verification simpler."""
		local_defs = None
		influences = None

		def decomposeArithmeticExpression(instruction):
			"""Decomposes arithmetic expressions such that non-explicit
			   uses and defs can be determined for the dataflow graph."""
			if instruction.mnemonic in self.arithmetic_operation:
				if instruction.firstOperand.value in local_defs:
					x = local_defs[instruction.firstOperand.value]
					decomposeArithmeticExpression(x.instruction)
				else:
					influences.append(instruction.firstOperand.value)
				if instruction.secondOperand.value in local_defs:
					x = local_defs[instruction.secondOperand.value]
					decomposeArithmeticExpression(x.instruction)
				else:
					influences.append(instruction.secondOperand.value)
			return influences

		# Walk the graph
		for node in graph:
			# Reset the local defs and influence list per native instruction
			if (node.instruction.address & 0xFF) == 0x00:
				local_defs = {}
				influences = []

			address = int(long(node.instruction.address >> 8))
			if self.writes_temporary_register(node.instruction):
				k = node.instruction.thirdOperand.value
				# we are here concerned with instruction nodes, not addresses
				local_defs[k] = node

			if self.reads_native_variable(node.instruction):
				if len(node.instruction.firstOperand.value) > 0:
					k = node.instruction.firstOperand.value
					if k not in self.uses:
						self.uses[k] = Set()
					self.uses[k] |= Set([address])
				if len(node.instruction.secondOperand.value) > 0:
					k = node.instruction.secondOperand.value
					if k not in self.uses:
						self.uses[k] = Set()
					self.uses[k] |= Set([address])

			if self.writes_native_variable(node.instruction):
				k1 = node.instruction.firstOperand.value
				k2 = node.instruction.thirdOperand.value

				# store from a previously defined temporary
				if (self.immediate_store(node.instruction)) and (k1 in local_defs):
					# Track arithmetics so we can reason about induction variables etc.
					# Result store can likely be tracked down from the first,
					# temporary, operand --- into the third, native, operand;
					#     'str t2, , eax'
					x = local_defs[k1]
					if x.instruction.mnemonic in self.arithmetic_operation:
						influences = decomposeArithmeticExpression(x.instruction)
						self.arithmetics[address] = self.Arithmetic(address, influences, k2)

				# ordinary definition of native variable

				# -----> XXX: FIX FLAGS PROPAGATION
				# Find a proper solution to treat REIL's status registers.
				# They must be treated accordingly such that we can know, for instance,
				# a reaching definition for 'CF', thus, allowing us to verify where
				# a certain branch condition was taken as well as which instruction
				# is resomposible for a given comparison result.
				#
				# We only need to separate how Uses and Defs are kept for
				# these registers such that, e.g., the Def of 'OF' doesn't kill a Def
				# of 'EAX'at the same related native address.
				if k2.isupper():
					continue
				# <------
				if k2 not in self.defs:
					self.defs[k2] = Set()
				self.defs[k2] |= Set([address])


