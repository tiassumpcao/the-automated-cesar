

__author__ = 'Tiago Assumpcao'
__license__ = '_'

import sys

from binnavi.reil.reilsemantics import RSemantics
from sets import Set

from com.google.security.zynamics.binnavi.API.disassembly import Address
from com.google.security.zynamics.binnavi.API.reil import ReilInstruction
from com.google.security.zynamics.binnavi.API.reil import ReilOperand
from com.google.security.zynamics.binnavi.API.reil import OperandSize


class Verification(RSemantics):
	"""This is the verification class: it implements the logic for
	   verifying code error conditions as we like."""
	def __init__(self, reilgraph, cfa, dfa):
		RSemantics.__init__(self)

		self.cfa = cfa
		self.dfa = dfa
		self.reilgraph = reilgraph
		self.induction_variables = {}

		self.calculateInductionVariables()

	def decomposeIntoStackVariables(self, address, variable):
		"""Identify local variables and their influences."""
		influences = []
		def decompose(address, variable):
			e_in = (self.dfa.N[Address(address)].e_in & self.dfa.defs[variable])
			for next_address in e_in:
				if next_address in self.dfa.arithmetics:
					A = self.dfa.arithmetics[next_address]
					for influence in A.influences:
						if self.is_numeric(influence):
							continue
						if self.is_native_register(ReilOperand(OperandSize.OPERAND_SIZE_DWORD, influence)):
							# XXX: Recursion overflow being caused with certain variables (native regs)
							try: decompose(next_address, influence)
							except:
								continue
						if self.is_stack_variable(ReilOperand(OperandSize.OPERAND_SIZE_DWORD, influence)):
							influences.append(influence)
				else: # ordinary store
					reil_code = self.dfa.N[Address(next_address)].reil_code
					store_op = reil_code[len(reil_code) - 1]
					LHS = store_op.instruction.firstOperand
					if self.is_native_register(LHS):
						decompose(next_address, LHS.value)
					if self.is_stack_variable(LHS):
						influences.append(LHS.value)
			return influences
		return decompose(address, variable)

	def calculateInductionVariables(self):
		"""Identify loop induction variables."""
		# Lemma: a variable 'i' is induction in a loop L such that
		# the only definition of 'i' in L is in the form 'i = i o c',
		# and 'c' is loop-invariant.
		for loop in self.cfa.loops.itervalues():
			L = self.cfa.get_loop_addresses(loop)
			may_induction_variables = {}
			may_induction_influences = {}

			for arithmetic in self.dfa.arithmetics.itervalues():
				# list the operations in the loop domain such that the operation has the form 'i = i o c'
				if (arithmetic.address in L) and (arithmetic.variable in arithmetic.influences):
					if arithmetic.variable not in may_induction_variables:
						may_induction_variables[arithmetic.variable] = Set()
					may_induction_variables[arithmetic.variable] |= Set([arithmetic.address])

					if arithmetic.variable not in may_induction_influences:
						may_induction_influences[arithmetic.variable] = Set()
					may_induction_influences[arithmetic.variable] |= Set(arithmetic.influences)

			for i in may_induction_variables.iterkeys():
				# are all definitions of 'i' in L as 'i = i o c'?
				loop_defs_i = (self.dfa.defs[i] & L)
				if (may_induction_variables[i] & loop_defs_i) != may_induction_variables[i]:
					# not the Kth 'i', take next
					continue
				# is there one definiton of 'c' in L other than 'i' itself?
				for c in may_induction_influences[i]:
					if self.is_numeric(c):
						continue
					loops_defs_c = (self.dfa.defs[c] & L)
					if (loops_defs_c) and (loops_defs_c ^ may_induction_variables[i]):
						del may_induction_variables[i]
						break

			# update loop
			for i in may_induction_variables.iterkeys():
				if not i in self.induction_variables:
					self.induction_variables[i] = Set()
				self.induction_variables[i] |= may_induction_variables[i]


