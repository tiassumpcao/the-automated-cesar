

from binnavi.reil.reilsemantics import RSemantics
from binnavi.ai import reachingdefinitions as ReachingDefinitions
from binnavi.memory.memoryregions import MemoryRegions
from binnavi.memory.memoryregions import LatticeElement as RegionElement

from sets import Set

from com.google.security.zynamics.binnavi.API.reil.mono import ILattice
from com.google.security.zynamics.binnavi.API.reil.mono import ILatticeElement
from com.google.security.zynamics.binnavi.API.reil.mono import MonotoneSolver
from com.google.security.zynamics.binnavi.API.reil.mono import ITransformationProvider
from com.google.security.zynamics.binnavi.API.reil.mono import DownWalker
from com.google.security.zynamics.binnavi.API.reil.mono import DefaultStateVector


class LatticeElement(ILatticeElement):
	def __init__(self):
		# Stack trace
		self.stack_trace = Set()
		# Current stack pointer
		self.stack_pointer = 0
		# Saved stack pointer
		self.saved_stack_pointer = 0
		# Size of stack shift
		self.dereference = 0
		# Saves stack pointer bit
		# - boolean checking instead of further semantic analysis
		self.saves_stack_pointer = False
		# Restores stack pointer bit
		# - boolean checking instead of further semantic analysis
		self.restores_stack_pointer = False

	def equals(self, rhs):
		return self.stack_trace == rhs.stack_trace

	def lessThan(self, rhs):
		return self.stack_trace < rhs.stack_trace

class Lattice(ILattice):
	def combine(self, states):
		combined_state = LatticeElement()

		for state in states:
			combined_state.stack_trace |= state.element.stack_trace

			# We assume stack frames are as small as possible; thence we
			# take the larger stack edge.
			if combined_state.stack_pointer < state.element.stack_pointer:
				combined_state.stack_pointer = state.element.stack_pointer
			if combined_state.saved_stack_pointer < state.element.saved_stack_pointer:
				combined_state.saved_stack_pointer = state.element.saved_stack_pointer

			combined_state.dereference = state.element.dereference
			combined_state.saves_stack_pointer = state.element.saves_stack_pointer
			combined_state.restores_stack_pointer = state.element.restores_stack_pointer

		return combined_state

class TransformationProvider(ITransformationProvider):
	def transform(self, node, currentState, influencingState):
		transformed_state = LatticeElement()

		transformed_state.stack_trace |= currentState.stack_trace
		transformed_state.stack_trace |= influencingState.stack_trace

		transformed_state.dereference = currentState.dereference
		transformed_state.saves_stack_pointer = currentState.saves_stack_pointer
		transformed_state.restores_stack_pointer = currentState.restores_stack_pointer

		if currentState.saves_stack_pointer == True:
			transformed_state.saved_stack_pointer = influencingState.stack_pointer
		else:
			transformed_state.saved_stack_pointer = influencingState.saved_stack_pointer

		if currentState.restores_stack_pointer == True:
			transformed_state.dereference = influencingState.saved_stack_pointer - influencingState.stack_pointer
		transformed_state.stack_pointer = influencingState.stack_pointer + influencingState.dereference

		return transformed_state

class StackTracer(RSemantics, MemoryRegions):
	"""This class implements a stack tracing scheme."""
	def __init__(self, graph):
		RSemantics.__init__(self)
		self.memory = MemoryRegions(graph)
		self.region = self.memory.stackAlloc()
		self.stack = DefaultStateVector()
		for node in graph:
			relement = RegionElement()
			relement.alocEnv[self.region.name] = Set([self.region])
			self.stack.setState(node, relement)

		self.graph = graph
		self.RDefinitions = None

	def getReachingDefinitions(self, node):
		return self.RDefinitions.getState(node).definitions

	def createStackPointerElement(self, p_node, operand):
		element = LatticeElement()

		def reduce(p_node, operand):
			definitions = self.getReachingDefinitions(p_node)

			try: I = definitions[operand]
			# We either are at the Data Dependence Graph's root or this is a bug.
			except: return element
			# We leave May-reaching expressions aside.
			if len(I) > 1: return element

			(aux_node,) = I
			operand = aux_node.instruction.firstOperand.value
			return self.createStackPointerElement(aux_node, operand)

		# Irreduceble conditions
		if self.aligns_stack_pointer(p_node.instruction):
			element.dereference = 0
			return element
		if self.shifts_stack_pointer(p_node.instruction):
			if "esp" in p_node.instruction.firstOperand.value:
				operand = p_node.instruction.secondOperand.value
			else: operand = p_node.instruction.firstOperand.value

			# Indirect shift - possibly a propagated constant.
			if not self.is_numeric(operand):
				operand = reduce(p_node, operand).dereference

			binop = self.arithmetic_operation[p_node.instruction.mnemonic]
			element.dereference = binop(0, - long(operand))
			return element
		if self.writes_constant_to_native_register(p_node.instruction):
			operand = p_node.instruction.firstOperand.value
			element.dereference = long(operand)
			element.dereference = element.dereference
			return element
		if self.saves_stack_pointer(p_node.instruction):
			element.dereference = element.dereference
			element.restores_stack_pointer = True
			return element

		operand = p_node.instruction.firstOperand.value
		return reduce(p_node, operand)

	def isCallSite(self, node):
		"""'node' is a stack poiter shift node."""
		# - Add[0..n-1] denotes a single native instruction -> REIL map.
		# Addr[0]: {stack_shift}\Addr[1]: stm {X}, , SP\(Addr[...]): [*]\Addr[n-1]: jcc 1, , {Y}\Addr[n]: [*]
		# - such that {X} = Addr[n]
		may_return_address = 0

		def reduce(r_node, may_return_address=may_return_address, is_branch=0):
			for x in r_node.outgoingEdges:
				y = x.target
				if (y.instruction.address >> 8) != (node.instruction.address >> 8):
					if (is_branch) and (y.instruction.address >> 8) == long(may_return_address):
						return True
					return False
				if self.memory_store(y.instruction):
					may_return_address = y.instruction.firstOperand.value
				if self.branch_operation(y.instruction):
					# Unconditional branch
					if y.instruction.firstOperand.value == "1":
						return reduce(y, may_return_address, True)
				return reduce(y, may_return_address)
		return reduce(node, may_return_address)

	def generateStartVector(self):
		startVector = DefaultStateVector()

		for node in self.graph:
			element = LatticeElement()

			if self.saves_stack_pointer(node.instruction):
				element.saves_stack_pointer = True
			if self.stores_stack_pointer(node.instruction) and \
			   not self.isCallSite(node):
				operand = node.instruction.firstOperand.value
				element = self.createStackPointerElement(node, operand)
				element.stack_trace.add(node)

			startVector.setState(node, element)

		return startVector

	def trace(self):
		# 1) Perform a reaching definition analysis to gather stack pointer
		#    influences.

		# Define the lattice used by the monotone framework.
		RDLattice = ReachingDefinitions.Lattice()

		# Generate the initial state vector.
		RDStartVector = ReachingDefinitions.generateStartVector(self.graph)

		# Define the transformations used by the monotone framework.
		RDTransformationProvider = ReachingDefinitions.TransformationProvider()

		# Transfer function requires a forward analysis
		RDWalker = ReachingDefinitions.DownWalker()

		# The solver
		RDSolver = ReachingDefinitions.MonotoneSolver(self.graph, RDLattice, RDStartVector, RDTransformationProvider, RDWalker)
		self.RDefinitions = RDSolver.solve()

		# 2) Iterate the graph gathering and applying the constraints
		#    to stack storing points.
		STLattice = Lattice()

		# Generate the initial state vector.
		STStartVector = self.generateStartVector()

		# Define the transformations used by the monotone framework.
		STTransformationProvider = TransformationProvider()

		# Transfer function requires a forward analysis
		STWalker = DownWalker()

		# The solver
		STSolver = MonotoneSolver(self.graph, STLattice, STStartVector, STTransformationProvider, STWalker)
		return STSolver.solve()



