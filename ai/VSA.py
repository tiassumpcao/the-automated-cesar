

__author__ = 'Tiago Assumpcao'
__license__ = '_'


from binnavi.reil.reilsemantics import RSemantics
from sets import Set

from com.google.security.zynamics.binnavi.API.reil.mono import ILattice
from com.google.security.zynamics.binnavi.API.reil.mono import ILatticeElement
from com.google.security.zynamics.binnavi.API.reil.mono import MonotoneSolver
from com.google.security.zynamics.binnavi.API.reil.mono import ITransformationProvider
from com.google.security.zynamics.binnavi.API.reil.mono import DownWalker
from com.google.security.zynamics.binnavi.API.reil.mono import DefaultStateVector
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph


class SkeletonLatticeElement(ILatticeElement):
	def __init__(self):
		self.written_registers = Set()

	def equals(self, rhs):
		return self.written_registers == rhs.written_registers
		
	def lessThan(self, rhs):
		return self.written_registers < rhs.written_registers

class SkeletonLattice(ILattice):
	def combine(self, states):
		combined_state = SkeletonLatticeElement()
		
		for state in states:
			combined_state.written_registers = combined_state.written_registers.union(state.element.written_registers)
		
		return combined_state

class SkeletonTransformationProvider(ITransformationProvider):
	def transform(self, node, currentState, influencingState):
	
		transformed_state = SkeletonLatticeElement()
		transformed_state.written_registers = transformed_state.written_registers.union(currentState.written_registers)
		transformed_state.written_registers = transformed_state.written_registers.union(influencingState.written_registers)
		
		return transformed_state

def generateStartVector(graph):
	reilSemantics = RSemantics()
	startVector = DefaultStateVector()

	for node in graph:
		element = SkeletonLatticeElement()

		if reilSemantics.writes_register(node.instruction):
			element.written_registers.add(node.instruction.thirdOperand.value)

		startVector.setState(node, element)

	return startVector


