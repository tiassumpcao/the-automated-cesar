

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


class LatticeElement(ILatticeElement):
	def __init__(self):
		self.constants = {}

	def equals(self, rhs):
		return self.constants == rhs.constants

	def lessThan(self, rhs):
		return self.constants < rhs.constants

class Lattice(ILattice):
	def combine(self, states):
		combined_state = LatticeElement()

		for state in states:
			for key in state.element.constants:
				if key not in combined_state.constants:
					combined_state.constants[key] = Set()
				combined_state.constants[key] |= state.element.constants[key]

		return combined_state

class TransformationProvider(ITransformationProvider):
	def transform(self, node, currentState, influencingState):
		reilSemantics = RSemantics()
		transformed_state = LatticeElement()
		imposedState = {}

		transformed_state.constants.update(influencingState.constants)
		if reilSemantics.writes_native_register(node.instruction):
			imposedState = {node.instruction.thirdOperand.value: Set([node.instruction.firstOperand.value])}
		transformed_state.constants.update(imposedState)

		return transformed_state

def generateStartVector(graph):
	reilSemantics = RSemantics()
	startVector = DefaultStateVector()

	for node in graph:
		element = LatticeElement()

		if reilSemantics.writes_native_register(node.instruction):
			element.constants[node.instruction.thirdOperand.value] = Set([node.instruction.firstOperand.value])

		startVector.setState(node, element)
		
	return startVector


