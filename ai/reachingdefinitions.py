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
		self.definitions = {}

	def equals(self, rhs):
		return self.definitions == rhs.definitions

	def lessThan(self, rhs):
		return self.definitions < rhs.definitions

class Lattice(ILattice):
	def combine(self, states):
		combined_state = LatticeElement()

		for state in states:
			for key in state.element.definitions:
				if key not in combined_state.definitions:
					combined_state.definitions[key] = Set()
				combined_state.definitions[key] |= state.element.definitions[key]

		return combined_state

class TransformationProvider(ITransformationProvider):
	def transform(self, node, currentState, influencingState):
		reilSemantics = RSemantics()
		imposedState = {}

		transformed_state = LatticeElement()
		transformed_state.definitions.update(influencingState.definitions)
		if reilSemantics.writes_register(node.instruction):
			imposedState = {node.instruction.thirdOperand.value: Set([node])}
		transformed_state.definitions.update(imposedState)

		return transformed_state

def generateStartVector(graph):
	reilSemantics = RSemantics()
	startVector = DefaultStateVector()

	for node in graph:
		element = LatticeElement()
		if reilSemantics.writes_register(node.instruction):
			element.definitions[node.instruction.thirdOperand.value] = Set([node])

		startVector.setState(node, element)

	return startVector

