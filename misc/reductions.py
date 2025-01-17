

__author__ = 'Tiago Assumpcao'
__license__ = '_'


from binnavi.reil.reilsemantics import RSemantics
from sets import Set


class DataAccesses(RSemantics):
	def __init__(self, AIdomain):
		self.AIdomain = AIdomain

	def reduce_to_memory_access(self, reaching_definitions):
		result = Set()
		def reduce(reaching_definitions, result):
			for node in reaching_definitions:
				if self.memory_operation(node.instruction):
					result |= Set([node])
					return result

				lhs = node.instruction.firstOperand
				if not self.is_temporary_register(lhs):
					return result

				state = self.AIdomain.getState(node)
				bk_definitions = state.definitions[lhs.value]
				return reduce(bk_definitions, result)
		return reduce(reaching_definitions, result)

