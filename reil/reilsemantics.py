

__author__ = 'Tiago Assumpcao'
__license__ = '_'


from com.google.security.zynamics.binnavi.API.reil import ReilOperand
from com.google.security.zynamics.binnavi.API.reil import OperandSize
from com.google.security.zynamics.binnavi.API.reil import OperandType


class RSemantics:
	""""This class abstracts REIL semantics."""
	def __init__(self):
	#############################################################################################
	# Operation categories
		self.arithmetic_operation = dict({
			"add": lambda x,y: x+y,
			"sub": lambda x,y: x-y,
			"mul": lambda x,y: x*y,
			"div": lambda x,y: x/y,
			"mod": lambda x,y: x%y
		})

		self.bitwise_operation = dict({
			"and": lambda x,y: x&y,
			"or": lambda x,y: x|y,
			"xor": lambda x,y: x^y,
			"bsh": lambda x,y: y > 0 and x<<y or x>>y.__neg__(),
			"bisz": lambda x: x != 0 and 1 or 0
		})

		self.indirect_branch_operation = ({
			0: lambda x: self.dereferences_stack_pointer(x),
			1: lambda x: self.stores_stack_pointer(x),
			2: lambda x: self.pushes_to_stack(x),
			3: lambda x: self.branch_indirect(x)
		})

	def immediate_store(self, instruction):
		return instruction.mnemonic in ("str")

	def memory_load(self, instruction):
		return instruction.mnemonic in ("ldm")

	def memory_store(self, instruction):
		return instruction.mnemonic in ("stm")

	def memory_operation(self, instruction):
		return instruction.mnemonic in ("stm", "ldm")

	def undefine_operation(self, instruction):
		return instruction.mnemonic in ("undef")

	def branch_operation(self, instruction):
		return instruction.mnemonic in ("jcc")

	#############################################################################################
	# Data types
	def is_numeric(self, value):
		try:
			int(value, 16)
			return True
		except:
			return False

	def is_stack_reference(self, operand):
		if len(operand.value) > 0: return "stack_ptr_" in operand.value[0:10]
		return False

	def is_stack_variable(self, operand):
		if len(operand.value) > 0: return "stack_var_" in operand.value[0:10]
		return False

	def is_temporary_register(self, operand):
		if len(operand.value) > 0: return "t" in operand.value[0]
		return False

	def is_native_register(self, operand):
		if len(operand.value) > 0:
			return not self.is_numeric(operand.value) and \
			       not self.is_stack_variable(operand) and \
			       not self.is_stack_reference(operand) and \
			       not self.is_temporary_register(operand)
		return False

	def is_native_variable(self, operand):
		return self.is_native_register(operand) or self.is_stack_variable(operand) or \
		       self.is_stack_reference(operand)

	#############################################################################################
	# Algebraic assertions
	def is_identity(self, instruction):
		if instruction.mnemonic in ("add", "sub"):
			# In case of substraction: this is how REIL specifies integer
			# sign inversion, which must be ignored in this transformation.
			if instruction.firstOperand.value == '0':
				return instruction.secondOperand
			if instruction.secondOperand.value == '0':
				return instruction.firstOperand

		if instruction.mnemonic in ("mul", "div"):
			if instruction.firstOperand.value == '1':
				return instruction.secondOperand
			if instruction.secondOperand.value == '1':
				return instruction.firstOperand
		return None
	#############################################################################################
	# Specific operations
	def reads_register(self, instruction):
		return self.reads_temporary_register(instruction) or self.reads_native_register(instruction)

	def reads_temporary_register(self, instruction):
		return (self.is_temporary_register(instruction.firstOperand) or self.is_temporary_register(instruction.secondOperand)) and not self.branch_operation(instruction)

	def reads_native_register(self, instruction):
		return (self.is_native_register(instruction.firstOperand) or self.is_native_register(instruction.secondOperand)) and not self.branch_operation(instruction)

	def reads_native_variable(self, instruction):
		return (self.is_native_variable(instruction.firstOperand) or self.is_native_variable(instruction.secondOperand)) and not self.branch_operation(instruction)

	def writes_register(self, instruction):
		return self.writes_temporary_register(instruction) or self.writes_native_register(instruction)

	def writes_temporary_register(self, instruction):
		return self.is_temporary_register(instruction.thirdOperand) and \
			not self.branch_operation(instruction)

	def writes_native_register(self, instruction):
		return self.is_native_register(instruction.thirdOperand) and \
		       not self.branch_operation(instruction)
	
	def writes_native_variable(self, instruction):
		return self.is_native_variable(instruction.thirdOperand) and \
		       not self.branch_operation(instruction)

	def dereferences_stack_pointer(self, instruction):
		if instruction.mnemonic in ("add", "sub"):
			o1 = instruction.firstOperand.value
			o2 = instruction.secondOperand.value
			return "esp" in (o1, o2)
		return False

	def stack_pointer_reference(self, instruction):
		if instruction.mnemonic in ("add", "sub"):
			if instruction.firstOperand.value == 'esp':
				try:
					operand = Address(long(instruction.secondOperand.value))
					return ReilOperand(OperandSize.OPERAND_SIZE_DWORD, str("stack_ptr_" + str(operand).upper()))
				except:
					pass
			if instruction.secondOperand.value == 'esp':
			  	try:
					operand = Address(long(instruction.firstOperand.value))
					return ReilOperand(OperandSize.OPERAND_SIZE_DWORD, str("stack_ptr_" + str(operand).upper()))
				except:
					pass
		return None

	def reference_to_variable(self, operand):
		return ReilOperand(OperandSize.OPERAND_SIZE_DWORD, str.replace(operand.value, "_ptr_", "_var_"))

	def writes_constant_to_native_register(self, instruction):
		return (self.immediate_store(instruction) and \
				self.is_native_register(instruction.thirdOperand)) and \
			   self.is_numeric(instruction.firstOperand.value)

	def aligns_stack_pointer(self, instruction):
		if instruction.mnemonic in "and":
			o1 = instruction.firstOperand.value
			o2 = instruction.secondOperand.value
			return "esp" in (o1, o2)
		return False

	def shifts_stack_pointer(self, instruction):
		if instruction.mnemonic in ("add", "sub"):
			o1 = instruction.firstOperand.value
			o2 = instruction.secondOperand.value
			return "esp" in (o1, o2)
		return False

	def stores_stack_pointer(self, instruction):
		if self.writes_native_register(instruction):
			o3 = instruction.thirdOperand.value
			return "esp" in o3
		return False

	def saves_stack_pointer(self, instruction):
		if self.writes_native_register(instruction):
			o1 = instruction.firstOperand.value
			return "esp" in o1
		return False

	def pushes_to_stack(self, instruction):
		if self.memory_store(instruction):
			o3 = instruction.thirdOperand.value
			return "esp" in o3
		return False

	def branch_always(self, instruction):
		if self.branch_operation(instruction):
			o1 = instruction.firstOperand.value
			return "1" in o1
		return False

	def branch_indirect(self, instruction):
		if self.branch_always(instruction):
			o3 = instruction.thirdOperand
			return self.is_native_register(o3)
		return False


