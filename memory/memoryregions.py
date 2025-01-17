

__author__ = 'Tiago Assumpcao'
__license__ = '_'


from sets import Set

from com.google.security.zynamics.binnavi.API.reil.mono import ILattice
from com.google.security.zynamics.binnavi.API.reil.mono import ILatticeElement
from com.google.security.zynamics.binnavi.API.reil.mono import MonotoneSolver
from com.google.security.zynamics.binnavi.API.reil.mono import ITransformationProvider
from com.google.security.zynamics.binnavi.API.reil.mono import DefaultStateVector


# The concrete domain
cRegionMap = {}
# The initial abstract domain
aRegionMap = None
TOP = None

def getTop():
	return TOP

def isTop(element):
	# We use a dummy singleton to represent Top.
	# F(Top) <-> Lattice { top, top, top, ... }
	return getTop() == element

def isBotom(element):
	# If any region is not in the regions map, maps to bottom.
	for k in element.alocEnv.iterkeys():
		if k in cRegionMap:
			return False
	return True

def join(states):
	# The join rules will pretty much depend on your analysis.
	# Intra-procedural shall allow for a unique activation record.
	# Any analysis shall allow for a unique Global.
	# Heaps can be allocated and categorized as pleased.
	#
	# The default rule is dummy - a top element influencing another
	# tops its successors.
	combined_state = LatticeElement()

	for element in states:
		for key in element.alocEnv:
			# Top element, widen it.
			if isTop(element):
				return element

			if key not in combined_state.alocEnv:
				combined_state.alocEnv[key] = Set()
			combined_state.alocEnv[key] |= element.alocEnv[key]

	return combined_state

def concretize(node):
	element = aRegionMap.getState(node)
	# Start with Bottom
	gama = {}

	for key in element.alocEnv.iterkeys():
		if key in cRegionMap:
			g = (element.alocEnv[key] & cRegionMap[key])
			if len(g) == 0: gama[key] = getTop()
			else: gama[key] = g

	return gama

class Region:
	def __init__(self, name):
		# No ID is actually required; we use the object's instance unique ID.
		self.name = name

class LatticeElement(ILatticeElement):
	# AlocEnv[Region] = AStore[Region, offset] -> ALoc -> AValue
	def __init__(self):
		self.alocEnv = {}

	def combine(self, l):
		return join([self, l])

	def isTop(self):
		return isTop(self)

	def isBotom(self):
		return isBotom(self)

	def equals(self, l):
		return self.alocEnv == l.alocEnv

	def lessThan(self, l):
		return self.alocEnv < l.alocEnv

class Lattice(ILattice):
	def combine(self, states):
		return join(states)

class TransformationProvider(ITransformationProvider):
	# The transfer function rule is also simplistic: just union every node's
	# alocation sites present at the start vector.
	def transform(self, node, currentState, influencingState):
		transformed_state = LatticeElement()

		transformed_state.alocEnv = currentState.alocEnv
		for key in influecingState.alocEnv:
			if key not in transformed_state.alocEnv:
				transformed_state.alocEnv[key] = Set()
			transformed_state.alocEnv[key] |= influencingState.element.alocEnv[key]

		return transformed_state

class MemoryRegions:
	def __init__(self, graph=None):
		global aRegionMap

		self.topAlloc()
		if graph != None:
			aRegionMap = self.generateStartVector(graph)

	def globalAlloc(self):
		global cRegionMap

		# The user must guarantee the existance of only one Global region.
		if "global" not in cRegionMap:
			cRegionMap["global"] = Set()

		r = Region("global")
		cRegionMap["global"] |= Set([r])
		return r

	def stackAlloc(self):
		global cRegionMap

		if "stack" not in cRegionMap:
			cRegionMap["stack"] = Set()

		r = Region("stack")
		cRegionMap["stack"] |= Set([r])
		return r

	def heapAlloc(self):
		global cRegionMap

		if "heap" not in cRegionMap:
			cRegionMap["heap"] = Set()

		r = Region("heap")
		cRegionMap["heap"] |= Set([r])
		return r

	def topAlloc(self):
		global cRegionMap
		global TOP

		# This should actually be a singleton set,
		# but life is easier if it's just an object.
		if "TOP" not in cRegionMap:
			cRegionMap["TOP"] = Set()

		r = Region("TOP")
		cRegionMap["TOP"] |= Set([r])
		TOP = LatticeElement()
		TOP.alocEnv["TOP"] = cRegionMap["TOP"]

	def concretize(self, node):
		return concretize(node)

	def getAbstractElement(self, node):
		return aRegionMap.getState(node)

	def getConcreteRegions(self, region_ame):
		return cRegionMap[region_name]

	def getTop(self):
		return getTop()

	def generateStartVector(self, graph):
		startVector = DefaultStateVector()

		# Default initializes one activation record.
		element = LatticeElement()
		stack = self.stackAlloc()
		heap1 = self.heapAlloc()
		heap2 = self.heapAlloc()
		heaps = Set([heap1])
		heaps |= Set([heap2])
		element.alocEnv[stack.name] = Set([stack])
		element.alocEnv[heap1.name] = heaps

		for node in graph:
			startVector.setState(node, element)

		return startVector


