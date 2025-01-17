

__author__ = 'Tiago Assumpcao'
__license__ = '_'

import sys
import os
import time

import binnavi

from sets import Set

from com.google.security.zynamics.binnavi.API.reil.mono import ILattice
from com.google.security.zynamics.binnavi.API.reil.mono import ILatticeElement
from com.google.security.zynamics.binnavi.API.reil.mono import MonotoneSolver
from com.google.security.zynamics.binnavi.API.reil.mono import ITransformationProvider
from com.google.security.zynamics.binnavi.API.reil.mono import DefaultStateVector

from binnavi.memory.memoryregions import MemoryRegions



# These are specified in accordance with G. Balakrishnan's doctorate
# thesis, defined specifically within the "Intermediate-Representation
# Recovery from Low-Level Code". Some of its design decisions were also
# inspired by Johannes Kinder's Jakstab.
# The concrete domain
cIntervalMap = {}
# The initial abstract domain
aIntervalMap = None
# Top
TOP1 = None
TOP8 = None
TOP16 = None
TOP32 = None
TOP64 = None


def createTop():
	global TOP1
	global TOP8
	global TOP16
	global TOP32
	global top64

	Regions = MemoryRegions()

	TOP1 = IntervalElement(Regions.getTop(), -1, 0, 1, 1)
	TOP8 = IntervalElement(Regions.getTop(), -128, 127, 1, 8)
	TOP16 = IntervalElement(Regions.getTop(), -32768, 32767, 1, 16)
	TOP32 = IntervalElement(Regions.getTop(), -2147483648, 2147483647, 1, 32)
	TOP64 = IntervalElement(Regions.getTop(), -9223372036854775808, 9223372036854775807, 1, 64)

def getTop(bitwidth):
	# Top[Top] -> {Top}
	# We support up to 64-bit strided intervals.
	if TOP1 == None:
		createTop()

	if bitwidth == 1:
		return TOP1
	elif bitwidth == 8:
		return TOP8
	elif bitwidth == 16:
		return TOP16
	elif bitwidth == 32:
		return TOP32 
	elif bitwidth == 64:
		return TOP64
	else:
		return None

def isTop(element):
	# We use a dummy singleton to represent Top.
	# F(Top) <-> Lattice { top, top, top, ... }
	return getTop(element.bitwidth) == element

def isBotom(element):
	# If any region is not in the regions map, maps to bottom.
	for k in element.alocEnv.iterkeys():
		if k in cIntervalMap: return False
	return True

def join(states):
	# As a matter of fact, the abstraction here isn't kept within
	# the lattice sets, but within the strided arithmetics.
	# For such, join etc. operations give specifically towards
	# a single-state lattice element. 
	combined_state = IntervalElement()

	for element in states:
		if combined_state.region == None:
			comtbined_state = element
			continue

		if combined_state.bitwidth != element.bitwidth:
			return combined_state
		# Top element, widen it.
		if isTop(element):
			return element
		# The rule here is: we don't want to join
		# different memory regions arbitrarily.
		if combined_state.region != element.region:
			return getTop(element.bitwidth)

		if combined_state.lboundOpen() and element.uboundOpen() or \
			combined_state.uboundOpen() and element.lboundOpen():
			return getTop(combined_state.bitwidth)

		combined_state.stride = mergeStrides(combined_state.stride, element.stride)
		combined_state.lbound = min(combined_state.lbound, state.lbound)
		combined_state.ubound = max(combined_state.ubound, state.ubound)

	return combined_state

def mergeStrides(si1, si2):
	stride = 0

	if (si1.stride == 0) and (si2.stride == 0):
		stride = si2.lbound - si1.lbound
		return stride

	stride = gcd(si1.stride, si2.stride)
	stride = gcd(stride, si1.lbound - si2.lbound)

	return stride

def lboundOpen(element):
	return element.lbound == getTop(element.bitwidth).lbound

def uboundOpen(element):
	return element.ubound == getTop(element.bitwidth).ubound

# Strided-Interval Arithmetic - as defined G. Balakrishnan's
# doctorate thesis.
def add(si1, si2):
	# This should just make the operation inane - work around overflows, if needed.
	if si1.bitwidth != si2.bitwidth:
		return si1

	bitwidth = si1.bitwidth

	lub_region = si1.region.combine(si2.region)
	if lub_region.isTop(): return si1.getTop(si2.bitwidth)

	lbound = int(si1.lbound + si2.lbound)
	ubound = int(si1.ubound + si2.ubound)
	u = int(si1.lbound & si2.lbound & ~lbound & ~(si1.ubound & si2.ubound & ~ubound))
	v = int((si1.lbound ^ si2.lbound) | ~(si1.lbound ^ lbound) & (~si1.ubound & ~si2.ubound & ubound))

	top = si1.getTop(si2.bitwidth)
	if ((u < 0) or (v < 0)) or (u > top.ubound) or (v > top.ubound):
		return top
	return IntervalElement(lub_region, lbound, ubound, gcd(si1.stride, si2.stride), bitwidth)

def gcd(s1, s2):
	def _gcd(a, b):
		r = 1
		while (r > 0):
			r = a % b
			a = b
			b = r
		return a
	if (s1 == 0): return s2
	if (s2 == 0): return s1
	return _gcd(s1, s2)

def neg(si):
	if si.lbound == getTop(si.bitwidth).lbound:
		if si.lbound == si.ubound:
			return si
		return getTop(si.bitwidth)
	return IntervalElement(si.region, si.ubound.__neg__(), si.lbound.__neg__(), si.stride, si.bitwidth)

def sub(si1, si2):
	return add(si1, neg(si2))

def mul(si1, si2):
	lub_region = si1.region.combine(si2.region)
	bitwidth = self.bitwidth * 2
	top = getTop(bitwidth)
	stride = 0

	lbound = int(si1.lbound * si2.lbound)
	ubound = int(si1.ubound * si2.ubound)

	if (lbound <= top.lbound) or (ubound > top.ubound):
		return top

	if si1.stride == 0:
		if si2.stride == 0:
			stride = 0
		if si1.lbound == si1.ubound:
			stride = si2.stride * si1.lbound
	elif si2.stride == 0:
		if si2.lbound == si2.ubound:
			stride = si2.lbound * si1.stride
	else:
		stride = si1.stride * si2.stride
	return IntervalElement(lub_region, lbound, ubound, stride, bitwidth)

def generateStartVector(self, graph):
	createTop()
	startVector = DefaultStateVector()

	# Default initializes one activation record.
	element = IntervalElement()

	for node in graph:
		startVector.setState(node, element)

	return startVector

class IntervalElement(ILatticeElement):
	def __init__(self, region=None, lbound=0, ubound=0, stride=0, bitwidth=0):
		self.region = region
		self.lbound = lbound
		self.ubound = ubound
		self.bitwidth = bitwidth
		if ubound - lbound == 0:
			self.stride = 0
		else:
			self.stride = stride

	def combine(self, l):
		return join([self, l])

	def isTop(self):
		return isTop(self)

	def equals(self, l):
		if self == l:
			return True
		if self.bitwidth != l.bitwidth:
			return False
		if self.stride != l.stride:
			return False
		if self.lbound != l.lbound:
			return False
		if self.ubound != l.ubound:
			return False
		if not self.region.equals(l.region):
			return False
		return True

	def lessThan(self, l):
		if self.bitwidth != l.bitwidth:
			return False
		return (l.lbound < self.lbound) and (l.ubound > self.lbound) and\
			l.stride < self.stride

	def getTop(self, bitwidth):
		return getTop(bitwidth)

	def setTop(self, bitwidth):
		top = getTop(bitwidth)

		self.region = top.region
		self.lbound = top.lbound
		self.ubound = top.ubound
		self.bitwidth = top.bitwidth

	def lboundOpen(self):
		return lboundOpen(self)

	def uboundOpen(self):
		return uboundOpen(self)

	def concretize(self):
		cValue = Set()
		stride = self.stride
		if stride != 0:
			while stride != 0:
				interval = range(self.lbound, self.ubound)
				cValue |= Set(interval)
		return cValue

	def getAbstractElement(self, node):
		return aIntervalMap.getState(node)

	def getConcreteRegions(self, region_ame):
		return cIntervalMap[region_name]

	def size(self):
		if self.stride == 0:
			return 1
		return (self.ubound - self.lbound) / self.stride + 1

	def add(self, stride):
		return add(self, stride)


class Lattice(ILattice):
	def combine(self, states):
		return join(states)

class TransformationProvider(ITransformationProvider):
	# The transfer function rule is also simplistic: just union every node's
	# alocation sites present at the start vector.
	def transform(self, node, currentState, influencingState):
		transformed_state = join([currentState, influencingState])
		return transformed_state


