

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
from binnavi.memory.memoryregions import LatticeElement as RegionElement
from binnavi.memory.stridedintervals import IntervalElement


TOP = None

def join(states):
	combined_state = LatticeElement()

	for element in states:
		for region, offset in element.aStore:
			if offset != self.offset:
				continue
			bitwidth = element.aStore[region, offset].size * 8
			aVal = element.aStore[region, offset].contents
			if (region, offset) in combined_state.aStore:
				aux_aVal = combined_state[region, offset].readAloc(region, offset, bitwidth)
				combined_state.writeAloc(region, offset, bitwidth, aux_aVal.combine(aVal))
			combined_state.writeAloc(region, offset, bitwidth, aVal)
	return combined_state

def createTop():
	TOP = LatticeElement()

def getTop():
	global TOP

	if TOP == None:
		createTop()
	return TOP

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

class Aloc:
	def __init__(self, offset, size, aVal):
		# Our abstract value is a strided-interval.
		self.aVal = aVal
		self.offset = offset
		self.size = size

	def equals(self, aloc):
		if self == aloc:
			return True

		if not self.aVal.equals(aloc.aVal):
			return False
		if self.offset != aloc.offset:
		 	return False
		if self.size != aloc.size:
			return False
		return True

class LatticeElement(ILatticeElement):
	def __init__(self):
		# AStore[Region, offset] = ALoc -> AValue
		self.aStore = {}

	def isTop(self):
		# We use a dummy singleton to represent Top.
		# F(Top) <-> Lattice { top, top, top, ... }
		return self.equals(TOP)

	def setTop(self):
		self.aStore = {}

	def getAloc(self, region, offset):
		if (region, offset) in self.aStore:
			return self.aStore[region, offset]
		return None

	def setAvalTop(self, aval, bitwidth):
		return aval.setTop(bitwidth)

	def writeAloc(self, region, offset, bitwidth, aVal):
		if region.isTop() or region.isBotom():
			return

		# As described by G. Balakrishnan et al. in
		# "WYSINWYX: What You See Is Not What You eXecute" and in
		# "Analyzing Memory Accesses in x86 Executables", to ensure
		# the strictness of partial overwrites within strided memory
		# cells, a memory update procedure must verify for unaligned
		# stores. If this is the case, our algorithm must set the
		# lattice to TOP.
		size = bitwidth / 8
		index = 0

		while index < size:
			# Check for partial memory writes - TOP the a-value.
			aLoc = self.getAloc(region, offset + index)
			if aLoc != None:
				self.setAvalTop(aLoc.aVal, bitwidth)
			index += 1

		aLoc = Aloc(offset, size, aVal)
		index = 0
		while index < size:
			self.aStore[region, offset + index] = aLoc
			index += 1

	def readAloc(self, region, offset, bitwidth):
		if region.isTop() or region.isBotom():
			return

		# As described by G. Balakrishnan et al. in
		# "WYSINWYX: What You See Is Not What You eXecute" and in
		# "Analyzing Memory Accesses in x86 Executables".

		# Work around possible bitmap-overwrites.
		size = bitwidth / 8
		aLoc = self.getAloc(region, offset)
		if aLoc != None or aLoc.size != size:
			if ((aLoc.size > size) and (aLoc.offset >= offset + size)):
				# Unaligned - fix it.
				lo = (int) ((offset - aLoc.offset) * 8)
				hi = (int) (lo + bitwidth - 1)
	
				# Here's the trick for the alignment
				cVal |= range(lo, hi)
				return aLoc.aVal.combine(IntervalElement(region, lo, hi, aLoc.aVal.stride, bitwidth))
			return aLoc.aVal
		return IntervalElement().getTop(bitwidth)

	def removeAloc(self, region, offset):
		del self.aStore[region, offset]

	def combine(self, l):
		return join([self, l])

	def equals(self, l):
		return self.aStore == l.aStore

	def lessThan(self, l):
		for region, offset in l.aStore:
			if offset != self.offset:
				continue
			bitwidth = l.aStore[region, offset].size * 8
			aVal = l.aStore[region, offset].contents
			aux_aVal = self.readAloc(region, offset, bitwidth)
			if aux_aVal.lessThan(aVal):
				return True
		return False

class Lattice(ILattice):
	def combine(self, states):
		return join(states)

class TransformationProvider(ITransformationProvider):
	def transform(self, node, currentState, influencingState):
		transformed_state = LatticeElement()

		transformed_state.aStore = currentState.aStore
		for element in influencingState:
			for region, offset in element.aStore:
				if offset != self.offset:
					continue
				bitwidth = element.aStore[region, offset].size * 8
				aVal = element.aStore[region, offset].contents
				if (region, offset) in transformed_state.aStore:
					aux_aVal = influencingState[region, offset].readAloc(region, offset, bitwidth)
					transformed_state.writeAloc(region, offset, bitwidth, aux_aVal.combine(aVal))
				transformed_state.writeAloc(region, offset, bitwidth, aVal)
		return transformed_state

