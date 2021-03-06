package com.hardcoded.plugin.tracer;

import com.hardcoded.plugin.ScrapMechanicPlugin;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;

class ConstantAnalyser {
	private final ScrapMechanicPlugin plugin;
	public ConstantAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
	public void analyseConstants(SMClass clazz, SMDefinition definiton) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return;
		
		AddressFactory factory = currentProgram.getAddressFactory();
		ProgramMemory memory = plugin.getProgramMemory();
		
		if(definiton.getConstant() != null) {
			Address address = factory.getAddress(definiton.getConstant());
			if(address != null) {
				int max = 256;
				do {
					Address nameAddr = memory.readAddress(address);
					if(nameAddr == null || nameAddr.getOffset() == 0) break;
					
					Address funcAddr = memory.readAddress(address.add(memory.getAddressSize()));
					String name = memory.readTerminatedString(nameAddr);
					clazz.createConstant(funcAddr.toString(), name, null);
					
					address = address.add(8);
				} while(max-- > 0);
			}
		}
	}
	
	public void analyseConstantValues(SMClass.Constant func) {
		
	}
}
