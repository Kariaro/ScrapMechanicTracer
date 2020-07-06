package sm.hardcoded.plugin.tracer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;

class FunctionAnalyser {
	private final ScrapMechanicPlugin plugin;
	public FunctionAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
	public void analyseFunctions(SMClass klass, SMDefinition definiton) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return;
		
		AddressFactory factory = currentProgram.getAddressFactory();
		ProgramMemory programMemory = plugin.getProgramMemory();
		
		if(definiton.getTabledata() != null) {
			Address address = factory.getAddress(definiton.getTabledata());
			if(address != null) {
				int max = 256;
				do {
					Address nameAddr = programMemory.readAddress(address);
					if(nameAddr == null || nameAddr.getOffset() == 0) break;
					
					Address funcAddr = programMemory.readAddress(address.add(4));
					String name = programMemory.readTerminatedString(nameAddr);
					klass.createFunction(funcAddr.toString(), name, false);
					
					address = address.add(8);
				} while(max-- > 0);
			}
		}
		
		if(definiton.getUserdata() != null) {
			Address address = factory.getAddress(definiton.getUserdata());
			if(address != null) {
				int max = 256;
				do {
					Address nameAddr = programMemory.readAddress(address);
					if(nameAddr == null || nameAddr.getOffset() == 0) break;
					
					Address funcAddr = programMemory.readAddress(address.add(4));
					String name = programMemory.readTerminatedString(nameAddr);
					klass.createFunction(funcAddr.toString(), name, true);
					
					address = address.add(8);
				} while(max-- > 0);
			}
		}
		
		if(definiton.getHidden() != null) {
			Address address = factory.getAddress(definiton.getHidden());
			if(address != null) {
				int max = 256;
				do {
					Address nameAddr = programMemory.readAddress(address);
					if(nameAddr == null || nameAddr.getOffset() == 0) break;
					
					Address funcAddr = programMemory.readAddress(address.add(4));
					String name = programMemory.readTerminatedString(nameAddr);
					klass.createFunction(funcAddr.toString(), name, false);
					
					address = address.add(8);
				} while(max-- > 0);
			}
		}
	}
	
	public void analyseFunctionArguments(SMClass.Function func) {
		
	}
}
