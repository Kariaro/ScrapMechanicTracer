package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * This class is used to update the current plugin information inside
 * the {@code ScrapMechanicWindowProvider} window.
 * 
 * <p>This class provides the interface with the amount of functions
 * loaded and the current version of the game.
 * 
 * @author HardCoded
 * @date 2020-11-22
 */
class InformationAnalyser {
	private final ScrapMechanicPlugin plugin;
	private final CodeSyntaxTreeAnalyser cta;
	public InformationAnalyser(ScrapMechanicPlugin tool, CodeSyntaxTreeAnalyser cta) {
		this.plugin = tool;
		this.cta = cta;
	}
	
	public void analyse(SMClass table) {
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) return;
		
		long time = System.currentTimeMillis();
		plugin.getWindow().writeLog(this, "Searching for information");
		
		{
			String version = findVersionString();
			plugin.getWindow().setVersionText("" + version);
			plugin.getWindow().writeLog(this, "Version -> " + version);
			
			int functions = table.getAllFunctions().size();
			plugin.getWindow().setFunctionsText("" + functions);
			plugin.getWindow().writeLog(this, "Functions -> " + functions);
		}
		
		plugin.getWindow().writeLog(this, "Took " + (System.currentTimeMillis() - time) + " ms");
	}
	
	private String findVersionString(){
		ProgramMemory programMemory = plugin.getProgramMemory();
		List<Address> list = programMemory.findMatches("\0version\0".getBytes());
		if(list.isEmpty()) return "<invalid>";
		
		// Make sure that we only find one version string!
		// Because otherwise we might get some problems finding the correct version id.
		Address pointer = list.get(0);
		List<Address> matches = programMemory.findMatches(pointer.add(1));
		if(matches.isEmpty()) return "<invalid>";
		
		pointer = null;
		for(Address addr : matches) {
			if(addr.toString().startsWith("00e")) {
				pointer = addr;
				break;
			}
		}
		
		if(pointer == null) return "<invalid>";
		pointer = programMemory.readAddress(pointer.add(4));
		if(pointer == null) return "<invalid>";
		return loadVersionString(pointer);
	}
	
	public String loadVersionString(Address entry) {
		Program program = plugin.getCurrentProgram();
		Listing listing = program.getListing();
		AddressFactory addressFactory = program.getAddressFactory();
		ProgramMemory programMemory = plugin.getProgramMemory();
		
		// Load and dissasemble this function
		cta.discoverCode(entry);
		Instruction iter = listing.getInstructionAt(entry);
		if(iter == null) return "<invalid>";
		
		List<Instruction> list = new ArrayList<>();
		
		String version = "<invalid>";
		String buildVersion = null;
		
		// FIXME: This is unsafe. This should use the same type of code as the CodeSyntaxResolver!
		boolean skipNext = false;
		while((iter = iter.getNext()) != null) {
			Address addr = iter.getAddress();
			String mnemonic = iter.getMnemonicString();
			int readByte = Byte.toUnsignedInt(programMemory.getBytes(addr, 1)[0]);
			
			if(readByte == 0xba && buildVersion == null) {
				int readBuildVersion = programMemory.readInt(addr.add(1));
				readBuildVersion &= 0xffff;
				buildVersion = Integer.toString(readBuildVersion);
				skipNext = true;
			}
			
			if("PUSH".equals(mnemonic)) {
				list.add(iter);
			} else {
				if("CALL".equals(mnemonic)) {
					if(skipNext) {
						skipNext = false;
						list.clear();
						continue;
					}
					
					for(Instruction inst : list) {
						String str = inst.toString().substring(4).replace("0x", "").trim();
						Address addr2 = addressFactory.getAddress(str);
						version = programMemory.readTerminatedString(addr2);
						if(version != null) break;
					}
					
					list.clear();
					break;
				}
				
			}
		}
		
		if(version == null) return "<invalid>";
		return version + '.' + buildVersion;
	}
}
