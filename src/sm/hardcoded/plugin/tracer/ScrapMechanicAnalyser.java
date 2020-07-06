package sm.hardcoded.plugin.tracer;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.util.List;

import docking.dnd.StringTransferable;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

class ScrapMechanicAnalyser {
	private final ScrapMechanicPlugin plugin;
	
	private TableElementFinder elementFinder;
	private TableFinder tableFinder;
	private LuaTypeManager luaTypeManager;
	
	private FunctionAnalyser functionAnalyser;
	private ConstantAnalyser constantAnalyser;
	private String errorMessage = "";
	
	public ScrapMechanicAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
		
		elementFinder = new TableElementFinder(tool);
		tableFinder = new TableFinder(tool);
		luaTypeManager = new LuaTypeManager(tool);
		
		functionAnalyser = new FunctionAnalyser(tool);
		constantAnalyser = new ConstantAnalyser(tool);
	}
	
	public boolean startAnalysis() {
		errorMessage = "";
		
		Program currentProgram = plugin.getCurrentProgram();
		if(currentProgram == null) {
			errorMessage = "No current program active";
			return false;
		}
		
		ProgramMemory programMemory = plugin.getProgramMemory();
		AddressFactory factory = currentProgram.getAddressFactory();
		ScrapMechanicWindowProvider provider = plugin.getWindow();
		
		provider.setScanEnabled(false);
		provider.clearLogger();
		
		// Step 1:
		//     Find all the strings and functions that registers
		//     the different lua elements.
		
		long startTime = System.currentTimeMillis();
		
		try {
			programMemory.loadMemory();
		} catch(MemoryAccessException e) {
			e.printStackTrace();
			errorMessage = "Failed to load memory\n" + e.getMessage();
			return false;
		}
		
		List<FunctionPointer> tables = tableFinder.findFunctionTable();
		List<SMDefinition> objects = elementFinder.findSMObjects(tables);
		luaTypeManager.registerTypes(objects);
		
		// Step 2:
		//     a) Load all the functions and constants that are we have found
		//        and add them to our own table.
		//
		//     b) Use a code flow analyser to get the arguments for each function that
		//        we have found. Use a constant analyser to get the rest of the
		//        information that we need.
		
		SMClass table = new SMClass("sm");
		
		for(SMDefinition object : objects) {
			String name = programMemory.readTerminatedString(factory.getAddress(object.getName()));
			SMClass klass = table.createClass(name);
			functionAnalyser.analyseFunctions(klass, object);
			constantAnalyser.analyseConstants(klass, object);
		}
		
		// Msg.debug(this, "\n" + table.toString());
		
		String string = table.toString();
		Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
		clip.setContents(new StringTransferable(string), null);
		
		// Step 3:
		//     Dump all the arguments and constants in a pretty format to the selected
		//     file path 'provider.getScanPath()' and give it the file name
		//     lua.<Version>.<Date yyyy.mm.dd.hh.MM.ss>.log
		
		
		provider.writeLog(this, "Done. Took " + (System.currentTimeMillis() - startTime) + " ms");
		
		return true;
	}
	
	public String getLastError() {
		return errorMessage;
	}
}
