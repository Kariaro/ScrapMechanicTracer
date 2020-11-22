package sm.hardcoded.plugin.tracer;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.util.List;

import docking.dnd.StringTransferable;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

/**
 * Used to analsyse a scrap mechanic executable.
 * 
 * @date 2020-11-22
 * @author HardCoded
 */
class ScrapMechanicAnalyser {
	private final ScrapMechanicPlugin plugin;
	
	private TableElementFinder elementFinder;
	private TableFinder tableFinder;
	private LuaTypeManager luaTypeManager;
	
	private FunctionAnalyser functionAnalyser;
	private ConstantAnalyser constantAnalyser;
	private CodeSyntaxTreeAnalyser cstAnalyser;
	private String errorMessage = "";
	
	public ScrapMechanicAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
		
		elementFinder = new TableElementFinder(tool);
		tableFinder = new TableFinder(tool);
		luaTypeManager = new LuaTypeManager(tool);
		
		functionAnalyser = new FunctionAnalyser(tool);
		constantAnalyser = new ConstantAnalyser(tool);
		cstAnalyser = new CodeSyntaxTreeAnalyser(tool);
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
		SMClass table = new SMClass("sm");
		
		// Read all the functions and constants found in the table found in memory
		for(SMDefinition object : objects) {
			String name = programMemory.readTerminatedString(factory.getAddress(object.getName()));
			SMClass clazz = table.createClass(name);
			functionAnalyser.analyseFunctions(clazz, object);
			constantAnalyser.analyseConstants(clazz, object);
		}
		
		SMClass.Function func = table.getClass("localPlayer").getFunction("updateFpAnimation");
		provider.writeLog(this, "Function -> " + (func == null ? null:func.getAddress()));
		
		//	     b) Use a code flow analyser to get the arguments for each function that
		//        we have found. Use a constant analyser to get the rest of the
		//        information that we need.
		if(func != null) {
			// updateFpAnimation
			Address entry = factory.getAddress(func.getAddress());
			
			// function updateFpAnimation( String, [Number, String], [Number, String], [Number, Boolean] ) min:2 max:4,
			// function updateFpAnimation( String, [Number, String], [Number, String], [Number, Boolean] ) min:2 max:4,
			
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
			cmd.enableCodeAnalysis(false);
			if(!cmd.applyTo(currentProgram)) {
				Msg.warn(this, "Failed to disassemble memory at address '" + entry + "'");
			}
			
			cstAnalyser.analyse(func);
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
