package sm.hardcoded.plugin.tracer;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import docking.dnd.StringTransferable;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.TracedFunction;

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
	
	private InformationAnalyser informationAnalyser;
	private FunctionAnalyser functionAnalyser;
	private ConstantAnalyser constantAnalyser;
	private CodeSyntaxTreeAnalyser cstAnalyser;
	private LuaFunctionImporter luaImporter;
	private String errorMessage = "";
	
	public ScrapMechanicAnalyser(ScrapMechanicPlugin tool) {
		plugin = tool;
		
		elementFinder = new TableElementFinder(tool);
		tableFinder = new TableFinder(tool);
		luaTypeManager = new LuaTypeManager(tool);
		
		functionAnalyser = new FunctionAnalyser(tool);
		constantAnalyser = new ConstantAnalyser(tool);
		cstAnalyser = new CodeSyntaxTreeAnalyser(tool);
		
		informationAnalyser = new InformationAnalyser(tool, cstAnalyser);
		luaImporter = new LuaFunctionImporter(tool);
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
		
		try {
			// Try import lua functions and categories
			luaImporter.initialize();
		} catch(Exception e) {
			e.printStackTrace();
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
		
		// Read all the functions and constants found in the table found in memory
		for(SMDefinition object : objects) {
			String name = programMemory.readTerminatedString(factory.getAddress(object.getName()));
			SMClass clazz = table.createClass(name);
			functionAnalyser.analyseFunctions(clazz, object);
			constantAnalyser.analyseConstants(clazz, object);
		}
		
		{
			informationAnalyser.analyse(table);
		}
		
		//SMClass.Function func = table.getClass("localPlayer").getFunction("updateFpAnimation");
//		SMClass.Function func = table.getClass("localPlayer").getFunction("addRenderable");
//		provider.writeLog(this, "Function -> " + (func == null ? null:func.getAddress()));
		
//		if(func != null) {
//			// function updateFpAnimation( String, [Number, String], [Number, String], [Number, Boolean] ) min:2 max:4,
//			// function updateFpAnimation( String, [Number, String], [Number, String], [Number, Boolean] ) min:2 max:4,
//			cstAnalyser.analyse(func);
//		}
		
		// Load important values
		cstAnalyser.init();
		scanAllFunctions(table);
		
		StringBuilder string = new StringBuilder();
		string.append(table.toString());
		string.append("\n").append("Done. Took " + (System.currentTimeMillis() - startTime) + " ms");
		Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
		clip.setContents(new StringTransferable(string.toString()), null);
		
		// Step 3:
		//     Dump all the arguments and constants in a pretty format to the selected
		//     file path 'provider.getScanPath()' and give it the file name
		//     lua.<Version>.<Date yyyy.mm.dd.hh.MM.ss>.log
		
		
		provider.writeLog(this, "Done. Took " + (System.currentTimeMillis() - startTime) + " ms");
		
		return true;
	}
	
	private boolean isRunning = false;
	public void scanAllFunctions(SMClass table) {
		if(isRunning) throw new IllegalArgumentException("The evaluater is already running!");
		isRunning = true;
		
		ScrapMechanicWindowProvider provider = plugin.getWindow();
		List<SMClass.Function> functions = table.getAllFunctions();
		
		final ConcurrentLinkedQueue<SMClass.Function> queue = new ConcurrentLinkedQueue<>(
			// This will remove all functions that link to the same address.
			Set.copyOf(functions)
		);
		final int originalSize = queue.size();
		final Map<String, TracedFunction> mappings = new HashMap<>();
		
		provider.setProgressBar(0);
		
		ThreadGroup group = new ThreadGroup("SMDecompiler Group");
		List<Thread> threads = new ArrayList<>();
		
		final int numThreads = provider.getThreads();
		for(int i = 0; i < numThreads; i++) {
			final int id = i;
			final String workerName = String.format("[Worker ID#%2d]", id);
			Thread thread = new Thread(group, () -> {
				SMClass.Function pointer = null;
				
				try {
					while(!queue.isEmpty()) {
						pointer = queue.poll();
						if(pointer == null) break;
						
						TracedFunction trace = cstAnalyser.analyse(pointer);
						mappings.put(pointer.getAddress(), trace);
						pointer.setTrace(trace);
						provider.writeLog(workerName, "Exploring: " + pointer.toString());
						
						provider.setProgressBar((originalSize - queue.size()) / (0.0 + originalSize));
					}
				} catch(Exception e) {
					e.printStackTrace();
				}

				provider.writeLog(workerName, "Done!");
			});
			thread.setName("Worker ID#" + id);
			thread.start();
			
			threads.add(thread);
		}
		
		for(Thread thread : threads) {
			try {
				thread.join();
			} catch(InterruptedException e) {
				e.printStackTrace();
			}
		}
		
		for(SMClass.Function function : functions) {
			TracedFunction trace = mappings.get(function.getAddress());
			if(trace != null) {
				function.setTrace(trace);
			}
		}
		
		provider.setProgressBar(1);
	}
	
	public String getLastError() {
		return errorMessage;
	}
}
