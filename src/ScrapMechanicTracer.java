// @author HardCoded
//
// @category ScrapMechanicTracer
// @keybinding 
// @menupath 
// @toolbar 

import ghidra.app.script.GhidraScript;
import sm.complex.ScrapMechanic;
import sm.gui.SMDialog;
import sm.importer.Importer;
import sm.importer.PointerFinder;
import sm.util.CacheUtil;
import sm.util.LuaUtil;
import sm.util.Util;

/**
 * This ghidra script is used to print the ScrapMechanic lua structure to a file.
 * It will get the different functions and all the arguments to each function.
 * 
 * @author HardCoded
 */
public class ScrapMechanicTracer extends GhidraScript {
	public static final void main(String[] args) {
		System.out.println("[Hopefully this will get compiled :&]");
	}
	
	// NOTE: Currently it looks like the pre computing can be done without any analysis but the rest
	//       of the program needs analysis to complete.
	//
	// NOTE: Must analyse 'Decompile Parameter ID'
	// NOTE: ??? Does it need to analyse 'Function ID'
	
	public void run() throws Exception {
		DevUtil.replacePrintStreams(this);
		DevUtil.replaceGhidraBin(this);
		
		// Initialize the cache
		CacheUtil.init();
		
		// Initialize the util and dialog
		SMDialog dialog = new SMDialog(this);
		Util.init(this, dialog);
		
		dialog.start();
		dialog.setStartFuzzingListener(new Runnable() {
			@Override
			public void run() {
				try {
					start();
				} catch(Exception e) {
					e.printStackTrace();
				}
				
				// TODO: Fallback stop if something threw a exception
				// Util.getDialog().stopFuzzing();
			}
			
			public void start() throws Exception {
				// Initialize all imports
				Importer.init(ScrapMechanicTracer.this);
				
				// Load all lua functions
				LuaUtil.init(ScrapMechanicTracer.this);
				
				// Find all the structure pointers
				PointerFinder.init(ScrapMechanicTracer.this);
				
				
				// Start the application
				long start = System.currentTimeMillis();
				
				try {
					ScrapMechanic structure = new ScrapMechanic(false);
					
					structure.evaluate();
				} catch(Exception e) {
					e.printStackTrace();
				}
				
				String type_str = LuaUtil.getTypes().values().toString();
				type_str = type_str.substring(1, type_str.length() - 1);
				type_str = type_str.replace(", ", "\n  ");
				System.out.println("LuaTypes:\n  " + type_str + "\n");
				
				long ellapsed = System.currentTimeMillis() - start;
				println("Time ellapsed: " + ellapsed + " ms");
			}
		});
	}
}
