// @author HardCoded
//
// @category ScrapMechanicTracer
// @keybinding 
// @menupath 
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
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
		for(java.awt.Frame frame : java.awt.Frame.getFrames()) {
			if(frame.getClass().getName().equals(SMDialog.class.getName()) && frame.isDisplayable()) {
				// We shouldnt create a new window if we already have one.
				// Just request focus and put the window ontop.
				frame.requestFocus();
				return;
			}
		}
		
		DevUtil.replacePrintStreams(this);
		DevUtil.replaceGhidraBin(this);
		
		// Initialize the cache
		CacheUtil.init();
		
		if(true) {
			//FunctionExplorer2 func = new FunctionExplorer2();
			//return;
		}
		
		// Initialize the util and dialog
		SMDialog dialog = new SMDialog(this);
		Util.init(this, dialog);
		
		dialog.start();
		dialog.setStartAnalysisListener(new Runnable() {
			@Override
			public void run() {
				DataTypeManager manager = Util.getDataTypeManager();
				int transactionId = manager.startTransaction("ScrapMechanicTracer");
				
				try {
					start();
					
					// TODO: Only update if needed
					manager.endTransaction(transactionId, true);
				} catch(Exception e) {
					e.printStackTrace();
					
					// NOTE: Fallback stop if something thows an exception
					Util.getDialog().stopFuzzing();
					Util.getDialog().setVisible(false);
					Util.getDialog().dispose();
					Util.getMonitor().clearCanceled();
					// Util.getDialog().dispose();
					
					manager.endTransaction(transactionId, true);
				}
			}
			
			public void start() throws Exception {
				// TODO: Should we call these functions everytime we press 'Start Analysing' ???
				
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
