// @author HardCoded
// @category ScrapMechanic
// @keybinding 
// @menupath 
// @toolbar 

import ghidra.app.script.GhidraScript;
import sm.util.LuaUtil;
import sm.util.Util;

public class PrintScrapMechanicStructure extends GhidraScript {
	private static final boolean DEV_RECOMPILE = true;
	
	public void run() throws Exception {
		DevUtil.replacePrintStreams(this);
		
		try {
			if(DEV_RECOMPILE) {
				println("Recompiling script [ DEV_RECOMPILE = true ]");
				DevUtil.recompileAllScriptFiles();
			}
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
		
		// Allow the user to close this script if it takes
		// to long to execute
		final Thread sm_thread = Thread.currentThread();
		@SuppressWarnings("deprecation")
		Thread thread = new Thread(sm_thread.getThreadGroup(), () -> {
			try {
				while(!monitor.isCancelled()) Thread.sleep(20);
			} catch(InterruptedException e) {
				
			}
			
			sm_thread.stop();
		});
		thread.setDaemon(true);
		thread.start();
		
		
		// Initialize the util
		Util.init(this);
		
		// Load all lua functions
		LuaUtil.init(this);
		
		
		
		println("--------------------------------------------------------------------------");
		
		long start = System.currentTimeMillis();
		ProgramStart.start();
		
		long ellapsed = System.currentTimeMillis() - start;
		println("Time ellapsed: " + ellapsed + " ms");

		println("--------------------------------------------------------------------------");
	}
}
                                  