package sm.complex;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import ghidra.program.model.address.Address;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskDialog;
import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.importer.PointerFinder;
import sm.util.CacheUtil;
import sm.util.Util;


public class SMStructure {
	public static final boolean SHOW_ADDRESS = true;
	public static final boolean TRACE = true;
	
	public static final int DECOMPILE_TIMEOUT = 10;
	
	private SMContainer container;
	
	public SMStructure(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluated_test.ser")) {
			//SMContainer container = CacheUtil.load("SMContainerEvaluated_test.ser");
			//printTrace(container);
			
			//return;
		}
		
		if(load) {
			container = CacheUtil.load("SMContainer_test.ser");
		}
		
		if(container == null) {
			SMContainerBuilder builder = SMContainerBuilder.create();
			
			Set<Address> pointers = PointerFinder.getStructures();
			for(Address pointer : pointers) {
				builder.loadSM(pointer.toString());
			}
			
			/*container = SMContainerBuilder.create()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.loadSM("010103c8") // terrainTile
				.calculate()
				.build();
			*/
			
			container = builder.calculate().build();
			
			CacheUtil.save("SMContainer_test.ser", container);
		}
	}
	
	private boolean evaluating;
	
	/**
	 * This function uses a {@link ConcurrentLinkedQueue} to distribute decompile
	 * calls  over multiple threads.
	 */
	public synchronized void evaluate() {
		//if(true) return;
		
		if(container == null) return;
		if(evaluating) throw new IllegalAccessError("Is already running!");
		evaluating = true;
		
		final int NUM_THREADS = 14;
		Set<SMFunctionObject> functions = container.getAllFunctions();
		final ConcurrentLinkedQueue<SMFunctionObject> queue = new ConcurrentLinkedQueue<SMFunctionObject>(functions);
		
		// TODO: If by somehow something makes everything crash and TaskDialog is not disposed
		//       Then the dialog will be blocking inputs and wont let the user do anything.
		TaskDialog monitor = new TaskDialog("Fuzzing all the functions", true, true, true);
		monitor.setMessage("Exploring functions");
		monitor.setShowProgressValue(true);
		monitor.clearCanceled();
		monitor.initialize(functions.size());
		monitor.setCancelEnabled(true);
		monitor.setIndeterminate(false);
		monitor.show(0);
		CancelledListener listener = new CancelledListener() {
			public void cancelled() {
				Util.getMonitor().cancel();
			}
		};
		monitor.addCancelledListener(listener);
		
		ThreadGroup group = new ThreadGroup("Evaluate Group");
		List<Thread> threads = new ArrayList<>();
		
		for(int i = 0; i < NUM_THREADS; i++) {
			final int id = i;
			Thread thread = new Thread(group, () -> {
				FunctionExplorer explorer = new FunctionExplorer();
				
				try {
					while(!queue.isEmpty()) {
						if(Util.isMonitorCancelled()) break;
						
						SMFunctionObject obj = queue.poll();
						if(obj == null) break;
						//if(!obj.getName().equals("getRaycast")) continue;
						//if(!obj.getName().equals("play")) continue;
						//if(!obj.getName().equals("getPistons")) continue;
						if(!obj.getName().equals("createCharacter")) continue;
						System.out.printf("[Worker ID#%d]: Exploring: %s\n", id, obj);
						explorer.evaluate(obj);
						monitor.incrementProgress(1);
					}
				} catch(Exception e) {
					e.printStackTrace();
				}
				
				// THIS IS IMPORTANT
				explorer.close();
				
				System.out.printf("[Worker ID#%d]: Done!\n", id);
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
		
		monitor.removeCancelledListener(listener);
		monitor.dispose();
		monitor.close();
		
		evaluating = false;
		
		System.out.println();
		System.out.println("");
		for(SMFunctionObject function : functions) {
			if(function.getFuzzedFunction() == null) continue;
			System.out.println(function);
		}
		
		CacheUtil.save("SMContainerEvaluated_test.ser", container);
		printTrace(container);
	}
	
	private void printTrace(SMContainer container) {
		if(container == null) return;
		
		String traceString = container.toString();
		File traceFile = new File(CacheUtil.getResourcePath(), "trace_test.txt");
		try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(traceFile))) {
			stream.write(traceString.getBytes());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}
}
