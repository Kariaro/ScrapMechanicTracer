package sm.complex;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.collections4.FunctorException;

import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskDialog;
import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.util.CacheUtil;
import sm.util.Util;

public class SMStructure {
	public static final boolean SHOW_ADDRESS = false;
	public static final boolean TRACE = false;
	
	public static final int DECOMPILE_TIMEOUT = 10;
	
	private SMContainer container;
	
	public SMStructure(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluated.ser")) {
			//SMContainer container = CacheUtil.load("SMContainerEvaluated.ser");
			//printTrace(container);
			
			//return;
		}
		
		if(load) {
			container = CacheUtil.load("SMContainer.ser");
		}
		
		if(container == null) {
			container = SMContainerBuilder.create()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.loadSM("010103c8") // terrainTile
				.calculate()
				.build();
			
			CacheUtil.save("SMContainer.ser", container);
		}
		
	}
	
	/**
	 * This container is just a empty structure that needs to be evaluated by
	 * a {@link FunctorException} before it is usable.
	 * 
	 * @return SMContainer
	 */
	public SMContainer getContainer() {
		return container;
	}
	
	private boolean evaluating;
	
	/**
	 * This function uses a {@link ConcurrentLinkedQueue} to distribute the functions
	 * to decompile equally over multiple threads.
	 */
	public synchronized void evaluate() {
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
				FunctionExplorer3 explorer = new FunctionExplorer3();
				
				try {
					while(!queue.isEmpty()) {
						if(Util.isMonitorCancelled()) break;
						
						SMFunctionObject obj = queue.poll();
						if(obj == null) break;
						
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
		
		CacheUtil.save("SMContainerEvaluated.ser", container);
		printTrace(container);
	}
	
	private void printTrace(SMContainer container) {
		if(container == null) return;
		
		String traceString = container.toString();
		File traceFile = new File(CacheUtil.getResourcePath(), "trace.txt");
		try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(traceFile))) {
			stream.write(traceString.getBytes());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}
}
