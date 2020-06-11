package sm.complex;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskDialog;
import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.importer.PointerFinder;
import sm.util.CacheUtil;
import sm.util.Util;


public class ScrapMechanic {
	public static final int DECOMPILE_TIMEOUT = 10;
	public static final int DECOMPILE_THREADS = 14;
	public static final boolean SHOW_ADDRESS = false;
	public static final boolean TRACE = false;
	
	// TODO: Read this value from memory!
	public static final String VERSION = "4.3.5";
	
	private SMContainer container;
	public ScrapMechanic(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluated_test_2.ser")) {
			SMContainer container = CacheUtil.load("SMContainerEvaluated_test_2.ser");
			printTrace(container);
			
			return;
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
			
			// server
			// client
			// both
			// storage [Server Only]
			// terrainTile
			container = builder.calculate().build();
			
			CacheUtil.save("SMContainer_test.ser", container);
		}
	}
	
	private boolean evaluating;
	
	/**
	 * This function uses a {@link ConcurrentLinkedQueue} to distribute decompile calls over multiple threads.
	 * This function is blocking.
	 * 
	 */
	public synchronized void evaluate() {
		if(container == null) return;
		if(evaluating) throw new IllegalAccessError("Is already running!");
		evaluating = true;
		
		Set<SMFunctionObject> functions = container.getAllFunctions();
		Set<FunctionPointer> unique = functions.stream().map((a) -> { return new FunctionPointer(a); }).collect(Collectors.toSet());
		
		final ConcurrentLinkedQueue<FunctionPointer> queue = new ConcurrentLinkedQueue<FunctionPointer>(unique);
		final Map<String, FuzzedFunction> mappings = new HashMap<>();
		
		// TODO: Cache the FuzzedFunctions so that if we try to decompile a function that
		//       we already have the code from. Just skip it and instantly just give it the
		//       FuzzedFunction.
		
		// TODO: If by somehow something makes everything crash and TaskDialog is not disposed
		//       Then the dialog will be blocking inputs and wont let the user do anything.
		TaskDialog monitor = new TaskDialog("Fuzzing all the functions", true, true, true);
		monitor.setMessage("Exploring functions");
		monitor.setShowProgressValue(true);
		monitor.clearCanceled();
		
		// 828
		// 1008
		monitor.initialize(unique.size());
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
		
		for(int i = 0; i < DECOMPILE_THREADS; i++) {
			final int id = i;
			Thread thread = new Thread(group, () -> {
				FunctionExplorer explorer = new FunctionExplorer();
				
				try {
					while(!queue.isEmpty()) {
						if(Util.isMonitorCancelled()) break;
						
						FunctionPointer pointer = queue.poll();
						if(pointer == null) break;
						
						//if(!pointer.name.equals("getRaycast")) continue;
						//if(!pointer.name.equals("play")) continue;
						//if(!pointer.name.equals("getPistons")) continue;
						//if(!pointer.name.equals("createCharacter")) continue;
						//if(!pointer.name.equals("getShapeUuid")) continue;
						//if(!pointer.name.equals("forceTool")) continue;
						// 006f76f0 -> destroy
						//if(!pointer.addr.equals("006f76f0")) continue;
						//if(!pointer.addr.equals("006e6850")) continue;
						
						System.out.printf("[Worker ID#%d]: Exploring: %s\n", id, pointer.addr + " -> " + pointer.name + "( --- );");
						FuzzedFunction fuzzed = explorer.evaluate(Util.getFunctionAt(pointer.addr));
						mappings.put(pointer.addr, fuzzed);
						monitor.incrementProgress(1);
						
						//System.out.println("FUZZED: "+ fuzzed.errors);
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
		
		for(SMFunctionObject object : functions) {
			String addr = object.getFunctionAddressString();
			FuzzedFunction fuzzed = mappings.get(addr);
			
			object.setFuzzedFunction(fuzzed);
		}
		
		evaluating = false;
		
		/*
		System.out.println();
		System.out.println("");
		for(SMFunctionObject function : functions) {
			if(function.getFuzzedFunction() == null) continue;
			System.out.println(function);
		}
		*/
		
		CacheUtil.save("SMContainerEvaluated_test_2.ser", container);
		printTrace(container);
	}
	
	private void printTrace(SMContainer container) {
		if(container == null) return;
		
		String traceString = container.toString();
		File traceFile = new File(CacheUtil.getResourcePath(), "dumps/lua." + VERSION + ".time." + System.currentTimeMillis() + ".txt");
		try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(traceFile))) {
			stream.write(traceString.getBytes());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}
	
	static class FunctionPointer {
		public final String name;
		public final String addr;
		
		public FunctionPointer(SMFunctionObject object) {
			name = object.getName();
			addr = object.getFunctionAddressString();
		}
		
		@Override
		public int hashCode() {
			return Integer.valueOf(addr, 16);
		}
		
		@Override
		public boolean equals(Object obj) {
			if(obj == null || !(obj instanceof FunctionPointer)) return false;
			return name.equals(((FunctionPointer)obj).name);
		}
	}
}
