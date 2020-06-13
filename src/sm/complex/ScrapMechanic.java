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
import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.gui.SMDialog;
import sm.importer.PointerFinder;
import sm.util.CacheUtil;
import sm.util.Util;


public final class ScrapMechanic {
	public static final String ROOT_NAME = "ScrapMechanic.exe";
	public static final String LIBRARY_NAME = "LUA51.DLL";
	
	public static final String REFERENCES_MEMORY_BLOCK = ".data";
	public static final String STRINGS_MEMORY_BLOCK = ".rdata";
	
	public static int DECOMPILE_MAX_DEPTH = 3;
	public static int DECOMPILE_TIMEOUT = 10;
	public static int DECOMPILE_THREADS = 14;
	
	/* DEBUG VALUES */
	public static final boolean SHOW_ADDRESS = false;
	public static final boolean TRACE = false;
	
	
	private SMContainer container;
	public ScrapMechanic(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluated_test_2.ser")) {
			//SMContainer container = CacheUtil.load("SMContainerEvaluated_test_2.ser");
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
			
			// server, client, both, storage, terrainTile
			container = builder.calculate().build();
			
			CacheUtil.save("SMContainer_test.ser", container);
		}
	}
	
	private boolean evaluating;
	
	/**
	 * This function uses a {@link ConcurrentLinkedQueue} to distribute decompile calls over multiple threads.
	 * This function is blocking.
	 */
	public synchronized void evaluate() {
		if(container == null) return;
		if(evaluating) throw new IllegalAccessError("The evaluater is already running!");
		evaluating = true;
		
		DECOMPILE_THREADS = CacheUtil.getProperty("decompiler.threads", Runtime.getRuntime().availableProcessors() - 1, Integer::valueOf);
		DECOMPILE_MAX_DEPTH = CacheUtil.getProperty("decompiler.maxDepth", 3, Integer::valueOf);
		DECOMPILE_TIMEOUT = CacheUtil.getProperty("decompiler.timeout", 10, Integer::valueOf);
		
		Set<SMFunctionObject> functions = container.getAllFunctions();
		Set<FunctionPointer> unique = functions.stream().map((a) -> { return new FunctionPointer(a); }).collect(Collectors.toSet());
		
		final ConcurrentLinkedQueue<FunctionPointer> queue = new ConcurrentLinkedQueue<FunctionPointer>(unique);
		final Map<String, AnalysedFunction> mappings = new HashMap<>();
		
		SMDialog monitor = Util.getDialog();
		monitor.setMaximumProgress(unique.size());
		monitor.setProgressIndex(0);
		
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
						
						// 006f76f0 -> destroy
						//if(!pointer.addr.equals("006f76f0")) continue;
						//if(!pointer.addr.equals("006e6850")) continue;
						
						System.out.printf("[Worker ID#%d]: Exploring: %s\n", id, pointer.addr + " -> " + pointer.name + "( --- );");
						AnalysedFunction fuzzed = explorer.evaluate(Util.getFunctionAt(pointer.addr));
						mappings.put(pointer.addr, fuzzed);
						
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
		
		monitor.stopFuzzing();
		
		for(SMFunctionObject object : functions) {
			String addr = object.getFunctionAddressString();
			AnalysedFunction fuzzed = mappings.get(addr);
			
			object.setAnalysedFunction(fuzzed);
		}
		
		evaluating = false;
		
		CacheUtil.save("SMContainerEvaluated_test_2.ser", container);
		printTrace(container);
	}
	
	private void printTrace(SMContainer container) {
		if(container == null) return;
		
		String traceString = container.toString();
		File traceFile = new File(CacheUtil.getTracePath(), "lua." + PointerFinder.getVersion() + ".time." + System.currentTimeMillis() + ".txt");
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
