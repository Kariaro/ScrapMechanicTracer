package sm.complex;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.FunctorException;

import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.util.CacheUtil;

public class SMStructure {
	public static final boolean SHOW_ADDRESS = false;
	public static final boolean TRACE = false;
	
	private SMContainer container;
	
	public SMStructure(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluate.ser")) {
			SMContainer container = CacheUtil.load("SMContainerEvaluate.ser");
			printTrace(container);
			
			return;
		}
		
		if(true) return;
		
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
	public void evaluate() {
		if(container == null) return;
		//if(true) return;
		
		if(evaluating) throw new IllegalAccessError("Is already running!");
		evaluating = true;
		
		final SMFunctionObject[] FUNCTIONS = container.getAllFunctions().toArray(SMFunctionObject[]::new);
		final int NUM_THREADS = 14;
		final int SIZE = FUNCTIONS.length / NUM_THREADS;
		
		ThreadGroup group = new ThreadGroup("Evaluate Group");
		List<Thread> threads = new ArrayList<>();
		
		int left = FUNCTIONS.length - SIZE * NUM_THREADS;
		int offset = 0;
		for(int i = 0; i < NUM_THREADS; i++) {
			int sz = SIZE;
			
			if(i < left) {
				sz++;
			}
			
			final int obj_size = sz;
			final int obj_offset = offset;
			offset += sz;
			final int id = i;
			Thread thread = new Thread(group, () -> {
				SMFunctionObject[] objects = new SMFunctionObject[obj_size];
				System.arraycopy(FUNCTIONS, obj_offset, objects, 0, obj_size);
				
				FunctionExplorer3 explorer = new FunctionExplorer3();
				
				try {
					for(SMFunctionObject obj : objects) {
						System.out.printf("[Worker ID#%d]: Exploring: %s\n", id, obj);
						explorer.evaluate(obj);
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
		
		evaluating = false;
		
		System.out.println();
		System.out.println("");
		for(int i = 0; i < FUNCTIONS.length; i++) {
			SMFunctionObject function = FUNCTIONS[i];
			System.out.println(function);
		}
		
		CacheUtil.save("SMContainerEvaluate.ser", container);
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
