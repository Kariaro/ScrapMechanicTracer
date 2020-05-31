package sm.complex;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections4.FunctorException;

import sm.SMClassObject;
import sm.SMContainer;
import sm.SMContainerBuilder;
import sm.SMFunctionObject;
import sm.SMObject;
import sm.util.CacheUtil;
import sm.util.LuaReg;
import sm.util.SMUtil;

public class SMStructure {
	public static final boolean SHOW_ADDRESS = true;
	public static final boolean TRACE = false;
	
	private SMContainer container;
	
	public SMStructure(boolean load) {
		if(CacheUtil.exists("SMContainerEvaluate.ser")) {
			//SMContainer container = CacheUtil.load("SMContainerEvaluate.ser");
			//printTrace(container);
		}
		
		
		try {
			// 006e2200
			// Load_sm_render
			LuaReg reg = new LuaReg("00fe3e10", "Load_sm_gui_interface", "006df3a0");
			SMObject smobj = SMUtil.loadSMObject(reg);
			
			SMContainer con = new SMContainer();
			SMClassObject clazz = con.addClass("sm.render");
			clazz.loadSettings(smobj);
			clazz.loadConstants(smobj);
			clazz.loadFunctions(smobj);
			
			
			Set<SMFunctionObject> functions = con.getAllFunctions();
			FunctionExplorer explorer = new FunctionExplorer();
			
			for(SMFunctionObject obj : functions) {
				System.out.printf("Exploring: %s\n", obj);
				explorer.evaluate(obj);
			}
			
			explorer.close();
			
			System.out.println(con.toString());
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		
		if(true) return;
		
		if(load) {
			container = SMContainer.loadCache();
		}
		
		if(container == null) {
			container = SMContainerBuilder.create()
				.loadSM("00fe35d8") // server
				.loadSM("00fe3dc8") // client
				.loadSM("00ff9888") // both
				.loadSM("00fe36a8") // storage [Server Only]
				.calculate()
				.build();
			
			SMContainer.saveCache(container);
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
		
		// TODO: This system does not distribute everything at maximum potential.
		
		final SMFunctionObject[] FUNCTIONS = container.getAllFunctions().toArray(SMFunctionObject[]::new);
		final int NUM_THREADS = 8;
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
				
				FunctionExplorer explorer = new FunctionExplorer();
				
				for(SMFunctionObject obj : objects) {
					System.out.printf("[Worker ID#%d]: Exploring: %s\n", id, obj);
					explorer.evaluate(obj);
				}
				
				// THIS IS IMPORTANT
				explorer.close();
				
				System.out.printf("[Worker ID#%d]: Done!\n", id);
				System.out.printf("[Worker ID#%d]: POS %d\n", id, objects.length);
			});
			thread.setName("Worker ID#" + id);
			thread.start();
			
			threads.add(thread);
		}
		
		System.out.println("Offset: " + offset);
		System.out.println("Size: " + FUNCTIONS.length);
		
		
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
		java.io.File traceFile = new java.io.File("C:\\Users\\Admin\\ghidra_scripts\\res\\trace.txt");
		try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(traceFile))) {
			stream.write(traceString.getBytes());
		} catch(IOException e) {
			e.printStackTrace();
		}
	}
}
