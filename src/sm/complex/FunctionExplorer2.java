package sm.complex;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;

public class FunctionExplorer2 extends DialogComponentProvider {
	public FunctionExplorer2() {
		super("ScrapMechanicTracer", false, false, true, true);
		
		DockingWindowManager.showDialog(this);
	}
}
