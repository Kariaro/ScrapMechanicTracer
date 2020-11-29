package sm.hardcoded.plugin.tracer;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.ResourceManager;

@PluginInfo(
	// Released because it's tested enough
	status = PluginStatus.RELEASED,
	category = PluginCategoryNames.ANALYSIS,
	packageName = ScrapPluginPackage.NAME,
	shortDescription = "This plugin finds the argument values for each lua function",
	description = "This plugin finds the argument values for each lua function",
	isSlowInstallation = false
)
public class ScrapMechanicPlugin extends ProgramPlugin implements FrontEndable {
	private ScrapMechanicWindowProvider provider;
	private ScrapMechanicBookmarkManager bookmarkManager;
	private ScrapMechanicAnalyser analyser;
	private ProgramMemory programMemory;
	
	private boolean scanning;
	private final SMPrefs preferences;
	
	final ImageIcon icon_64 = ResourceManager.loadImage("images/smt_icon_64.png");
	final ImageIcon icon_16 = ResourceManager.loadImage("images/smt_icon_16.png");
	
	public ScrapMechanicPlugin(PluginTool tool) {
		super(tool, false, false);
		
		preferences = new SMPrefs();
		provider = new ScrapMechanicWindowProvider(this);
		bookmarkManager = new ScrapMechanicBookmarkManager(this);
		analyser = new ScrapMechanicAnalyser(this);
		
		Logger.println("This should print if we are in development mode hopefully!!!!!!!");
		
		setupActions();
	}
	
	private void setupActions() {
		DockingAction action = new DockingAction("ScrapMechanicTracer", getName()) {
			public void actionPerformed(ActionContext context) {
				provider.setVisible(true);
			}
		};
		
		DockingWindowManager.getHelpService().excludeFromHelp(action);
		action.setToolBarData(new ToolBarData(icon_64));
		tool.addAction(action);
	}
	
	protected void programOpened(Program program) {
		updateScanOptions();
	}
	
	protected void programClosed(Program program) {
		updateScanOptions();
	}
	
	protected void programActivated(Program program) {
		updateScanOptions();
	}
	
	protected SMPrefs getPreferences() {
		return preferences;
	}
	
	protected boolean canClose() {
		return !scanning;
	}
	
	private void updateScanOptions() {
		if(provider != null) {
			provider.setScanEnabled(getCurrentProgram() != null);
			
			if(bookmarkManager != null) {
				provider.setResetScanEnabled(bookmarkManager.hasBookmarks());
			}
		}
	}
	
	public void init() {
		super.init();
		
		// FIXME: Reload this when to program changes always!!!
		programMemory = new ProgramMemory(this);
	}
	
	/**
	 * Start scanning the current program.
	 */
	public void startScan() {
		Thread thread = new Thread(() -> {
			int transactionId = -1;
			try {
				scanning = true;
				
				transactionId = currentProgram.startTransaction("ScrapMechanicPlugin - Scan");
				
				boolean result = analyser.startAnalysis();
				if(!result) {
					Msg.showError(this, provider.getComponent(), "Start analysis failed", analyser.getLastError());
				}
				
				currentProgram.endTransaction(transactionId, result);
			} catch(Throwable e) {
				StringWriter writer = new StringWriter();
				e.printStackTrace(new PrintWriter(writer));
				
				Msg.showError(this, provider.getComponent(), "Exception: " + e.getCause(), writer.toString());
				
				if(transactionId != -1) {
					currentProgram.endTransaction(transactionId, false);
				}
			} finally {
				updateScanOptions();
				scanning = false;
			}
		});
		
		thread.start();
	}
	
	public ScrapMechanicBookmarkManager getBookmarkManager() {
		return bookmarkManager;
	}
	
	public ScrapMechanicWindowProvider getWindow() {
		return provider;
	}
	
	public ProgramMemory getProgramMemory() {
		return programMemory;
	}
	
	protected void dispose() {
		super.dispose();
		provider.setVisible(false);
	}
}
