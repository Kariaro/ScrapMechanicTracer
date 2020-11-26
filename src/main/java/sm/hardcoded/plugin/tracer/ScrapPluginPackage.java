package sm.hardcoded.plugin.tracer;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class ScrapPluginPackage extends PluginPackage {
	public static final String NAME = "ScrapMechanicTracer";
	
	public ScrapPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/smt_icon_64.png"), "", FEATURE_PRIORITY);
	}
}
