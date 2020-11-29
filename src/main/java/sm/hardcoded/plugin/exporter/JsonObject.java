package sm.hardcoded.plugin.exporter;

public abstract class JsonObject {
	public abstract boolean isArray();
	public abstract boolean isMap();
	public abstract int getSize();
	
	public final JsonArray toArray() {
		return (JsonArray)this;
	}
	
	public final JsonMap toMap() {
		return (JsonMap)this;
	}
	
	public final String toString() {
		return toString(false);
	}
	
	public final String toString(boolean compact) {
		if(compact) return toCompactString();
		return toNormalString();
	}
	
	protected abstract String toCompactString();
	protected abstract String toNormalString();
}
