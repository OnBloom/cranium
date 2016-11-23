package burp;

import cranium.Cranium;


public class BurpExtender implements IBurpExtender {

	private Cranium cranium;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// set our extension name
		callbacks.setExtensionName("Cranium");
		cranium = new Cranium(callbacks);

	}


}
