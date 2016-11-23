package cranium;

import burp.*;

import javax.swing.*;

public class MessageEditor extends JTabbedPane implements IMessageEditorController {

	private IHttpRequestResponse currentlyDisplayedItem;
	private final IMessageEditor requestViewer;
	private final IMessageEditor responseViewer;


	public MessageEditor(IBurpExtenderCallbacks callbacks) {
		super();
		requestViewer = callbacks.createMessageEditor(this, false);
		responseViewer = callbacks.createMessageEditor(this, false);
		addTab("Request", requestViewer.getComponent());
		addTab("Response", responseViewer.getComponent());
	}

	@Override
	public byte[] getRequest() {
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService() {
		return currentlyDisplayedItem.getHttpService();
	}

	public IHttpRequestResponse getCurrentlyDisplayedItem() {
		return currentlyDisplayedItem;
	}

	public void setCurrentlyDisplayedItem(IHttpRequestResponse currentlyDisplayedItem) {
		requestViewer.setMessage(currentlyDisplayedItem.getRequest(), true);
		responseViewer.setMessage(currentlyDisplayedItem.getResponse(), false);
		this.currentlyDisplayedItem = currentlyDisplayedItem;
	}
}
