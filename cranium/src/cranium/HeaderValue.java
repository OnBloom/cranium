package cranium;

import burp.IHttpRequestResponsePersisted;

import java.util.Objects;

class HeaderValue {
	final String value;
	final IHttpRequestResponsePersisted requestResponse;

	HeaderValue(String value, IHttpRequestResponsePersisted requestResponse) {
		this.value = value;
		this.requestResponse = requestResponse;

	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.value);
	}

	@Override
	public boolean equals(Object obj) {
		return obj != null && obj.getClass().equals(this.getClass()) && this.value.equals(((HeaderValue) obj).value);
	}
}
