package burp.api.montoya.http.message.requests;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
public interface HttpRequest {
    static HttpRequest httpRequest(HttpService service, ByteArray request) { return null; }
}
