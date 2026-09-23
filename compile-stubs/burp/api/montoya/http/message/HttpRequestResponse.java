package burp.api.montoya.http.message;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
public interface HttpRequestResponse {
    static HttpRequestResponse httpRequestResponse(HttpRequest request, HttpResponse response) { return null; }
}
