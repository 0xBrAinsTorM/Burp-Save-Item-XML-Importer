package burp.api.montoya;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
public interface MontoyaApi {
    Extension extension();
    Logging logging();
    SiteMap siteMap();
    UserInterface userInterface();
}
