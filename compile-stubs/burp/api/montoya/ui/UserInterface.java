package burp.api.montoya.ui;
import burp.api.montoya.core.Registration;
import java.awt.Component;
public interface UserInterface {
    void applyThemeToComponent(Component component);
    Registration registerSuiteTab(String title, Component component);
}
