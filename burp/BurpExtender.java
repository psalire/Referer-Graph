package burp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.net.MalformedURLException;

import java.awt.Component;
import java.awt.LayoutManager;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonStructure;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Pattern reHeader;
    private Writer writer;
    private HttpHandler httpHandler;
    private String serverAddress;
    private String serverPort;
    private boolean isTrafficForwarded;
    private final String extensionName = "Referer Graph";

    private JPanel uiPanel = new JPanel();
    private GridBagConstraints uiGridConstraints = new GridBagConstraints();

    /**
    * implement IBurpExtender
    */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(this.extensionName);
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);

        this.callbacks = callbacks;
        this.burpHelpers = callbacks.getHelpers();
        this.reHeader = Pattern.compile("^(.+): (.+)$");
        this.writer = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.serverAddress = "localhost";
        this.serverPort = "8000";
        this.isTrafficForwarded = false;
        this.httpHandler = new HttpHandler(this.writer, this.serverAddress, this.serverPort);

        // Setup Burp UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run() {
                GridBagLayout uiGridLayout = new GridBagLayout();
                uiPanel = new JPanel(uiGridLayout);

                JToggleButton uiOnOffButton = new JToggleButton();
                uiOnOffButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg) {
                        writer.printlnOut("actionEvent: "+arg.paramString());
                        isTrafficForwarded = !isTrafficForwarded;
                        String forwardTrafficStatus = isTrafficForwarded ? "ON" : "OFF";
                        uiOnOffButton.setText("Forward Traffic: "+forwardTrafficStatus);
                    }
                });

                JPanel uiAddressPortPanel = new JPanel(new FlowLayout());
                JTextField uiAddressText = new JTextField(serverAddress, 10);
                JTextField uiPortText = new JTextField(serverPort, 4);
                JLabel uiAddressLabel = new JLabel("Referer Graph Server Address:Port");
                uiAddressLabel.setLabelFor(uiAddressText);
                uiAddressPortPanel.add(uiAddressLabel);
                uiAddressPortPanel.add(uiAddressText);
                uiAddressPortPanel.add(uiPortText);

                JButton uiApplyButton = new JButton();
                uiApplyButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg) {
                        writer.printlnOut("actionEvent: "+arg.paramString());
                        writer.printlnOut("Address: "+uiAddressText.getText());
                        writer.printlnOut("Port: "+uiPortText.getText());
                        httpHandler.setRequestEndpoint(uiAddressText.getText(), uiPortText.getText());
                    }
                });
                uiApplyButton.setText("Apply");

                addComponentAtCoor(0, 0, uiOnOffButton);
                addComponentAtCoor(0, 1, uiAddressPortPanel);
                addComponentAtCoor(0, 2, uiApplyButton);

                callbacks.customizeUiComponent(uiPanel);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                uiOnOffButton.doClick(); // Turn on forwarding
            }
        });
    }

    private void addComponentAtCoor(int x, int y, JComponent component) {
        this.uiGridConstraints.gridx = x;
        this.uiGridConstraints.gridy = y;
        this.uiPanel.add(component, this.uiGridConstraints);
    }

    /**
    * implement ITab
    */
    @Override
    public String getTabCaption() {
        return this.extensionName;
    }
    @Override
    public Component getUiComponent() {
        return this.uiPanel;
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !isTrafficForwarded) {
            return; // Only record requests with responses & if listening on
        }

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        IResponseInfo responseInfo = this.burpHelpers.analyzeResponse(messageInfo.getResponse());

        String requestBody = this.writer.jsonToString(
            Json.createObjectBuilder().addAll(
                JsonHelper.getRequestJson(requestInfo, this.writer)
            ).addAll(
                JsonHelper.getResponseJson(responseInfo, this.writer)
            ).build()
        );
        this.writer.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        this.writer.printlnOut("--------------------");
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.writer.printlnOut("[BurpExtender] Extension was unloaded");
    }
}
