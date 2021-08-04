package burp;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class LoggedActionListener extends ActionListenerDecorator {
    private Writer writer;

    public LoggedActionListener(ActionListener actionListener, Writer writer) {
        super(actionListener);
        this.writer = writer;
    }

    @Override
    public void decorator(ActionEvent arg) {
        this.writer.printlnOut("actionEvent: "+arg.paramString());
    }
}
