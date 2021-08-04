package burp;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

abstract public class ActionListenerDecorator implements ActionListener {
    private ActionListener actionListener;

    public ActionListenerDecorator(ActionListener actionListener) {
        this.actionListener = actionListener;
    }

    @Override
    public void actionPerformed(ActionEvent arg) {
        decorator(arg);
        this.actionListener.actionPerformed(arg);
    }

    abstract public void decorator(ActionEvent arg);
}
