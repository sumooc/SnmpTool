package org.sumooc;

import org.snmp4j.mp.SnmpConstants;

import javax.swing.*;
import java.awt.*;
import java.util.Locale;
import java.util.Objects;

public class MainUI {
    private JPanel rootPanel;
    private JPanel SnmpSettings;
    private JTextField ipAddress;
    private JComboBox snmpVersionBox;
    private JComboBox authenticateProtocol;
    private JTextField authenticatePassword;
    private JComboBox encryptionProtocol;
    private JTextField encryptedPassword;
    private JTextField username;
    private JTextField port;
    private JTextField timeout;
    private JTextField retries;
    private JTextArea results;
    private JButton requestButton;
    private JTextField community;
    private JTextArea oIds;


    public MainUI() {
        requestButton.addActionListener(e -> {
            SnmpAgent snmpAgent = new SnmpAgent();
            SnmpParameter parameter = new SnmpParameter();
            parameter.setIpAddress(ipAddress.getText());
            parameter.setPort(Integer.parseInt(port.getText()));
            String snmpVersion = Objects.requireNonNull(snmpVersionBox.getSelectedItem()).toString();
            if ("SNMP v1".equals(snmpVersion)) {
                parameter.setSnmpVersion(SnmpConstants.version1);
            } else if ("SNMP v2c".equals(snmpVersion)) {
                parameter.setSnmpVersion(SnmpConstants.version2c);
            } else if ("SNMP v3".equals(snmpVersion)) {
                parameter.setSnmpVersion(SnmpConstants.version3);
            }
            parameter.setCommunity(community.getText());
            parameter.setAuthProtocol(Objects.requireNonNull(authenticateProtocol.getSelectedItem()).toString());
            parameter.setAuthPassphrase(authenticatePassword.getText());
            parameter.setPrivacyProtocol(Objects.requireNonNull(encryptionProtocol.getSelectedItem()).toString());
            parameter.setPrivacyPassphrase(encryptedPassword.getText());
            parameter.setSecurityName(username.getText());
            parameter.setOids(oIds.getText().split(","));
            parameter.setSnmpTimeout(Integer.parseInt(timeout.getText()));
            parameter.setSnmpRetry(Integer.parseInt(retries.getText()));
            try {
                Object snmpResult = snmpAgent.getSnmpResult(parameter);
                System.out.println(snmpResult.toString());
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }


    public void ToolGUI() {
        JFrame frame = new JFrame("SNMPTool");
        frame.setSize(900, 700);
        frame.setLocationRelativeTo(new Component() {
            @Override
            public Locale getLocale() {
                return super.getLocale();
            }
        });
        oIds.setWrapStyleWord(true);
        frame.setContentPane(new MainUI().rootPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }

}
