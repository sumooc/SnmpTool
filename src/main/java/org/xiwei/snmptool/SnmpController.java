package org.xiwei.snmptool;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;

import java.net.URL;
import java.util.ResourceBundle;

public class SnmpController implements Initializable {
    @FXML
    private TextField ipAddress;

    @FXML
    private TextField port;

    @FXML
    private ChoiceBox<String> version;

    @FXML
    private TextField community;

    @FXML
    private TextField username;

    @FXML
    private Label authProtocolLabel;

    @FXML
    private ChoiceBox<String> authProtocol;

    @FXML
    private Label authPasswordLabel;

    @FXML
    private TextField authPassword;

    @FXML
    private Label encryProtocolLabel;

    @FXML
    private ChoiceBox<String> encryProtocol;

    @FXML
    private Label encryPasswordLabel;

    @FXML
    private TextField encryPassword;

    @FXML
    private TextArea oid;

    @FXML
    private TextField overtime;

    @FXML
    private TextField retry;

    @FXML
    private Button commit;

    public String[] versionValue = {"SNMP v1", "SNMP v2c", "SNMP v3"};
    public String[] authProtocolValue = {"AES128", "AES192", "AES256", "DES", "3DES"};
    public String[] encryProtocolValue = {"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"};


    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        port.setText("161");
        community.setText("public");

        // SNMP版本
        version.getItems().addAll(versionValue);
        version.getSelectionModel().select(0);
        version.setOnAction(this::getVersion);
        // 认证协议
        authProtocol.getItems().addAll(authProtocolValue);
        authProtocol.getSelectionModel().select(0);
        authProtocol.setOnAction(this::getVersion);

        //加密协议
        encryProtocol.getItems().addAll(encryProtocolValue);
        encryProtocol.getSelectionModel().select(0);
        encryProtocol.setOnAction(this::getVersion);

        // 打开软件的时候默认是snmp v1 所以不显示认证和加密
        authProtocolLabel.setVisible(false);
        authProtocol.setVisible(false);
        authPasswordLabel.setVisible(false);
        authPassword.setVisible(false);
        encryProtocolLabel.setVisible(false);
        encryProtocol.setVisible(false);
        encryPasswordLabel.setVisible(false);
        encryPassword.setVisible(false);
    }

    public String getVersion(ActionEvent event) {
        return version.getValue().toString();
    }

    @FXML
    void click(MouseEvent event) {
        System.out.println(version.getSelectionModel().getSelectedItem());
        System.out.println(ipAddress.getText());
        System.out.println("11111111111");
    }

    @FXML
    void selectVersion(MouseEvent event){
        System.out.println(version.getValue());
    }

}
