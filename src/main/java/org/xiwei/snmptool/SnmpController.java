package org.xiwei.snmptool;

import com.alibaba.fastjson2.JSON;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;
import org.apache.commons.lang3.StringUtils;
import org.xiwei.common.SnmpAgent;
import org.xiwei.common.SnmpParameter;

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

    @FXML
    private TextArea result;

    @FXML
    private GridPane basicInfo;

    public String[] versionValue = {"SNMP v1", "SNMP v2c", "SNMP v3"};
    public String[] authProtocolValue = {"AES128", "AES192", "AES256", "DES", "3DES"};
    public String[] encryProtocolValue = {"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"};

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        port.setText("161");
        community.setText("public");
        overtime.setText("3000");
        retry.setText("2");

        //自动换行
        oid.setWrapText(true);
        result.setWrapText(true);

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

        authProtocol.setDisable(true);
        authPassword.setDisable(true);
        encryProtocol.setDisable(true);
        encryPassword.setDisable(true);
        // 监听SNMP版本，控制界面上一些控件是否能使用
        version.getSelectionModel().selectedItemProperty().addListener((observableValue, oldValue, newValue) -> {
            int index = version.getSelectionModel().getSelectedIndex();
            if (index == 2) {
                username.setDisable(false);
                authProtocol.setDisable(false);
                authPassword.setDisable(false);
                encryProtocol.setDisable(false);
                encryPassword.setDisable(false);
            } else {
                username.setDisable(true);
                authProtocol.setDisable(true);
                authPassword.setDisable(true);
                encryProtocol.setDisable(true);
                encryPassword.setDisable(true);
            }
        });

    }

    public String getVersion(ActionEvent event) {
        return version.getValue();
    }

    @FXML
    void click(MouseEvent event) {
        SnmpAgent snmpAgent = new SnmpAgent();
        SnmpParameter parameter = new SnmpParameter();
        String ipAddressText = ipAddress.getText();
        if (StringUtils.isEmpty(ipAddressText)){
            commit.setOnAction(buttonEvent -> {
                Stage msgBox = new Stage();
                Group msgGroup = new Group();
                Scene scene1 = new Scene(msgGroup, 230, 50);

                Label label = new Label("IP地址不能为空");
                label.setLayoutX(80);
                label.setLayoutY(20);
                msgGroup.getChildren().add(label);

                msgBox.setScene(scene1);
                msgBox.show();
            });
        }
        parameter.setIpAddress(ipAddress.getText());
        int versionIndex = version.getSelectionModel().getSelectedIndex();
        if (versionIndex == 2) {
            parameter.setSnmpVersion(3);
            parameter.setAuthProtocol(authProtocol.getSelectionModel().getSelectedIndex());
            parameter.setAuthPassphrase(authPassword.getText());
            parameter.setPrivacyProtocol(encryProtocol.getSelectionModel().getSelectedIndex());
            parameter.setPrivacyPassphrase(encryPassword.getText());
        } else {
            parameter.setSnmpVersion(versionIndex);
        }
        parameter.setPort(Integer.parseInt(port.getText()));
        parameter.setCommunity(community.getText());
        parameter.setSecurityName(username.getText());
        String[] oidArr = oid.getText().split(",");
        parameter.setoIds(oidArr);
        parameter.setSnmpTimeout(Integer.parseInt(overtime.getText()));
        parameter.setSnmpRetry(Integer.parseInt(retry.getText()));
        try {
            String result = snmpAgent.getSnmpResult(parameter).toString();
            this.result.setText(result);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
