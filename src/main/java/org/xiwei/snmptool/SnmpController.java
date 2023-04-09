package org.xiwei.snmptool;

import javafx.fxml.FXML;
import javafx.scene.control.Label;

public class SnmpController {
    @FXML
    private Label welcomeText;

    @FXML
    protected void commit() {
        welcomeText.setText("Welcome to JavaFX Application!");
    }
}