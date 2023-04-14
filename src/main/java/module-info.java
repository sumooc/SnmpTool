module org.xiwei.snmptool {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;
    requires com.alibaba.fastjson2;
    requires org.apache.commons.lang3;
    requires org.snmp4j;
            
      /*  requires org.controlsfx.controls;
            requires com.dlsc.formsfx;
            requires net.synedra.validatorfx;
            requires org.kordamp.ikonli.javafx;
            requires org.kordamp.bootstrapfx.core;
            requires eu.hansolo.tilesfx;
            requires com.almasb.fxgl.all;*/

    opens org.xiwei.snmptool to javafx.fxml;
    exports org.xiwei.snmptool;
}