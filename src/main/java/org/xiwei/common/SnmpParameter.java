package org.xiwei.common;

public class SnmpParameter {

    public String ipAddress;
    /**
     * SNMP端口
     */
    public int port = 161;
    /**
     * snmp版本 1,2c,3
     */
    public int snmpVersion = 1;
    /**
     * OID
     */
    private String[] oIds;
    private String[] variables;
    private String[] types;
    /**
     * 1和2c版本的团体字名
     */
    private String community = "public";
    /**
     * USM username(用户名)
     */
    private String securityName;
    /**
     * 认证级别（包括不认证不加密，认证但不加密，认证且加密）
     */
    private int securityLevel = 3;
    /**
     * 认证协议
     */
    private int authProtocol;
    /**
     * 认证密钥
     */
    private String authPassphrase;
    /**
     * 加密协议
     */
    private int privacyProtocol;
    /**
     * 加密密钥
     */
    private String privacyPassphrase;
    /**
     * 重试次数
     */
    private int snmpRetry = 1;
    /**
     * 连接超时时间
     */
    private int snmpTimeout = 3000;
    /**
     * 采集方式代码
     */
    private int pduCode;

    public SnmpParameter() {
    }

    public String[] getOids() {
        return oIds;
    }

    public void setOids(String[] oids) {
        this.oIds = oids;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public int getSnmpVersion() {
        return snmpVersion;
    }

    public void setSnmpVersion(int snmpVersion) {
        this.snmpVersion = snmpVersion;
    }

    public String[] getoIds() {
        return oIds;
    }

    public void setoIds(String[] oIds) {
        this.oIds = oIds;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int getVersion() {
        return snmpVersion;
    }

    public void setVersion(int snmpVersion) {
        this.snmpVersion = snmpVersion;
    }

    public String getSecurityName() {
        return securityName;
    }

    public void setSecurityName(String securityName) {
        this.securityName = securityName;
    }

    public int getSecurityLevel() {
        return securityLevel;
    }

    public void setSecurityLevel(int securityLevel) {
        this.securityLevel = securityLevel;
    }

    public int getAuthProtocol() {
        return authProtocol;
    }

    public void setAuthProtocol(int authProtocol) {
        this.authProtocol = authProtocol;
    }

    public int getPrivacyProtocol() {
        return privacyProtocol;
    }

    public void setPrivacyProtocol(int privacyProtocol) {
        this.privacyProtocol = privacyProtocol;
    }

    public String getAuthPassphrase() {
        return authPassphrase;
    }

    public void setAuthPassphrase(String authPassphrase) {
        this.authPassphrase = authPassphrase;
    }

    public String getPrivacyPassphrase() {
        return privacyPassphrase;
    }

    public void setPrivacyPassphrase(String privacyPassphrase) {
        this.privacyPassphrase = privacyPassphrase;
    }

    public int getSnmpRetry() {
        return snmpRetry;
    }

    public void setSnmpRetry(int snmpRetry) {
        this.snmpRetry = snmpRetry;
    }

    public int getSnmpTimeout() {
        return snmpTimeout;
    }

    public void setSnmpTimeout(int snmpTimeout) {
        this.snmpTimeout = snmpTimeout;
    }

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public int getPduCode() {
        return pduCode;
    }

    public void setPduCode(int pduCode) {
        this.pduCode = pduCode;
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        try {
            sb.append("ip/port:").append(this.ipAddress).append("/").append(port).append(";version:").append(this.snmpVersion)
                    .append(";").append("oids:");
            if (this.oIds != null) {
                for (String oid : this.oIds) {
                    sb.append(oid).append(";");
                }
            }
        } catch (Exception e) {
            return null;
        }
        return sb.toString();
    }

    public String[] getVariables() {
        return variables;
    }

    public void setVariables(String[] variables) {
        this.variables = variables;
    }

    public String[] getTypes() {
        return types;
    }

    public void setTypes(String[] types) {
        this.types = types;
    }
}
