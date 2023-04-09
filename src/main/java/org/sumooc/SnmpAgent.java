package org.sumooc;


import org.apache.commons.lang3.StringUtils;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.*;

import java.io.IOException;
import java.util.*;

public class SnmpAgent {

    /**
     * SNMP Walk 代码
     */
    public static final int GETSUBTREE = -92;
    public static final int GETTABLE = -93;
    /**
     * 不正确尝试次数
     */
    public static final int INVALID_TRY_COUNT = 1;
    /**
     * 针对snmpget的行为的返回值，将oid中的索引提取出来，放到返回值的该key的值里。
     */
    public static final String INDEX_COLUMN_NAME = "snmp_index";
    private static final int NONREPEATERS = 0;
    private static final int MAXREPETITIONS = 10;
    private static final String AES256 = "AES-256";
    private static final String AES192 = "AES-192";
    private static final String AES128 = "AES-128";
    private static final String _3DES = "3DES";
    private static final String DES = "DES";
    private static final String MD5 = "MD5";
    private static final String SHA = "SHA";
    private static final String SHA224 = "SHA-224";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    private static final String GBK = "GBK";
    private static final String A1_67 = "a1:67";
    private static final String REGEX_TEXT = ":";
    /**
     * 十六进制整数
     */
    private static final int HEX_TEXT = 16;
    /**
     * walk成功
     */
    private static final int WALK_SUCCESS = 0;
    /**
     * walk超时
     */
    private static final int WALK_TIMEOUT = 2;
    /**
     * OID无效
     */
    private static final int WALK_OID_INVALID = 1;
    private static String[] convertToString = new String[]{
            "1.3.6.1.2.1.2.2.1.2.", "1.3.6.1.2.1.25.2.3.1.3.",
            "1.3.6.1.2.1.1.5.", "1.3.6.1.2.1.17.7.1.4.3.1.1.",
            "1.3.6.1.2.1.31.1.1.1.18.", "1.3.6.1.4.1.4881.1.1.10.2.9.1.7.1.3.",
            "1.3.6.1.4.1.4881.1.1.10.2.9.1.5.1.4."};

    private TransportMapping<UdpAddress> transportMapping;
    private Snmp snmp = null;
    private PDUFactory getNextPDUFactory;
    private PDUFactory getBulkPDUFactory;

    public SnmpAgent() {
        try {
            transportMapping = new DefaultUdpTransportMapping();
            ((DefaultUdpTransportMapping) transportMapping).setReceiveBufferSize(50 * 1024 * 1024); // 50MB
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
                    MPv3.createLocalEngineID(new OctetString("MyUniqueID" + System.currentTimeMillis()))), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            snmp = new Snmp();
            snmp.addTransportMapping(transportMapping);
            SecurityProtocols.getInstance().addDefaultProtocols();
            snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
            snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
            snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));
            snmp.getMessageDispatcher().addCommandResponder(snmp);
            snmp.listen();

            getNextPDUFactory = new DefaultPDUFactory(PDU.GETNEXT);
            getBulkPDUFactory = new DefaultPDUFactory(PDU.GETBULK);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * 获取SNMP数据
     */
    public Object getSnmpResult(SnmpParameter snmpParameter) throws Exception {
        Target target = null;
        if (snmpParameter.getVersion() == SnmpConstants.version3) { // snmp v3
            target = new UserTarget();
            target.setSecurityLevel(snmpParameter.getSecurityLevel());
            final OctetString securityName = new OctetString(snmpParameter.getSecurityName());
            OctetString authPassphrase = null;
            OctetString privacyPassphrase = null;
            OID authProtocol = null;
            OID privacyProtocol = null;
            // 认证加密
            if (StringUtils.isNotBlank(snmpParameter.getAuthPassphrase())
                    && snmpParameter.getSecurityLevel() != SecurityLevel.NOAUTH_NOPRIV) {
                authPassphrase = new OctetString(snmpParameter.getAuthPassphrase());
                if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), MD5)) {
                    authProtocol = AuthMD5.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), SHA)) {
                    authProtocol = AuthSHA.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), SHA224)) {
                    authProtocol = AuthHMAC128SHA224.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), SHA256)) {
                    authProtocol = AuthHMAC192SHA256.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), SHA384)) {
                    authProtocol = AuthHMAC256SHA384.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getAuthProtocol(), SHA512)) {
                    authProtocol = AuthHMAC384SHA512.ID;
                }
            }
            // 加密算法
            if (StringUtils.isNotBlank(snmpParameter.getPrivacyPassphrase())
                    && snmpParameter.getSecurityLevel() == SecurityLevel.AUTH_PRIV) {
                privacyPassphrase = new OctetString(snmpParameter.getPrivacyPassphrase());
                if (StringUtils.equalsIgnoreCase(snmpParameter.getPrivacyProtocol(), DES)) {
                    privacyProtocol = PrivDES.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getPrivacyProtocol(), _3DES)) {
                    privacyProtocol = Priv3DES.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getPrivacyProtocol(), AES128)) {
                    privacyProtocol = PrivAES128.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getPrivacyProtocol(), AES192)) {
                    privacyProtocol = PrivAES192.ID;
                } else if (StringUtils.equalsIgnoreCase(snmpParameter.getPrivacyProtocol(), AES256)) {
                    privacyProtocol = PrivAES256.ID;
                }
            }
            target.setSecurityName(securityName);
            UsmUser user = new UsmUser(securityName, authProtocol, authPassphrase, privacyProtocol, privacyPassphrase);
            snmp.getUSM().addUser(securityName, user);
        } else {// snmp v1 or v2c
            target = new CommunityTarget();
            ((CommunityTarget<?>) target).setCommunity(new OctetString(snmpParameter.getCommunity()));
        }
        Address address = new UdpAddress(snmpParameter.getIpAddress() + "/" + snmpParameter.getPort());

        target.setAddress(address);
        // 通信不成功时的重试次数
        target.setRetries(snmpParameter.getSnmpRetry());
        // 超时时间
        target.setTimeout(snmpParameter.getSnmpTimeout());
        // 版本
        target.setVersion(snmpParameter.getVersion());

        Map<String, List<String>> oidResultValueMaps = new HashMap<String, List<String>>();
        // set PDU
        String[] oids = snmpParameter.getOids();
        if (snmpParameter.getPduCode() == PDU.SET) {
            PDU pdu = (snmpParameter.getVersion() == SnmpConstants.version3) ? (new ScopedPDU()) : (new PDU());
            pdu.setType(PDU.SET);
            String[] variables = snmpParameter.getVariables();
            String[] types = snmpParameter.getTypes();
            for (int i = 0; i < oids.length; ++i) {
                String oid = oids[i];
                String variable = variables[i];
                String type = types[i];
                pdu.add(new VariableBinding(new OID(oid), getVariable(variable, type)));
            }
            ResponseEvent responseEvent = snmp.send(pdu, target);
            if (responseEvent.getError() != null)
                throw responseEvent.getError();
            PDU response = responseEvent.getResponse();
            if (response.getErrorStatus() != PDU.noError)
                throw new RuntimeException(response.getErrorStatus() + ":" + response.getErrorStatusText());
            List<? extends VariableBinding> variableBindings = response.getVariableBindings();
            for (VariableBinding variableBinding : variableBindings) {
                if (!variableBinding.isException()) {
                    String oid = variableBinding.getOid().toString();
                    oidResultValueMaps.computeIfAbsent(oid, k -> new ArrayList<String>());
                    List<String> result = oidResultValueMaps.get(oid);
                    result.add(variableBinding.getVariable().toString());
                }
            }
        } else if (snmpParameter.getPduCode() == PDU.GET || snmpParameter.getPduCode() == PDU.GETNEXT) {
            for (String oid : oids) {
                // Get或者GetNext分别去请求,因为可能存在多个oid以：进行顺序尝试的情况
                String[] singleOids = oid.split(REGEX_TEXT);
                for (String singleOid : singleOids) {
                    if (singleOid.matches("(\\d+\\.)+\\d+")) {
                        PDU pdu = (snmpParameter.getVersion() == SnmpConstants.version3) ? (new ScopedPDU())
                                : (new PDU());
                        pdu.add(new VariableBinding(new OID(singleOid)));
                        pdu.setType(snmpParameter.getPduCode());
                        boolean isSuccess = snmpGetOrGetNext(pdu, target, oidResultValueMaps, singleOid, oid);
                        List<String> oidListValuesList = oidResultValueMaps.get(oid);
                        if (oidListValuesList != null) {
                            oidListValuesList.removeIf(StringUtils::isBlank);
                        }
                        if (isSuccess) {
                            continue;
                        }
                    } else { // 设置默认值
                        List<String> values = new ArrayList<String>(1);
                        values.add(singleOid);
                        oidResultValueMaps.put(oid, values);
                    }
                }
            }
        } else if (snmpParameter.getPduCode() == PDU.GETBULK) {// snmp块读取
            List<String> list = new ArrayList<>(oids.length);
            Collections.addAll(list, oids);
            Map<String, Map<String, String>> datas = new HashMap<String, Map<String, String>>();
            snmpGetBulk(target, datas, list, oids);
            if (!datas.isEmpty()) {
                Set<String> keySet = datas.keySet();
                for (String next : keySet) {
                    if (StringUtils.isNotBlank(next)) {
                        try {
                            Collection<String> collection = datas.get(next).values();
                            List<String> valueList = new ArrayList<String>(collection);
                            oidResultValueMaps.put(next, valueList);
                        } catch (Exception e) {
                            System.out.println(e.getMessage());
                        }
                    }
                }
            }
        } else if (snmpParameter.getPduCode() == GETSUBTREE) {
            for (String oid : oids) {
                getSubtree(target, oid, oidResultValueMaps);
            }
        } else if (snmpParameter.getPduCode() == GETTABLE) {
            return getTable(target, oids);
        } else {
            snmpWalk(target, oidResultValueMaps, oids);
        }
        return oidResultValueMaps;
    }

    private Variable getVariable(String variable, String type) {
        switch (type) {
            case "OctetString":
                return new OctetString(variable);
            case "Counter32":
                return new Counter32(Long.parseLong(variable));
            case "Counter64":
                return new Counter64(Long.parseLong(variable));
            case "Integer32":
                return new Integer32(Integer.parseInt(variable));
            case "Gauge32":
                return new Gauge32(Long.parseLong(variable));
            default:
                throw new IllegalArgumentException("Invalid type: " + type);
        }
    }

    /**
     * snmp get or getnext operation
     *
     * @param pdu
     * @param target
     * @param oidResultValueMaps
     * @param requestOid
     * @param initOid
     * @return
     * @throws IOException
     */
    private boolean snmpGetOrGetNext(PDU pdu, Target target, Map<String, List<String>> oidResultValueMaps,
                                     String requestOid, String initOid) throws IOException {
        // 向Agent发送PDU，并返回Response
        ResponseEvent e = snmp.send(pdu, target);
        if (e == null || e.getResponse() == null) {
            // 重新采集一次
            ResponseEvent again = snmp.send(pdu, target);
            if (again == null || again.getResponse() == null) {
                return false;
            }
        }
        if (e != null && e.getResponse() != null) {
            List<? extends VariableBinding> bindings = e.getResponse().getVariableBindings();
            resolveSnmpReturnValue(oidResultValueMaps, pdu.getType(), bindings, requestOid, initOid);
            return true;
        } else {
            return false;
        }

    }

    /**
     * SNMP walk方法,只walk一层节点
     *
     * @param target
     * @param oidResultValueMaps
     * @param oids
     * @throws IOException
     */
    private void snmpWalk(Target target, Map<String, List<String>> oidResultValueMaps, String[] oids){
        // Walk多个oid
        for (String oid : oids) {
            // 可能存在多个oid以：进行分割的情况
            String[] singleOids = oid.split(REGEX_TEXT);
            /*
             * 关于默认值的设置问题。如果是oid无效的情况下，则设置默认值。如果是因为超时等问题，设置默认值为null。
             * successType: 0表示成功；1表示oid无效；2表示walk超时等问题
             */
            int successType = WALK_SUCCESS; // snmp walk是否成功
            for (String singleOid : singleOids) {
                // 用于统计执行GetNext的操作次数。一般情况下至少两次操作才能判断操作正常结束。如果只有一次即结束，表明该oid无效。需要设置默认值
                int getNextCount = 0;
                if (singleOid.matches("(\\d+\\.)+\\d+")) {

                    PDU requestPDU = null;
                    if (target.getVersion() == SnmpConstants.version3) {// snmpv3
                        requestPDU = new ScopedPDU();
                    } else
                        requestPDU = new PDU();
                    requestPDU.add(new VariableBinding(new OID(singleOid)));
                    OID targetOID = requestPDU.get(0).getOid();
                    requestPDU.setType(PDU.GETNEXT);
                    try {
                        boolean finished = false;
                        while (!finished) {
                            ResponseEvent responseEvent = snmp.send(requestPDU, target);
                            getNextCount++;
                            if (responseEvent != null && responseEvent.getResponse() != null) {
                                PDU responsePDU = responseEvent.getResponse();
                                VariableBinding firstColumnVar = responsePDU.get(0);
                                finished = isEndWalk(firstColumnVar, targetOID, responsePDU);
                                if (!finished) {
                                    // Dump response.
                                    List<? extends VariableBinding> bindings = responsePDU.getVariableBindings();
                                    // Set up the variable binding for the next
                                    resolveSnmpReturnValue(oidResultValueMaps, PDU.GETNEXT, bindings, singleOid, oid);
                                    requestPDU.setRequestID(new Integer32(0));
                                    for (int i = 0; i < bindings.size(); i++) {
                                        VariableBinding variableBinding = bindings.get(i);
                                        requestPDU.set(i, variableBinding);
                                    }
                                } else if (getNextCount == INVALID_TRY_COUNT) {// 表示只get
                                    // next一次即结束，oid无效
                                    successType = WALK_OID_INVALID;
                                }
                            } else {
                                successType = WALK_TIMEOUT;
                                finished = true;
                            }
                        }
                    } catch (IOException e) {
                        System.out.println(e.getMessage());
                    }
                } else { // 设置默认值,再有默认值的情况下
                    // 索引值个数,根据索引值得个数来设置默认值的个数
                    int indexSize = 1;
                    if (oidResultValueMaps.get(INDEX_COLUMN_NAME) != null)
                        indexSize = oidResultValueMaps.get(INDEX_COLUMN_NAME).size();
                    List<String> defaultValues = new ArrayList<String>(indexSize);
                    for (int i = 0; i < indexSize; i++)
                        defaultValues.add(successType == WALK_TIMEOUT ? null : singleOid);
                    oidResultValueMaps.put(oid, defaultValues);
                }
                if (successType == WALK_SUCCESS)
                    break;
            }
        }
    }

    /**
     * The GETBULK operation merely requests a number of GETNEXT responses to be
     * returned in a single packet rather than having to issue multiple GETNEXTs
     * to retrieve all the data that is needed. This is generally more efficient
     * with network bandwidth and also allows an agent to optimize how it
     * retrieves the data from the MIB instrumentation. However, there is also
     * the possibility of an overrun, which means to get back more data than was
     * needed because parts of the MIB tree that wasn't required were returned
     * as well.The expected returned PDU will be a RESPONSE, although a REPORT
     * may be issued as well in certain SNMPv3 circumstances.
     *
     * @param target   目前机器封装信息
     * @param datas    oid对应采集回来的结果集
     * @param rootOids 根oid
     * @loopOids 循环子oid，因为需要是递归去取oid，所以这个集合是动态的
     */
    private void snmpGetBulk(Target target, Map<String, Map<String, String>> datas,
                             Collection<String> loopOids, String[] rootOids) throws IOException {
        PDU requestPDU = null;
        if (target.getVersion() == SnmpConstants.version3) {// snmpv3
            requestPDU = new ScopedPDU();
        } else
            requestPDU = new PDU();
        for (String oid : loopOids) {
            requestPDU.add(new VariableBinding(new OID(oid)));
        }
        requestPDU.setType(PDU.GETBULK);
        requestPDU.setMaxRepetitions(MAXREPETITIONS);
        requestPDU.setNonRepeaters(NONREPEATERS);

        Map<String, String> currentOids = new HashMap<String, String>();// 用于下次循环的oid
        for (String rootOID : rootOids) {
            if (!datas.containsKey(rootOID)) {
                datas.put(rootOID, new LinkedHashMap<String, String>());
            }
            currentOids.put(rootOID, rootOID);
        }

        if (!datas.containsKey(INDEX_COLUMN_NAME)) {
            datas.put(INDEX_COLUMN_NAME, new LinkedHashMap<String, String>());
        }

        try {
            ResponseEvent responseEvent = snmp.send(requestPDU, target);
            PDU response = responseEvent.getResponse();
            if (response != null && response.getErrorIndex() == PDU.noError
                    && response.getErrorStatus() == PDU.noError) {
                // Dump response.
                List<? extends VariableBinding> bindings = response.getVariableBindings();
                /*
                 * get bullk返回块数据，所以需要和原始OID进行挨个对比，如果当前返回块没有原始OID的数据，那么就丢弃当前OID，
                 * 直到所有的原始OID都walk结束。
                 */
                List<String> overRootOids = new ArrayList<String>(rootOids.length);
                for (String rootOid : rootOids) {
                    boolean isEnd = true; // 标志当前rootOid是否walk结束
                    for (VariableBinding bind : bindings) {
                        String key = bind.getOid().toString();
                        if (StringUtils.startsWith(key, rootOid)
                                && !isEndWalk(bind, new OID(rootOid), response)) {
                            isEnd = false;
                            String value = getValue(key, bind.getVariable());
                            String index = key.substring(rootOid.length() + 1);
                            if (!datas.get(INDEX_COLUMN_NAME).containsKey(index))
                                datas.get(INDEX_COLUMN_NAME).put(index, index);
                            datas.get(rootOid).put(index, value);
                            currentOids.put(rootOid, key);
                        }
                    }
                    if (!isEnd) {
                        overRootOids.add(rootOid);
                    }
                }
                if (overRootOids.isEmpty())
                    return;
                if (currentOids.isEmpty())
                    return;
                String[] loopRootOIDs = new String[overRootOids.size()];
                snmpGetBulk(target, datas, currentOids.values(), overRootOids.toArray(loopRootOIDs));
            }
        } catch (IOException e) {
            throw e;
        }
    }

    // 获取一层子树
    private void getSubtree(Target target, String oidStr, Map<String, List<String>> oidResultValueMaps) {
        OID oid = new OID(oidStr);
        TreeUtils utils = null;
        if (target.getVersion() == SnmpConstants.version1)
            utils = new TreeUtils(snmp, getNextPDUFactory);
        else
            utils = new TreeUtils(snmp, getBulkPDUFactory);
        List<TreeEvent> treeEventList = utils.getSubtree(target, oid);
        if (!treeEventList.isEmpty()) {
            for (TreeEvent treeEvent : treeEventList) {
                VariableBinding[] variables = treeEvent.getVariableBindings();
                if (variables != null) {
                    for (VariableBinding variable : variables) {
                        String responseOid = variable.getOid().toString();
                        String value = getValue(responseOid, variable.getVariable());
                        String index = responseOid.substring(oidStr.length() + 1);
                        if (oidResultValueMaps.get(INDEX_COLUMN_NAME) == null) {
                            List<String> indexList = new ArrayList<String>();
                            indexList.add(index);
                            oidResultValueMaps.put(INDEX_COLUMN_NAME, indexList);
                        } else if (!oidResultValueMaps.get(INDEX_COLUMN_NAME).contains(index)) {
                            oidResultValueMaps.get(INDEX_COLUMN_NAME).add(index);
                        }
                        if (oidResultValueMaps.get(oidStr) == null) {
                            List<String> valueList = new ArrayList<>();
                            valueList.add(value);
                            oidResultValueMaps.put(oidStr, valueList);
                        } else {
                            oidResultValueMaps.get(oidStr).add(value);
                        }
                    }
                }
            }
        }
    }

    /**
     * 获取表格数据,例如获取arp表，ip路由表等
     *
     * @param target
     * @param oidStrs
     */
    private List<List<String>> getTable(Target target, String[] oidStrs) {
        OID[] oids = new OID[oidStrs.length];
        for (int i = 0; i < oidStrs.length; i++) {
            oids[i] = new OID(oidStrs[i]);
        }
        TableUtils utils = null;
        if (target.getVersion() == SnmpConstants.version1) {
            utils = new TableUtils(snmp, getNextPDUFactory);
        } else {
            utils = new TableUtils(snmp, getBulkPDUFactory);
        }
        List<TableEvent> tableEventList = utils.getTable(target, oids, null, null);
        if (!tableEventList.isEmpty()) {
            List<List<String>> datas = new ArrayList<List<String>>(50);
            for (TableEvent tableEvent : tableEventList) {
                VariableBinding[] variables = tableEvent.getColumns();
                if (variables != null) {
                    String rowOID = tableEvent.getIndex().toString();
                    List<String> rows = new ArrayList<String>(variables.length + 1);
                    rows.add(rowOID);
                    for (VariableBinding variable : variables) {
                        String value = getValue(variable.getOid().toString(), variable.getVariable());
                        rows.add(value);
                    }
                    datas.add(rows);
                }
            }
            return datas;
        }
        return null;
    }

    /**
     * 判断SNMP walk是否已经结束，只walk一层节点
     *
     * @return
     */
    private boolean isEndWalk(VariableBinding responseVariableBinding, OID requestOID, PDU responsePDU) {
        boolean isFinished = false;
        if (responsePDU.getErrorStatus() != PDU.noError) {
            isFinished = true;
        } else if (responseVariableBinding.getOid() == null) {
            isFinished = true;
        } else if (responseVariableBinding.getOid().size() < requestOID.size()) {
            isFinished = true;
        } else if (requestOID.leftMostCompare(requestOID.size(), responseVariableBinding.getOid()) != 0) {
            isFinished = true;
        } else if (Null.isExceptionSyntax(responseVariableBinding.getVariable().getSyntax())) {
            isFinished = true;
        } else if (responseVariableBinding.getOid().compareTo(requestOID) <= 0) {
            isFinished = true;
        }
        return isFinished;
    }

    private String getSourceOid(String lastSourceOid, String requestOid, String snmpResponseOid) {
        if (lastSourceOid != null && snmpResponseOid.startsWith(lastSourceOid)) {
            return lastSourceOid;
        } else {
            if (snmpResponseOid.startsWith(requestOid)) {
                return requestOid;
            }
        }
        return null;
    }

    private void resolveSnmpReturnValue(Map<String, List<String>> oidResultValueMaps, int pduCode,
                                        List<? extends VariableBinding> bindings, String requestOid, String initOid) {
        boolean parseIndex = (pduCode == PDU.GETNEXT);
        if (parseIndex) {
            if (!oidResultValueMaps.containsKey(INDEX_COLUMN_NAME)) {
                oidResultValueMaps.put(INDEX_COLUMN_NAME, new ArrayList<>());
            }
        }
        String lastSourceOid = null;
        for (int i = 0; i < bindings.size(); i++) {
            VariableBinding variableBinding = bindings.get(i);
            String snmpReturnoid = variableBinding.getOid().toString();
            lastSourceOid = getSourceOid(lastSourceOid, requestOid, snmpReturnoid);
            try {
                if (lastSourceOid == null) {
                    continue;
                }
                int lastIndex = lastSourceOid.length();
                if (parseIndex) {
                    if (i == 0) {
                        String index = snmpReturnoid.substring(lastIndex + 1);
                        if (!oidResultValueMaps.get(INDEX_COLUMN_NAME).contains(index))
                            oidResultValueMaps.get(INDEX_COLUMN_NAME).add(index);
                    }
                }
                if (oidResultValueMaps.containsKey(initOid)) {
                    oidResultValueMaps.get(initOid).add(getValue(variableBinding.getOid().toString(),
                            variableBinding.getVariable()));
                } else {
                    List<String> varValues = new ArrayList<>();
                    varValues.add(getValue(variableBinding.getOid().toString(), variableBinding.getVariable()));
                    oidResultValueMaps.put(initOid, varValues);
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    public String getValue(final String oid, Variable v) {
        int syntax = v.getSyntax();
        String value = null;
        switch (syntax) {
            case SnmpConstant.SNMP_SYNTAX_INT:
            case SnmpConstant.SNMP_SYNTAX_UINT32:
                value = String.valueOf(v.toInt());
                break;
            case SnmpConstant.SNMP_SYNTAX_TIMETICKS:
                value = String.valueOf(v.toLong());
                break;
            default:
                value = v.toString();
                break;
        }
        return convertToGBK(oid, value);
    }

    /**
     * @param oid String
     * @param str String
     * @return String
     */
    protected String convertToGBK(final String oid, final String str) {
        // 八进制转String
        if (isOct(str) && StringUtils.startsWithAny(oid, convertToString)) {
            // 特殊字符特殊处理
            if (str.contains(A1_67)) {
                final String[] split = str.split(A1_67);
                final StringBuffer buffer = new StringBuffer();
                for (String str2 : split) {
                    if (str2.startsWith(":")) {
                        str2 = str2.substring(1);
                    }
                    buffer.append(fmtHexStr(str2));
                    buffer.append("　");
                }
                if (buffer.length() > 0) {
                    return buffer.substring(0, buffer.length() - 1);
                }
                return buffer.toString();
            }
            return fmtHexStr(str);
        }
        if (str != null) {
            return str.trim();
        }
        return str;
    }

    private boolean isOct(final String s) {
        if (StringUtils.isEmpty(s) || s.indexOf(REGEX_TEXT) < 0) {
            return false;
        }
        final String[] t_strs = s.split(REGEX_TEXT);
        for (int t_i = 0; t_i < t_strs.length; t_i++) {
            try {
                Integer.parseInt(t_strs[t_i], HEX_TEXT);
            } catch (final NumberFormatException t_e) {
                return false;
            }
        }
        return true;
    }

    private String fmtHexStr(final String paramString) {
        String t_str = null;
        try {
            if (paramString != null) {
                final String[] t_strs = paramString.split(REGEX_TEXT);
                byte[] t_bytes;
                if (t_strs != null) {
                    final int t_i = t_strs.length;
                    t_bytes = new byte[t_i];
                    for (int t_j = 0; t_j < t_i; t_j++) {
                        t_bytes[t_j] = new Integer(Integer.parseInt(
                                t_strs[t_j], HEX_TEXT)).byteValue();
                    }
                    t_str = new String(t_bytes, GBK);
                } else {
                    t_str = paramString;
                }
            }
        } catch (final Throwable t_e) {
            t_str = paramString;
        }
        if (t_str != null) {
            t_str = t_str.trim();
        }
        return t_str;
    }
}
