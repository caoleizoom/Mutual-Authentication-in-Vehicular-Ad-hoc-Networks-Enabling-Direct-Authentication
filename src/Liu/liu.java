package Liu;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import static java.lang.System.*;

public class liu {
    public static void setup1(String pairingFile,String publicFile) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P",P.toString());
        storePropToFile(PubProp,publicFile);

    }
    public static void setup(String pairingFile,  String publicFile,String mskFile,String KGC_i) {
        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String Pstr=PubProp.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        //调用两次setup函数为了不代替之前的数据，用loadPropFromFile打开文件并直接取其中数据

        Properties mskProp = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        //设置KGC_A和KGC_B的主私钥
        Element s_i = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        Element u_i = bp.getZr().newRandomElement().getImmutable();
        mskProp.setProperty("s_"+KGC_i, Base64.getEncoder().encodeToString(s_i.toBytes()));//element和string类型之间的转换需要通过bytes
        mskProp.setProperty("u_"+KGC_i, Base64.getEncoder().encodeToString(u_i.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥
        Element T_pubi = P.powZn(s_i).getImmutable();
        Element K_pubi = P.powZn(u_i).getImmutable();
        // out.println(end-sta);

        PubProp.setProperty("T_pub_"+KGC_i, T_pubi.toString());
        PubProp.setProperty("K_pub_"+KGC_i, K_pubi.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段
    public static void Registration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {

        //获得主公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String T_pubistr=pubProp.getProperty("T_pub_"+KGC_i);
        String K_pubistr=pubProp.getProperty("K_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Element T_pubi=bp.getG1().newElementFromBytes(T_pubistr.getBytes()).getImmutable();
        Element K_pubi=bp.getG1().newElementFromBytes(K_pubistr.getBytes()).getImmutable();
        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        String u_istr=mskp.getProperty("u_"+KGC_i);
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element u_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(u_istr)).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
        byte[] bh1_i=sha1(ID_i);
        Element h1_i=bp.getZr().newElementFromHash(bh1_i,0,bh1_i.length).getImmutable();
        Element t_i=bp.getZr().newRandomElement().getImmutable();
        Element PID_i=t_i.mul(h1_i).getImmutable();
        Element PID_si=PID_i.mul(s_i).getImmutable();

        pkp.setProperty("h1_"+ID_i, h1_i.toString());
        pkp.setProperty("PID_"+ID_i, PID_i.toString());
        pkp.setProperty("PID_s"+ID_i, PID_si.toString());
        skp.setProperty("t_"+ID_i,Base64.getEncoder().encodeToString(t_i.toBytes()));

        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }
    public static void PartialKeyGeneration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {

        //获得主公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String T_pubistr=pubProp.getProperty("T_pub_"+KGC_i);
        String K_pubistr=pubProp.getProperty("K_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Element T_pubi=bp.getG1().newElementFromBytes(T_pubistr.getBytes()).getImmutable();
        Element K_pubi=bp.getG1().newElementFromBytes(K_pubistr.getBytes()).getImmutable();
        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        String u_istr=mskp.getProperty("u_"+KGC_i);
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element u_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(u_istr)).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        String h1_istr=pkp.getProperty("h1_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        String PID_sistr=pkp.getProperty("PID_s"+ID_i);
        Element h1_i=bp.getZr().newElementFromBytes(h1_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Element PID_si=bp.getZr().newElementFromBytes(PID_sistr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
        byte[] bPID_i=PID_i.toBytes();
        Element psk_i=u_i.add(PID_i.mul(s_i)).getImmutable();
        Element Psk_i=P.powZn(psk_i.invert());
       byte[] bPsk_i=Psk_i.toBytes();
        int n = Math.max(bPID_i.length, bPsk_i.length);
        int m = Math.min(bPID_i.length, bPsk_i.length);
        byte[] bPIDPsk_i=new byte[n];
        for (int i=0;i<m;i++)
            bPIDPsk_i[i]= (byte) (bPID_i[i]^bPsk_i[i]);
        Element PIDPsk_i=bp.getZr().newElementFromHash(bPIDPsk_i,0,bPIDPsk_i.length).getImmutable();

        byte[] bh2_i=sha1(PIDPsk_i.toString());
        Element h2_i=bp.getZr().newElementFromHash(bh2_i,0,bh2_i.length).getImmutable();

        pkp.setProperty("h2_"+ID_i, h2_i.toString());
        skp.setProperty("psk_"+ID_i,Base64.getEncoder().encodeToString(psk_i.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }
    public static void KeyGeneration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {

        //获得主公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String T_pubistr=pubProp.getProperty("T_pub_"+KGC_i);
        String K_pubistr=pubProp.getProperty("K_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Element T_pubi=bp.getG1().newElementFromBytes(T_pubistr.getBytes()).getImmutable();
        Element K_pubi=bp.getG1().newElementFromBytes(K_pubistr.getBytes()).getImmutable();
        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        String u_istr=mskp.getProperty("u_"+KGC_i);
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element u_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(u_istr)).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        String h1_istr=pkp.getProperty("h1_"+ID_i);
        String h2_istr=pkp.getProperty("h2_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        String PID_sistr=pkp.getProperty("PID_s"+ID_i);
        Element h1_i=bp.getZr().newElementFromBytes(h1_istr.getBytes()).getImmutable();
        Element h2_i=bp.getZr().newElementFromBytes(h1_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Element PID_si=bp.getZr().newElementFromBytes(PID_sistr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String psk_istr=skp.getProperty("psk_"+ID_i);
        Element psk_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(psk_istr)).getImmutable();
        //生成私钥
        Element psk_iP=P.powZn(psk_i).getImmutable();
        Element L1= bp.pairing(psk_iP,P).getImmutable();
        Element pidT_i=(T_pubi.powZn(PID_i)).add(K_pubi).getImmutable();
        Element R1=bp.pairing(pidT_i,P).getImmutable();
        if (L1.isEqual(R1)){
            out.println("1成功");
            Element x_i=bp.getZr().newRandomElement().getImmutable();
            Element V_pubi=P.powZn(x_i).getImmutable();
            pkp.setProperty("V_pub"+ID_i, V_pubi.toString());
            skp.setProperty("x_"+ID_i,Base64.getEncoder().encodeToString(x_i.toBytes()));
        }else {
            out.println("1失败");
        }
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }

    public static void Authentication1(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Properties pkp=loadPropFromFile(pkFile);
        String h2_istr=pkp.getProperty("h2_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        Element h2_i=bp.getZr().newElementFromBytes(h2_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String psk_istr=skp.getProperty("psk_"+ID_i);
        Element psk_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(psk_istr)).getImmutable();

        Properties authP=loadPropFromFile(authFile);

        byte[] bPID_i=PID_i.toBytes();
        Element Psk_i=P.powZn(psk_i.invert());
        byte[] bPsk_i=Psk_i.toBytes();
        int n = Math.max(bPID_i.length, bPsk_i.length);
        int m = Math.min(bPID_i.length, bPsk_i.length);
        byte[] bPIDPsk_i=new byte[n];
        for (int i=0;i<m;i++)
            bPIDPsk_i[i]= (byte) (bPID_i[i]^bPsk_i[i]);
        Element PIDPsk_i=bp.getZr().newElementFromHash(bPIDPsk_i,0,bPIDPsk_i.length).getImmutable();

        byte[] bh2_i=sha1(PIDPsk_i.toString());
        Element h2_i1=bp.getZr().newElementFromHash(bh2_i,0,bh2_i.length).getImmutable();



        Element N_i=bp.getZr().newRandomElement().getImmutable();
        authP.setProperty("N_"+ID_i,Base64.getEncoder().encodeToString(N_i.toBytes()));
        if (h2_i.isEqual(h2_i1)){
            //Element N_i=bp.getZr().newRandomElement().getImmutable();
           // authP.setProperty("N_"+ID_i,Base64.getEncoder().encodeToString(N_i.toBytes()));
        }else {
            out.println("2失败");
        }
        storePropToFile(authP,authFile);
    }
    public static void Authentication2(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties authP=loadPropFromFile(authFile);
        String N_istr=authP.getProperty("N_"+ID_i);
        Element N_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(N_istr)).getImmutable();

        Element M_i=bp.getZr().newRandomElement().getImmutable();
        byte[] bN_i=N_i.toBytes();
        byte[] bM_i=M_i.toBytes();
        int n = Math.max(bN_i.length, bM_i.length);
        int m = Math.min(bN_i.length, bM_i.length);
        byte[] bNM_i=new byte[n];
        for (int i=0;i<m;i++)
            bNM_i[i]= (byte) (bN_i[i]^bM_i[i]);
        Element NM_i=bp.getZr().newElementFromHash(bNM_i,0,bNM_i.length).getImmutable();

        byte[] bh3_i=sha1(NM_i.toString());
        Element h3_i=bp.getZr().newElementFromHash(bh3_i,0,bh3_i.length).getImmutable();

        int n1 = Math.max(bh3_i.length, bM_i.length);
        int m1 = Math.min(bh3_i.length, bM_i.length);
        byte[] bh3M_i=new byte[n1];
        for (int i=0;i<m1;i++)
            bh3M_i[i]= (byte) (bh3_i[i]^bM_i[i]);
        Element h3M_i=bp.getZr().newElementFromHash(bh3M_i,0,bh3M_i.length).getImmutable();

        authP.setProperty("M_"+ID_i,Base64.getEncoder().encodeToString(N_i.toBytes()));
        authP.setProperty("h3M_"+ID_i,Base64.getEncoder().encodeToString(h3M_i.toBytes()));
        authP.setProperty("h3_"+ID_i,Base64.getEncoder().encodeToString(h3_i.toBytes()));

        storePropToFile(authP,authFile);
    }
    public static void Authentication3(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Properties pkp=loadPropFromFile(pkFile);
        String h2_istr=pkp.getProperty("h2_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        String V_pubistr=pkp.getProperty("V_pub"+ID_i);
        Element h2_i=bp.getZr().newElementFromBytes(h2_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Element V_pubi=bp.getZr().newElementFromBytes(V_pubistr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String psk_istr=skp.getProperty("psk_"+ID_i);
        Element psk_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(psk_istr)).getImmutable();

        Properties authP=loadPropFromFile(authFile);
        String N_istr=authP.getProperty("N_"+ID_i);
        String M_istr=authP.getProperty("M_"+ID_i);
        Element N_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(N_istr)).getImmutable();
        Element M_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(M_istr)).getImmutable();

        Element L_i=N_i.mul(M_i.invert()).getImmutable();
        byte[] bL_i=L_i.toBytes();
        byte[] bPID_i=PID_i.toBytes();
        byte[] bV_pubi=V_pubi.toBytes();
        int n = Math.max(bPID_i.length, bV_pubi.length);
        int m = Math.min(bPID_i.length, bV_pubi.length);
        byte[] bPIDV_i=new byte[n];
        for (int i=0;i<m;i++)
            bPIDV_i[i]= (byte) (bPID_i[i]^bV_pubi[i]);
        Element PIDV_i=bp.getZr().newElementFromHash(bPIDV_i,0,bPIDV_i.length).getImmutable();
        int n1 = Math.max(bL_i.length,bPIDV_i.length);
        int m1 = Math.min(bL_i.length, bPIDV_i.length);
        byte[] bPIDVL_i=new byte[n1];
        for (int i=0;i<m1;i++)
            bPIDVL_i[i]= (byte) (bL_i[i]^bPIDV_i[i]);
        Element Tx_1=bp.getZr().newElementFromHash(bPIDVL_i,0,bPIDVL_i.length).getImmutable();
        authP.setProperty("Tx_1",Base64.getEncoder().encodeToString(Tx_1.toBytes()));
        storePropToFile(authP,authFile);
    }
    public static void Verify1(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String veriFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        String h2_istr=pkp.getProperty("h2_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        String V_pubistr=pkp.getProperty("V_pub"+ID_i);
        Element h2_i=bp.getZr().newElementFromBytes(h2_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Element V_pubi=bp.getZr().newElementFromBytes(V_pubistr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String psk_istr=skp.getProperty("psk_"+ID_i);
        Element psk_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(psk_istr)).getImmutable();
        String x_istr=skp.getProperty("x_"+ID_i);
        Element x_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_istr)).getImmutable();

        Properties authP=loadPropFromFile(authFile);
        String N_istr=authP.getProperty("N_"+ID_i);
        String M_istr=authP.getProperty("M_"+ID_i);
        Element N_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(N_istr)).getImmutable();
        Element M_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(M_istr)).getImmutable();

        Properties verip=new Properties();
        Element N_P=P.powZn(N_i).getImmutable();
        byte[] bN_P=N_P.toBytes();
        byte[] bPID_i=PID_i.toBytes();
        byte[] bM_i=M_i.toBytes();
        int n = Math.max(bPID_i.length, bN_P.length);
        int m = Math.min(bPID_i.length, bN_P.length);
        byte[] bPIDN_i=new byte[n];
        for (int i=0;i<m;i++)
            bPIDN_i[i]= (byte) (bPID_i[i]^bN_P[i]);
        Element PIDN_i=bp.getZr().newElementFromHash(bPIDN_i,0,bPIDN_i.length).getImmutable();
        int n1 = Math.max(bM_i.length,bPIDN_i.length);
        int m1 = Math.min(bM_i.length, bPIDN_i.length);
        byte[] bPIDNM_i=new byte[n1];
        for (int i=0;i<m1;i++)
            bPIDNM_i[i]= (byte) (bM_i[i]^bPIDN_i[i]);
        Element PIDNM_i=bp.getZr().newElementFromHash(bPIDNM_i,0,bPIDNM_i.length).getImmutable();
        byte[] bh4_i=sha1(PIDNM_i.toString());
        Element h4_i=bp.getZr().newElementFromHash(bh4_i,0,bh4_i.length).getImmutable();

        Element b_i=bp.getZr().newRandomElement().getImmutable();
        Element B_i=P.powZn(b_i).getImmutable();
        Element M_P=P.powZn(M_i).getImmutable();
        Element A_i=(N_i.mul(psk_i)).add((x_i.add(b_i)).mul(h4_i)).getImmutable();
        verip.setProperty("h4_"+ID_i,Base64.getEncoder().encodeToString(bh4_i));
        verip.setProperty("B_"+ID_i,Base64.getEncoder().encodeToString(B_i.toBytes()));
        verip.setProperty("M_P",Base64.getEncoder().encodeToString(M_P.toBytes()));
        verip.setProperty("N_P",Base64.getEncoder().encodeToString(N_P.toBytes()));
        verip.setProperty("A_"+ID_i,Base64.getEncoder().encodeToString(A_i.toBytes()));
        storePropToFile(verip,veriFile);
    }
    public static void Verify2(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String veriFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String T_pubistr=pubProp.getProperty("T_pub_"+KGC_i);
        String K_pubistr=pubProp.getProperty("K_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();;
        Element T_pubi=bp.getG1().newElementFromBytes(T_pubistr.getBytes()).getImmutable();
        Element K_pubi=bp.getG1().newElementFromBytes(K_pubistr.getBytes()).getImmutable();
        Properties pkp=loadPropFromFile(pkFile);
        String h2_istr=pkp.getProperty("h2_"+ID_i);
        String PID_istr=pkp.getProperty("PID_"+ID_i);
        String V_pubistr=pkp.getProperty("V_pub"+ID_i);
        Element h2_i=bp.getZr().newElementFromBytes(h2_istr.getBytes()).getImmutable();
        Element PID_i=bp.getZr().newElementFromBytes(PID_istr.getBytes()).getImmutable();
        Element V_pubi=bp.getG1().newElementFromBytes(V_pubistr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String psk_istr=skp.getProperty("psk_"+ID_i);
        Element psk_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(psk_istr)).getImmutable();

        String x_istr=skp.getProperty("x_"+ID_i);
        Element x_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_istr)).getImmutable();

        Properties authP=loadPropFromFile(authFile);
        String N_istr=authP.getProperty("N_"+ID_i);
        String M_istr=authP.getProperty("M_"+ID_i);
        Element N_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(N_istr)).getImmutable();
        Element M_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(M_istr)).getImmutable();

        Properties verip=loadPropFromFile(veriFile);
        String h4_istr=verip.getProperty("h4_"+ID_i);
        String B_istr=verip.getProperty("B_"+ID_i);
        String M_Pstr=verip.getProperty("M_P");
        String N_Pstr=verip.getProperty("N_P");
        String A_istr=verip.getProperty("A_"+ID_i);
        Element h4_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(h4_istr)).getImmutable();
        Element B_i=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B_istr)).getImmutable();
        Element M_P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(M_Pstr)).getImmutable();
        Element N_P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(N_Pstr)).getImmutable();
        Element A_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(A_istr)).getImmutable();

        Element N_P1=P.powZn(N_i).getImmutable();
        byte[] bN_P=N_P.toBytes();
        byte[] bPID_i=PID_i.toBytes();
        byte[] bM_i=M_i.toBytes();
        int n = Math.max(bPID_i.length, bN_P.length);
        int m = Math.min(bPID_i.length, bN_P.length);
        byte[] bPIDN_i=new byte[n];
        for (int i=0;i<m;i++)
            bPIDN_i[i]= (byte) (bPID_i[i]^bN_P[i]);
        Element PIDN_i=bp.getZr().newElementFromHash(bPIDN_i,0,bPIDN_i.length).getImmutable();
        int n1 = Math.max(bM_i.length,bPIDN_i.length);
        int m1 = Math.min(bM_i.length, bPIDN_i.length);
        byte[] bPIDNM_i=new byte[n1];
        for (int i=0;i<m1;i++)
            bPIDNM_i[i]= (byte) (bM_i[i]^bPIDN_i[i]);
        Element PIDNM_i=bp.getZr().newElementFromHash(bPIDNM_i,0,bPIDNM_i.length).getImmutable();
        byte[] bh4_i=sha1(PIDNM_i.toString());
        Element h4_i1=bp.getZr().newElementFromHash(bh4_i,0,bh4_i.length).getImmutable();

        if (h4_i1.isEqual(h4_i))
            out.println("3成功");
        else
            out.println("3shibai");
        Element R1=(P.powZn(A_i)).add((B_i.powZn(h4_i.negate()))).getImmutable();

        Element L1=K_pubi.powZn(N_i).getImmutable();
        Element L2=T_pubi.powZn(PID_i.mul(N_i)).getImmutable();
        Element L3=V_pubi.powZn(h4_i).getImmutable();
        Element L4=L1.add(L2.add(L3)).getImmutable();
        if (R1.isEqual(L4))
            out.println("4chenggong");
        else
            out.println("4shibai");

        byte[] bM_i1=M_i.toBytes();
        byte[] bPID_i1=PID_i.toBytes();
        byte[] bh4_i1=h4_i.toBytes();
        int n2 = Math.max(bPID_i.length, bM_i1.length);
        int m2 = Math.min(bPID_i.length, bM_i1.length);
        byte[] bPIDM_i1=new byte[n2];
        for (int i=0;i<m2;i++)
            bPIDM_i1[i]= (byte) (bPID_i[i]^bM_i1[i]);
        Element PIDM_i1=bp.getZr().newElementFromHash( bPIDM_i1,0, bPIDM_i1.length).getImmutable();
        int n3 = Math.max(bh4_i1.length, bPIDM_i1.length);
        int m3 = Math.min(bh4_i1.length,  bPIDM_i1.length);
        byte[] bPIDMh4_i=new byte[n3];
        for (int i=0;i<m3;i++)
            bPIDMh4_i[i]= (byte) (bh4_i1[i]^ bPIDM_i1[i]);
        Element Tx_2=bp.getZr().newElementFromHash(bPIDMh4_i,0,bPIDMh4_i.length).getImmutable();
        authP.setProperty("Tx_2",Base64.getEncoder().encodeToString(Tx_2.toBytes()));
        storePropToFile(authP,authFile);

        storePropToFile(verip,veriFile);
    }
    /*
    将程序变量数据存储到文件中
     */
    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }


    /*
    从文件中读取数据
     */
    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }


    /*
    哈希函数
     */
    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*
        指定配置文件的路径
         */
        String dir = "./storeFile/Liu/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String certificateFileName=dir+"certi.properties";
        String authenticationFileName=dir+"auth.properties";
        String verifyFileName=dir+"Veri.properties";

        String KGC_A="KGC_A";
        String KGC_B="KGC_B";
        String ID_i="Alice";
        String ID_j="Bob";
        setup1(pairingParametersFileName,publicKeyFileName);
        setup(pairingParametersFileName,publicParameterFileName,mskFileName,KGC_B);
        setup(pairingParametersFileName,publicParameterFileName,mskFileName,KGC_A);
        Registration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_A,ID_i);
        Registration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_B,ID_j);
        PartialKeyGeneration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_A,ID_i);
        PartialKeyGeneration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_B,ID_j);
        KeyGeneration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_A,ID_i);
        KeyGeneration(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,KGC_A,ID_i);
        long nums = 0;
        for (int i = 0; i < 10; i++) {
            long start_nanoTime = System.nanoTime();
            Authentication1(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,KGC_A,ID_i,ID_j);
            Authentication2(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,KGC_A,ID_i,ID_j);
            Authentication3(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,KGC_A,ID_i,ID_j);
            Verify1(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,verifyFileName,KGC_A,ID_i,ID_j);
            Verify2(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,verifyFileName,KGC_A,ID_i,ID_j);
            long end_nanoTime = System.nanoTime();
            nums += end_nanoTime-start_nanoTime;
        }
        System.out.println((double) nums/10000000);












        /*long start1 = System.currentTimeMillis();

            long end1= System.currentTimeMillis();
            System.out.println(end1 - start1);


        */


    }
}
