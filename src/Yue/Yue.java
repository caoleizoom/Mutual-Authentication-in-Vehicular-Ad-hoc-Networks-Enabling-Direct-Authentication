package Yue;

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


import static java.lang.System.out;
import static java.lang.System.setOut;

public class Yue {

    //初始阶段
    /*public static void setup(String pairingFile, String publicFile,String mskFile,String KGC_i) {
        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        //设置KGC_A和KGC_B的主私钥
        Element s_i = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        Properties mskProp = new Properties();  //定义一个对properties文件操作的对象
        mskProp.setProperty("s_"+KGC_i, Base64.getEncoder().encodeToString(s_i.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);

        //设置主公钥
        Element BSN_A = bp.getZr().newRandomElement().getImmutable();
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pubi = P.powZn(s_i).getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P",P.toString());
        PubProp.setProperty("BSN_"+KGC_i, BSN_A.toString());
        PubProp.setProperty("P_pub_"+KGC_i, P_pubi.toString());
        storePropToFile(PubProp,publicFile);

    }  */
    public static void setup1(String pairingFile,String publicFile,String mskFile) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element g11 = bp.getG1().newRandomElement().getImmutable();
        Element g12 = bp.getG1().newRandomElement().getImmutable();
        Element g2 = bp.getG2().newRandomElement().getImmutable();
        Element gama=bp.getZr().newRandomElement().getImmutable();
        Element Gama=g2.powZn(gama).getImmutable();
        Element x11=bp.getZr().newRandomElement().getImmutable();
        Element x21=bp.getZr().newRandomElement().getImmutable();
        Element y11=bp.getZr().newRandomElement().getImmutable();
        Element y21=bp.getZr().newRandomElement().getImmutable();
        Element fai1=g11.powZn(x11).mul(g12.powZn(x21)).getImmutable();
        Element fai2=g11.powZn(y11).mul(g12.powZn(y21)).getImmutable();
        Element v=bp.getZr().newRandomElement().getImmutable();
        Element u=g11.powZn(v).getImmutable();

        Properties PubProp =new Properties();
        Properties mskProp =new Properties();
        PubProp.setProperty("g1",g1.toString());
        PubProp.setProperty("g11",g11.toString());
        PubProp.setProperty("g12",g12.toString());
        PubProp.setProperty("g2",g12.toString());
        PubProp.setProperty("Gama",Gama.toString());
        PubProp.setProperty("fai1",fai1.toString());
        PubProp.setProperty("fai2",fai2.toString());
        PubProp.setProperty("u",u.toString());
        mskProp.setProperty("gama", Base64.getEncoder().encodeToString(gama.toBytes()));
        mskProp.setProperty("x11", Base64.getEncoder().encodeToString(x11.toBytes()));
        mskProp.setProperty("x21", Base64.getEncoder().encodeToString(x21.toBytes()));
        mskProp.setProperty("y11", Base64.getEncoder().encodeToString(y11.toBytes()));
        mskProp.setProperty("y21", Base64.getEncoder().encodeToString(y21.toBytes()));
        mskProp.setProperty("v", Base64.getEncoder().encodeToString(v.toBytes()));
        storePropToFile(PubProp,publicFile);
        storePropToFile(mskProp,mskFile);
    }
    public static void Registration1(String pairingFile,  String publicFile,String mskFile,String RSU_i) {
        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG2().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element v=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vstr)).getImmutable();
        //调用两次setup函数为了不代替之前的数据，用loadPropFromFile打开文件并直接取其中数据

        Element omiga=bp.getZr().newRandomElement().getImmutable();
        Element Omiga=g2.powZn(omiga).getImmutable();

        PubProp.setProperty("Omiga"+RSU_i,Omiga.toString());
        mskProp.setProperty("omiga"+RSU_i, Base64.getEncoder().encodeToString(omiga.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);
        storePropToFile(PubProp, publicFile);
    }
    public static void Registration2(String pairingFile,  String publicFile,String mskFile,String OBU_i) {
        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG2().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element v=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vstr)).getImmutable();
        //调用两次setup函数为了不代替之前的数据，用loadPropFromFile打开文件并直接取其中数据

        Element ka=bp.getZr().newRandomElement().getImmutable();
        Element Ka=g12.powZn(ka).getImmutable();

        PubProp.setProperty("Ka"+OBU_i,Ka.toString());
        mskProp.setProperty("ka"+OBU_i, Base64.getEncoder().encodeToString(ka.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);
        storePropToFile(PubProp, publicFile);

    }


    //Registration阶段
    public static void Join1(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RSU_i,String OBU_i) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        String Omiga_istr=PubProp.getProperty("Omiga"+RSU_i);
        String Ka_istr=PubProp.getProperty("Ka"+OBU_i);
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG1().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();
        Element Omiga_i=bp.getG2().newElementFromBytes(Omiga_istr.getBytes()).getImmutable();
        Element Ka_i=bp.getG1().newElementFromBytes(Ka_istr.getBytes()).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        String omiga_istr=mskProp.getProperty("omiga"+RSU_i);
        String ka_istr=mskProp.getProperty("ka"+OBU_i);
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element omiga_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(omiga_istr)).getImmutable();
        Element ka_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ka_istr)).getImmutable();
        //获得主公钥
        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
       Element epsl_i=bp.getZr().newRandomElement().getImmutable();
       Element yita_i=bp.getZr().newRandomElement().getImmutable();
         Element gCert_i=(g1.mul((g11.powZn(epsl_i))).mul(Ka_i)).powZn((omiga_i.add(yita_i)).invert()).getImmutable();
        pkp.setProperty("epsl_"+OBU_i,epsl_i.toString());
        pkp.setProperty("yita_"+OBU_i,yita_i.toString());
        pkp.setProperty("gCert_"+OBU_i,gCert_i.toString());

        storePropToFile(pkp,pkFile);

    }

    public static void Join2(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String RSU_i,String OBU_i) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        String Omiga_istr=PubProp.getProperty("Omiga"+RSU_i);
        String Ka_istr=PubProp.getProperty("Ka"+OBU_i);
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG1().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();
        Element Omiga_i=bp.getG2().newElementFromBytes(Omiga_istr.getBytes()).getImmutable();
        Element Ka_i=bp.getG1().newElementFromBytes(Ka_istr.getBytes()).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        String omiga_istr=mskProp.getProperty("omiga"+RSU_i);
        String ka_istr=mskProp.getProperty("ka"+OBU_i);
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element omiga_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(omiga_istr)).getImmutable();
        Element ka_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ka_istr)).getImmutable();
        //获得主公钥
        Properties pkp=loadPropFromFile(pkFile);
        String epsl_istr=pkp.getProperty("epsl_"+OBU_i);
        String yita_istr=pkp.getProperty("yita_"+OBU_i);
        String gCert_istr=pkp.getProperty("gCert_"+OBU_i);
        Element epsl_i=bp.getG1().newElementFromBytes(epsl_istr.getBytes()).getImmutable();
        Element yita_i=bp.getZr().newElementFromBytes(yita_istr.getBytes()).getImmutable();
        Element gCert_i=bp.getG1().newElementFromBytes(gCert_istr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
        Element r1=Omiga_i.mul(g2.powZn(yita_i)).getImmutable();
        Element r=bp.pairing(gCert_i,r1).getImmutable();
        Element l1=bp.pairing(Ka_i,g2).getImmutable();
        Element l2=bp.pairing(g1.mul(g11.powZn(epsl_i)),g2).getImmutable();
        if(r.isEqual(l1.mul(l2))){
            out.println("1");
        }else
            out.println("2");
        Element gCert=(g1.mul((g11.powZn(epsl_i)).mul(g12.powZn(Ka_i)))).powZn((omiga_i.add(yita_i)).invert()).getImmutable();

    }

    public static void Authentication(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String RSU_i,String OBU_i,String OBU_j) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        String Omiga_istr=PubProp.getProperty("Omiga"+RSU_i);
        String Ka_istr=PubProp.getProperty("Ka"+OBU_i);
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG1().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();
        Element Omiga_i=bp.getG2().newElementFromBytes(Omiga_istr.getBytes()).getImmutable();
        Element Ka_i=bp.getG1().newElementFromBytes(Ka_istr.getBytes()).getImmutable();
        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        String omiga_istr=mskProp.getProperty("omiga"+RSU_i);
        String ka_istr=mskProp.getProperty("ka"+OBU_i);
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element omiga_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(omiga_istr)).getImmutable();
        Element ka_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ka_istr)).getImmutable();
        //获得主公钥
        Properties pkp=loadPropFromFile(pkFile);
        String epsl_istr=pkp.getProperty("epsl_"+OBU_i);
        String yita_istr=pkp.getProperty("yita_"+OBU_i);
        String yita_jstr=pkp.getProperty("yita_"+OBU_j);
        String gCert_istr=pkp.getProperty("gCert_"+OBU_i);
        Element epsl_i=bp.getZr().newElementFromBytes(epsl_istr.getBytes()).getImmutable();
        Element yita_i=bp.getZr().newElementFromBytes(yita_istr.getBytes()).getImmutable();
        Element yita_j=bp.getZr().newElementFromBytes(yita_jstr.getBytes()).getImmutable();
        Element gCert_i=bp.getG1().newElementFromBytes(gCert_istr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);

        Element S=bp.getZr().newRandomElement().getImmutable();
        Element F1=gCert_i.mul(u.powZn(S)).getImmutable();
        Element F2=g1.powZn(S).getImmutable();
        Element F3=g11.powZn(S).getImmutable();
        Element F4=g12.powZn(S).getImmutable();
        byte[] bh=sha1(F1.toString()+F2.toString()+F3.toString()+F4.toString());
        Element h=bp.getZr().newElementFromHash(bh,0,bh.length).getImmutable();
        Element F5=(fai1.mul(fai2).powZn(h)).powZn(S).getImmutable();
        Element afa=S.mul(yita_i).getImmutable();
        Element bta=S.mul(yita_j).getImmutable();
        Element r11=bp.pairing(F1,g2).powZn(yita_i.negate()).getImmutable();
        Element r12=bp.pairing(g12,g2).powZn(Ka_i).getImmutable();
        Element r13=bp.pairing(u,g2).powZn(afa).getImmutable();
        Element r14=bp.pairing(u,Omiga_i).powZn(S).getImmutable();
        Element r15=bp.pairing(g11,g2).powZn(epsl_i).getImmutable();
        Element l11=bp.pairing(F1,Omiga_i).powZn(epsl_i).getImmutable();
        Element l12=bp.pairing(g1,g2).getImmutable();
        Element R1=r11.mul(r12.mul(r13.mul(r14.mul(r15)))).getImmutable();
        Element L1=l11.div(l12).getImmutable();

        Element r21=bp.pairing(F2,g2).powZn(yita_i.negate()).getImmutable();
        Element r22=bp.pairing(g12,g2).getImmutable();
        Element r23=bp.pairing(g1,g2).powZn(bta).getImmutable();
        Element r24=bp.pairing(g1,Gama).powZn(S).getImmutable();
        Element r25=bp.pairing(g11,g2).powZn(epsl_i).getImmutable();
        Element l21=bp.pairing(F2,Gama).getImmutable();
        Element l22=bp.pairing(g1,g2).getImmutable();
        Element R2=r21.mul(r22.mul(r23.mul(r24.mul(r25)))).getImmutable();
        Element L2=l21.div(l22).getImmutable();

        Element F31=g11.powZn(S).getImmutable();
        Element F41=g12.powZn(S).getImmutable();
        Element F51=(fai1.mul(fai2.powZn(h))).powZn(S);
        Element r_afa=bp.getZr().newRandomElement().getImmutable();
        Element r_bta=bp.getZr().newRandomElement().getImmutable();
        Element r_s=bp.getZr().newRandomElement().getImmutable();
        Element r_eps=bp.getZr().newRandomElement().getImmutable();
        Element r_ka=bp.getZr().newRandomElement().getImmutable();
        Element r_yita=bp.getZr().newRandomElement().getImmutable();
        Element r_yita1=bp.getZr().newRandomElement().getImmutable();

        Element R_1=g11.powZn(r_s).getImmutable();
        Element R_2=g12.powZn(r_s).getImmutable();
        Element R_3=(fai1.mul(fai2.powZn(h))).powZn(r_s).getImmutable();
        Element c1=bp.pairing(g11,g2).powZn(r_s).getImmutable();
        Element c2=bp.pairing(fai1,g2).powZn(r_yita.invert()).getImmutable();
        Element c3=bp.pairing(g12,g2).powZn(r_ka).getImmutable();
        Element c4=bp.pairing(u,g2).powZn(r_afa).getImmutable();
        Element c5=bp.pairing(u,Omiga_i).powZn(r_s).getImmutable();
        Element RgCert=c1.mul(c2.mul(c3.mul(c4.mul(c5)))).getImmutable();


        Element t1=bp.pairing(g11,g2).powZn(r_eps).getImmutable();
        Element t2=bp.pairing(fai2,g2).powZn(r_yita1.invert()).getImmutable();
        Element t3=bp.pairing(g12,g2).powZn(epsl_i).getImmutable();
        Element t4=bp.pairing(g1,g2).powZn(r_bta).getImmutable();
        Element t5=bp.pairing(g1,Gama).powZn(r_s).getImmutable();
        Element Rtoken=t1.mul(t2.mul(t3.mul(t4.mul(t5)))).getImmutable();
        byte[] bh1=sha1(F31.toString()+F41.toString()+F51.toString()+F1.toString()+F2.toString()+R1.toString()+R2.toString()+R_3.toString()+Rtoken.toString()+RgCert.toString());
        Element c=bp.getZr().newElementFromHash(bh1,0,bh1.length).getImmutable();
        Element s_afa=r_afa.add(c.mul(afa)).getImmutable();
        Element s_bta=r_bta.add(c.mul(bta)).getImmutable();
        Element s_s=r_s.add(c.mul(S)).getImmutable();
        Element s_yita=r_yita.add(c.mul(yita_i)).getImmutable();
        Element s_yita1=r_yita1.add(c.mul(yita_j)).getImmutable();
        Element s_ka=r_ka.add(c.mul(ka_i)).getImmutable();
        Element s_eps=r_eps.add(c.mul(epsl_i)).getImmutable();

        Properties authp=new Properties();
        authp.setProperty("c",c.toString());
        authp.setProperty("s_afa",s_afa.toString());
        authp.setProperty("s_bta",s_bta.toString());
        authp.setProperty("s_s",s_s.toString());
        authp.setProperty("s_yita",s_yita.toString());
        authp.setProperty("s_yita1",s_yita1.toString());
        authp.setProperty("s_ka",s_ka.toString());
        authp.setProperty("s_eps",s_eps.toString());
        authp.setProperty("F1",F1.toString());
        authp.setProperty("F2",F2.toString());
        authp.setProperty("F3",F3.toString());
        authp.setProperty("F4",F4.toString());
        authp.setProperty("F5",F5.toString());
        storePropToFile(authp,authFile);

    }
    public static void Verify(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String veriFile,String RSU_i,String OBU_i,String OBU_j) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str=PubProp.getProperty("g1");
        String g11str=PubProp.getProperty("g11");
        String g12str=PubProp.getProperty("g12");
        String g2str=PubProp.getProperty("g2");
        String Gamastr=PubProp.getProperty("Gama");
        String fai1str=PubProp.getProperty("fai1");
        String fai2str=PubProp.getProperty("fai2");
        String ustr=PubProp.getProperty("u");
        String Omiga_istr=PubProp.getProperty("Omiga"+RSU_i);
        String Ka_istr=PubProp.getProperty("Ka"+OBU_i);
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g11=bp.getG1().newElementFromBytes(g11str.getBytes()).getImmutable();
        Element g12=bp.getG1().newElementFromBytes(g12str.getBytes()).getImmutable();
        Element g2=bp.getG1().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element Gama=bp.getG1().newElementFromBytes(Gamastr.getBytes()).getImmutable();
        Element fai1=bp.getG1().newElementFromBytes(fai1str.getBytes()).getImmutable();
        Element fai2=bp.getG1().newElementFromBytes(fai2str.getBytes()).getImmutable();
        Element u=bp.getG1().newElementFromBytes(ustr.getBytes()).getImmutable();
        Element Omiga_i=bp.getG2().newElementFromBytes(Omiga_istr.getBytes()).getImmutable();
        Element Ka_i=bp.getG1().newElementFromBytes(Ka_istr.getBytes()).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String gamastr=mskProp.getProperty("gama");
        String x11str=mskProp.getProperty("x11");
        String x21str=mskProp.getProperty("x21");
        String y11str=mskProp.getProperty("y11");
        String y21str=mskProp.getProperty("y21");
        String vstr=mskProp.getProperty("v");
        String omiga_istr=mskProp.getProperty("omiga"+RSU_i);
        String ka_istr=mskProp.getProperty("ka"+OBU_i);
        Element gama=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamastr)).getImmutable();
        Element x11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x11str)).getImmutable();
        Element x21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x21str)).getImmutable();
        Element y11=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y11str)).getImmutable();
        Element y21=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y21str)).getImmutable();
        Element omiga_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(omiga_istr)).getImmutable();
        Element ka_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ka_istr)).getImmutable();
        //获得主公钥
        Properties pkp=loadPropFromFile(pkFile);
        String epsl_istr=pkp.getProperty("epsl_"+OBU_i);
        String yita_istr=pkp.getProperty("yita_"+OBU_i);
        String yita_jstr=pkp.getProperty("yita_"+OBU_j);
        String gCert_istr=pkp.getProperty("gCert_"+OBU_i);
        Element epsl_i=bp.getG1().newElementFromBytes(epsl_istr.getBytes()).getImmutable();
        Element yita_i=bp.getZr().newElementFromBytes(yita_istr.getBytes()).getImmutable();
        Element yita_j=bp.getZr().newElementFromBytes(yita_jstr.getBytes()).getImmutable();
        Element gCert_i=bp.getG1().newElementFromBytes(gCert_istr.getBytes()).getImmutable();

        Properties authp=loadPropFromFile(authFile);
        String cstr=authp.getProperty("c");
        String s_afastr=authp.getProperty("s_afa");
        String s_btastr=authp.getProperty("s_bta");
        String s_sstr=authp.getProperty("s_s");
        String s_yitastr=authp.getProperty("s_yita");
        String s_yita1str=authp.getProperty("s_yita1");
        String s_kastr=authp.getProperty("s_ka");
        String s_epsstr=authp.getProperty("s_eps");
        String F1str=authp.getProperty("F1");
        String F2str=authp.getProperty("F2");
        String F3str=authp.getProperty("F3");
        String F4str=authp.getProperty("F4");
        String F5str=authp.getProperty("F5");
        Element c=bp.getG1().newElementFromBytes(cstr.getBytes()).getImmutable();
        Element s_afa=bp.getG1().newElementFromBytes(s_afastr.getBytes()).getImmutable();
        Element s_bta=bp.getG1().newElementFromBytes(s_btastr.getBytes()).getImmutable();
        Element s_s=bp.getG1().newElementFromBytes(s_sstr.getBytes()).getImmutable();
        Element s_yita=bp.getG1().newElementFromBytes(s_yitastr.getBytes()).getImmutable();
        Element s_yita1=bp.getG1().newElementFromBytes(s_yita1str.getBytes()).getImmutable();
        Element s_ka=bp.getG1().newElementFromBytes(s_kastr.getBytes()).getImmutable();
        Element s_eps=bp.getG1().newElementFromBytes(s_epsstr.getBytes()).getImmutable();
        Element F1=bp.getG1().newElementFromBytes(F1str.getBytes()).getImmutable();
        Element F2=bp.getG1().newElementFromBytes(F2str.getBytes()).getImmutable();
        Element F3=bp.getG1().newElementFromBytes(F3str.getBytes()).getImmutable();
        Element F4=bp.getG1().newElementFromBytes(F4str.getBytes()).getImmutable();
        Element F5=bp.getG1().newElementFromBytes(F5str.getBytes()).getImmutable();


        Element c1=bp.pairing(g11,g2).powZn(s_eps).getImmutable();
        Element c2=bp.pairing(fai1,g2).powZn(s_yita.invert()).getImmutable();
        Element c3=bp.pairing(g12,g2).powZn(s_ka).getImmutable();
        Element c4=bp.pairing(u,g2).powZn(s_afa).getImmutable();
        Element c5=bp.pairing(u,Omiga_i).powZn(s_s).getImmutable();
        Element c6=(bp.pairing(g1,g2).div(bp.pairing(fai1,Omiga_i))).powZn(c).getImmutable();
        Element RgCert=c1.mul(c2.mul(c3.mul(c4.mul(c5.mul(c6))))).getImmutable();


        Element t1=bp.pairing(g11,g2).powZn(s_eps).getImmutable();
        Element t2=bp.pairing(fai2,g2).powZn(s_yita1.invert()).getImmutable();
        Element t3=bp.pairing(g1,g2).powZn(epsl_i).getImmutable();
        Element t4=bp.pairing(g1,g2).powZn(s_bta).getImmutable();
        Element t5=bp.pairing(g1,Gama).powZn(s_s).getImmutable();
        Element t6=(bp.pairing(g12.mul(g1),g2).div(bp.pairing(fai2,Gama))).powZn(c).getImmutable();
        Element Rtoken=t1.mul(t2.mul(t3.mul(t4.mul(t5.mul(t6))))).getImmutable();

        Element R1=g11.powZn(s_s).mul(F3).powZn(c.invert()).getImmutable();
        Element R2=g12.powZn(s_s).mul(F4).powZn(c.invert()).getImmutable();
        Element R3=(fai1.mul(fai2)).powZn(s_s).mul(F5).powZn(c.invert()).getImmutable();
        //V_j验证



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

    public static void main(String[] args) throws NoSuchAlgorithmException, InterruptedException {
        /*
        指定配置文件的路径
         */
        String dir = "./storeFile/Yue/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName=dir+"pk.properties";
        String secretKeyFileName=dir+"sk.properties";
        String certificateFileName=dir+"certi.properties";
        String authenticationFileName=dir+"auth.properties";
        String verifyFileName=dir+"Veri.properties";

        String RSU_A="KGC_A";
        String RSU_B="KGC_B";
        String OBU_i="Alice";
        String OBU_j="Bob";
        setup1(pairingParametersFileName, publicKeyFileName, mskFileName);
        Registration1(pairingParametersFileName,publicKeyFileName,mskFileName,RSU_A);
        Registration1(pairingParametersFileName,publicKeyFileName,mskFileName,RSU_B);
        Registration2(pairingParametersFileName,publicKeyFileName,mskFileName,OBU_i);
        Registration2(pairingParametersFileName,publicKeyFileName,mskFileName,OBU_j);
        Join1(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,RSU_A,OBU_i);
        Join2(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,RSU_A,OBU_i);
        Join1(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,RSU_B,OBU_j);
        Join2(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,RSU_B,OBU_j);
        long nums = 0;
        for (int i = 0; i < 10; i++) {
            long start_nanoTime = System.nanoTime();
            Authentication(pairingParametersFileName, publicKeyFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,RSU_A,OBU_i,OBU_j);
            Verify(pairingParametersFileName, publicKeyFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,verifyFileName,RSU_A,OBU_i,OBU_j);
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
