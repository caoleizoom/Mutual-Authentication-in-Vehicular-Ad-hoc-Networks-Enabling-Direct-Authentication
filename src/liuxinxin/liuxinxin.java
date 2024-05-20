package liuxinxin;

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

public class liuxinxin {

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
    public static void setup1(String pairingFile,String publicFile,String mskFile) throws NoSuchAlgorithmException {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象

        Element g2 = bp.getG2().newRandomElement().getImmutable();
        Element g1 = bp.getG1().newRandomElement().getImmutable();
        Element yita = bp.getG1().newRandomElement().getImmutable();
        Element pi = bp.getG1().newRandomElement().getImmutable();

        Element afa = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element lameda1 = bp.getZr().newRandomElement().getImmutable();
        Element lameda2 = bp.getZr().newRandomElement().getImmutable();
        Element tao1 =yita.powZn(lameda1).getImmutable();
        Element tao2 =pi.powZn(lameda1).getImmutable();
        Element oumiga1=g1.powZn(afa).getImmutable();
        Element oumiga2=g2.powZn(beta).getImmutable();

        Properties PubProp =loadPropFromFile(publicFile);
        PubProp.setProperty("g1",g1.toString());
        PubProp.setProperty("g2",g2.toString());
        PubProp.setProperty("yita",yita.toString());
        PubProp.setProperty("pi",pi.toString());
        PubProp.setProperty("tao1",tao1.toString());
        PubProp.setProperty("tao2",tao2.toString());
        PubProp.setProperty("oumiga1",oumiga1.toString());
        PubProp.setProperty("oumiga2",oumiga2.toString());
        storePropToFile(PubProp,publicFile);
        Properties mskProp = loadPropFromFile(mskFile);
        mskProp.setProperty("afa",Base64.getEncoder().encodeToString(afa.toBytes()));
        mskProp.setProperty("beta",Base64.getEncoder().encodeToString(beta.toBytes()));
        mskProp.setProperty("lameda1",Base64.getEncoder().encodeToString(lameda1.toBytes()));
        mskProp.setProperty("lameda2",Base64.getEncoder().encodeToString(lameda2.toBytes()));
        storePropToFile(mskProp,mskFile);
    }
    public  static  void service(String pairingFile,String publicFile,String mskFile,String ID_i){
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str = PubProp.getProperty("g1");
        String g2str = PubProp.getProperty("g2");
        String yitastr = PubProp.getProperty("yita");
        String pistr = PubProp.getProperty("pi");
        String tao1str = PubProp.getProperty("tao1");
        String tao2str = PubProp.getProperty("tao2");
        String oumiga1str = PubProp.getProperty("oumiga1");
        String oumiga2str = PubProp.getProperty("oumiga2");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2=bp.getG2().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element yita=bp.getG1().newElementFromBytes(yitastr.getBytes()).getImmutable();
        Element pi=bp.getG1().newElementFromBytes(pistr.getBytes()).getImmutable();
        Element tao1=bp.getG1().newElementFromBytes(tao1str.getBytes()).getImmutable();
        Element tao2=bp.getG1().newElementFromBytes(tao2str.getBytes()).getImmutable();
        Element oumiga1=bp.getG1().newElementFromBytes(oumiga1str.getBytes()).getImmutable();
        Element oumiga2=bp.getG2().newElementFromBytes(oumiga2str.getBytes()).getImmutable();
        Properties mskProp =loadPropFromFile(mskFile);
        String afastr = mskProp.getProperty("afa");
        String betastr = mskProp.getProperty("beta");
        String lameda1str = mskProp.getProperty("lameda1");
        String lameda2str = mskProp.getProperty("lameda2");
        Element afa=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(afastr)).getImmutable();
        Element beta=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betastr)).getImmutable();
        Element lameda1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda1str)).getImmutable();
        Element lameda2=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda2str)).getImmutable();

        Element T_0=bp.getG1().newRandomElement().getImmutable();
        PubProp.setProperty("T_"+ID_i,T_0.toString());
        storePropToFile(PubProp,publicFile);

    }
    public static void Join1(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String ID_i) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str = PubProp.getProperty("g1");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();



        //生成私钥
        Element y_i=bp.getZr().newRandomElement().getImmutable();
        Element b_i=bp.getZr().newRandomElement().getImmutable();
        Element Y_i=g1.powZn(y_i).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        pkp.setProperty("Y_"+ID_i,Y_i.toString());
        Properties skp=loadPropFromFile(skFile);
        skp.setProperty("b_"+ID_i,Base64.getEncoder().encodeToString(b_i.toBytes()));
        skp.setProperty("y_"+ID_i,Base64.getEncoder().encodeToString(y_i.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }
    public static void Join2(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String ID_i) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str = PubProp.getProperty("g1");
        String g2str = PubProp.getProperty("g2");
        String yitastr = PubProp.getProperty("yita");
        String pistr = PubProp.getProperty("pi");
        String tao1str = PubProp.getProperty("tao1");
        String tao2str = PubProp.getProperty("tao2");
        String oumiga1str = PubProp.getProperty("oumiga1");
        String oumiga2str = PubProp.getProperty("oumiga2");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2=bp.getG2().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element yita=bp.getG1().newElementFromBytes(yitastr.getBytes()).getImmutable();
        Element pi=bp.getG1().newElementFromBytes(pistr.getBytes()).getImmutable();
        Element tao1=bp.getG1().newElementFromBytes(tao1str.getBytes()).getImmutable();
        Element tao2=bp.getG1().newElementFromBytes(tao2str.getBytes()).getImmutable();
        Element oumiga1=bp.getG1().newElementFromBytes(oumiga1str.getBytes()).getImmutable();
        Element oumiga2=bp.getG2().newElementFromBytes(oumiga2str.getBytes()).getImmutable();
        Properties mskProp =loadPropFromFile(mskFile);
        String afastr = mskProp.getProperty("afa");
        String betastr =mskProp.getProperty("beta");
        String lameda1str = mskProp.getProperty("lameda1");
        String lameda2str = mskProp.getProperty("lameda2");
        Element afa=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(afastr)).getImmutable();
        Element beta=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betastr)).getImmutable();
        Element lameda1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda1str)).getImmutable();
        Element lameda2=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda2str)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        String Y_istr=pkp.getProperty("Y_"+ID_i);
        Element Y_i=bp.getG1().newElementFromBytes(Y_istr.getBytes()).getImmutable();

        Properties skp=loadPropFromFile(skFile);
        String b_istr=skp.getProperty("b_"+ID_i);
        String y_istr=skp.getProperty("y_"+ID_i);
        Element b_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(b_istr)).getImmutable();
        Element y_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y_istr)).getImmutable();

        Element x_i=bp.getZr().newRandomElement().getImmutable();
        Element gamama_i=bp.getZr().newRandomElement().getImmutable();
        Element K_1=(y_i.add(beta)).mul((x_i.add(gamama_i)).invert()).getImmutable();
        Element K_i=g1.powZn(K_1).getImmutable();

        pkp.setProperty("K_"+ID_i,K_i.toString());
        skp.setProperty("x_"+ID_i,Base64.getEncoder().encodeToString(x_i.toBytes()));
        skp.setProperty("gamama_"+ID_i,Base64.getEncoder().encodeToString(gamama_i.toBytes()));
        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }
    public static void Join3(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String ID_i,String ID_j) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String T_istr = PubProp.getProperty("T_"+ID_i);
        String T_jstr = PubProp.getProperty("T_"+ID_j);
        Element T_i=bp.getG1().newElementFromBytes(T_istr.getBytes()).getImmutable();
        Element T_j=bp.getG1().newElementFromBytes(T_jstr.getBytes()).getImmutable();
        Properties mskProp =loadPropFromFile(mskFile);
        String afastr = mskProp.getProperty("afa");
        Element afa=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(afastr)).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String b_istr=skp.getProperty("b_"+ID_i);
        String b_jstr=skp.getProperty("b_"+ID_j);
        Element b_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(b_istr)).getImmutable();
        Element b_j=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(b_jstr)).getImmutable();
        Element T1=T_i.powZn(b_i).mul(T_i.powZn(afa)).getImmutable();
        Element T_j1=T_i.mul(T_j.powZn(b_i.add(b_j.negate()))).getImmutable();
        PubProp.setProperty("T1"+ID_i,T1.toString());
        PubProp.setProperty("T1"+ID_j,T_j1.toString());
        storePropToFile(PubProp,publicFile);

    }

    public static void Authentication(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str = PubProp.getProperty("g1");
        String g2str = PubProp.getProperty("g2");
        String yitastr = PubProp.getProperty("yita");
        String pistr = PubProp.getProperty("pi");
        String tao1str = PubProp.getProperty("tao1");
        String tao2str = PubProp.getProperty("tao2");
        String oumiga1str = PubProp.getProperty("oumiga1");
        String oumiga2str = PubProp.getProperty("oumiga2");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2=bp.getG2().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element yita=bp.getG1().newElementFromBytes(yitastr.getBytes()).getImmutable();
        Element pi=bp.getG1().newElementFromBytes(pistr.getBytes()).getImmutable();
        Element tao1=bp.getG1().newElementFromBytes(tao1str.getBytes()).getImmutable();
        Element tao2=bp.getG1().newElementFromBytes(tao2str.getBytes()).getImmutable();
        Element oumiga1=bp.getG1().newElementFromBytes(oumiga1str.getBytes()).getImmutable();
        Element oumiga2=bp.getG2().newElementFromBytes(oumiga2str.getBytes()).getImmutable();
        String T_istr = PubProp.getProperty("T_"+ID_i);
        String T_jstr = PubProp.getProperty("T_"+ID_j);
        Element T_i=bp.getG1().newElementFromBytes(T_istr.getBytes()).getImmutable();
        Element T_j=bp.getG1().newElementFromBytes(T_jstr.getBytes()).getImmutable();

        Properties mskProp =loadPropFromFile(mskFile);
        String afastr = mskProp.getProperty("afa");
        String betastr = mskProp.getProperty("beta");
        String lameda1str = mskProp.getProperty("lameda1");
        String lameda2str = mskProp.getProperty("lameda2");
        Element afa=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(afastr)).getImmutable();
        Element beta=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betastr)).getImmutable();
        Element lameda1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda1str)).getImmutable();
        Element lameda2=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda2str)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        String Y_istr=pkp.getProperty("K_"+ID_i);
        String K_istr=pkp.getProperty("Y_"+ID_i);
        Element Y_i=bp.getG1().newElementFromBytes(Y_istr.getBytes()).getImmutable();
        Element K_i=bp.getG1().newElementFromBytes(K_istr.getBytes()).getImmutable();

        Properties skp=loadPropFromFile(skFile);
        String b_istr=skp.getProperty("b_"+ID_i);
        String y_istr=skp.getProperty("y_"+ID_i);
        String x_istr=skp.getProperty("x_"+ID_i);
        String gamama_istr=skp.getProperty("gamama_"+ID_i);
        Element b_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(b_istr)).getImmutable();
        Element y_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y_istr)).getImmutable();
        Element x_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_istr)).getImmutable();
        Element gamama_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamama_istr)).getImmutable();

        //V_i向V_j发消息
        Element u1=bp.getZr().newRandomElement().getImmutable();
        Element u2=bp.getZr().newRandomElement().getImmutable();
        Element vu=bp.getZr().newRandomElement().getImmutable();
        Element vx=bp.getZr().newRandomElement().getImmutable();
        Element vy=bp.getZr().newRandomElement().getImmutable();
        Element vu1=bp.getZr().newRandomElement().getImmutable();
        Element vu2=bp.getZr().newRandomElement().getImmutable();

        Element C_1=yita.powZn(u1).getImmutable();
        Element C_2=pi.powZn(u2).getImmutable();
        Element C_3=K_i.mul(tao1.powZn(u1.add(u2))).getImmutable();
        Element D_1=C_1.powZn(vx).mul(yita.powZn(vu1.negate())).getImmutable();
        Element D_2=C_2.powZn(vx).mul(pi.powZn(vu2.negate())).getImmutable();
        Element D_31=bp.pairing(C_3,g2).powZn(vx).getImmutable();
        Element D_32=bp.pairing(tao1,oumiga1).powZn(vu).getImmutable();
        Element D_33=bp.pairing(tao1,g2).powZn((vu1.add(vu2)).negate()).getImmutable();
        Element D_34=bp.pairing(g1,g2).powZn(vy).getImmutable();
        Element D_3=D_31.mul(D_32.mul(D_33.mul(D_34))).getImmutable();
        Element t=(T_i.powZn(g1.powZn(b_i))).mul(T_i.powZn(oumiga1));
        byte[] bH1=sha1(t.toString()+C_1.toString()+C_2.toString()+C_3.toString()+D_1.toString()+D_2.toString()+D_3.toString());
        Element c=bp.getZr().newElementFromHash(bH1,0,bH1.length).getImmutable();
        Element ru=vu.add((c.mul(u1.add(u2))).negate()).getImmutable();
        Element rx=vx.add(c.mul(x_i)).getImmutable();
        Element ry=vy.add((c.mul(y_i)).negate()).getImmutable();
        Element ru1=vu1.add(c.mul(x_i.mul(u1))).getImmutable();
        Element ru2=vu2.add(c.mul(x_i.mul(2))).getImmutable();

        Properties authp=new Properties();
        authp.setProperty("C_1",C_1.toString());
        authp.setProperty("C_2",C_2.toString());
        authp.setProperty("C_3",C_3.toString());
        authp.setProperty("c",c.toString());
        authp.setProperty("ru",ru.toString());
        authp.setProperty("rx",rx.toString());
        authp.setProperty("ry",ry.toString());
        authp.setProperty("ru1",ru1.toString());
        authp.setProperty("ru2",ru2.toString());
        storePropToFile(authp,authFile);
    }
    public static void Verify(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String veriFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties PubProp =loadPropFromFile(publicFile);
        String g1str = PubProp.getProperty("g1");
        String g2str = PubProp.getProperty("g2");
        String yitastr = PubProp.getProperty("yita");
        String pistr = PubProp.getProperty("pi");
        String tao1str = PubProp.getProperty("tao1");
        String tao2str = PubProp.getProperty("tao2");
        String oumiga1str = PubProp.getProperty("oumiga1");
        String oumiga2str = PubProp.getProperty("oumiga2");
        Element g1=bp.getG1().newElementFromBytes(g1str.getBytes()).getImmutable();
        Element g2=bp.getG2().newElementFromBytes(g2str.getBytes()).getImmutable();
        Element yita=bp.getG1().newElementFromBytes(yitastr.getBytes()).getImmutable();
        Element pi=bp.getG1().newElementFromBytes(pistr.getBytes()).getImmutable();
        Element tao1=bp.getG1().newElementFromBytes(tao1str.getBytes()).getImmutable();
        Element tao2=bp.getG1().newElementFromBytes(tao2str.getBytes()).getImmutable();
        Element oumiga1=bp.getG1().newElementFromBytes(oumiga1str.getBytes()).getImmutable();
        Element oumiga2=bp.getG2().newElementFromBytes(oumiga2str.getBytes()).getImmutable();
        String T_istr = PubProp.getProperty("T_"+ID_i);
        String T_jstr = PubProp.getProperty("T_"+ID_j);
        Element T_i=bp.getG1().newElementFromBytes(T_istr.getBytes()).getImmutable();
        Element T_j=bp.getG1().newElementFromBytes(T_jstr.getBytes()).getImmutable();

        Properties mskProp =loadPropFromFile(mskFile);
        String afastr = mskProp.getProperty("afa");
        String betastr = mskProp.getProperty("beta");
        String lameda1str = mskProp.getProperty("lameda1");
        String lameda2str = mskProp.getProperty("lameda2");
        Element afa=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(afastr)).getImmutable();
        Element beta=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betastr)).getImmutable();
        Element lameda1=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda1str)).getImmutable();
        Element lameda2=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lameda2str)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        String Y_istr=pkp.getProperty("K_"+ID_i);
        String K_istr=pkp.getProperty("Y_"+ID_i);
        Element Y_i=bp.getG1().newElementFromBytes(Y_istr.getBytes()).getImmutable();
        Element K_i=bp.getG1().newElementFromBytes(K_istr.getBytes()).getImmutable();

        Properties skp=loadPropFromFile(skFile);
        String b_istr=skp.getProperty("b_"+ID_i);
        String y_istr=skp.getProperty("y_"+ID_i);
        String x_istr=skp.getProperty("x_"+ID_i);
        String gamama_istr=skp.getProperty("gamama_"+ID_i);
        Element b_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(b_istr)).getImmutable();
        Element y_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(y_istr)).getImmutable();
        Element x_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_istr)).getImmutable();
        Element gamama_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gamama_istr)).getImmutable();

        
        Properties authp=loadPropFromFile(authFile);
        String C_1str=authp.getProperty("C_1");
        String C_2str=authp.getProperty("C_2");
        String C_3str=authp.getProperty("C_3");
        String cstr=authp.getProperty("c");
        String rustr=authp.getProperty("ru");
        String rxstr=authp.getProperty("rx");
        String rystr=authp.getProperty("ry");
        String ru1str=authp.getProperty("ru1");
        String ru2str=authp.getProperty("ru2");
        Element C_1=bp.getG1().newElementFromBytes(C_1str.getBytes()).getImmutable();
        Element C_2=bp.getG1().newElementFromBytes(C_2str.getBytes()).getImmutable();
        Element C_3=bp.getG1().newElementFromBytes(C_3str.getBytes()).getImmutable();
        Element c=bp.getZr().newElementFromBytes(cstr.getBytes()).getImmutable();
        Element ru=bp.getZr().newElementFromBytes(rustr.getBytes()).getImmutable();
        Element rx=bp.getZr().newElementFromBytes(rxstr.getBytes()).getImmutable();
        Element ry=bp.getZr().newElementFromBytes(rystr.getBytes()).getImmutable();
        Element ru1=bp.getZr().newElementFromBytes(ru1str.getBytes()).getImmutable();
        Element ru2=bp.getZr().newElementFromBytes(ru2str.getBytes()).getImmutable();

        Element D_1=(C_1.powZn(rx)).mul(yita.powZn(ru1.negate())).getImmutable();
        Element D_2=(C_2.powZn(rx)).mul(pi.powZn(ru2.negate())).getImmutable();
        Element D_31=bp.pairing(C_3,g2).powZn(rx).getImmutable();
        Element D_32=bp.pairing(tao1,oumiga1).powZn(ru).getImmutable();
        Element D_33=bp.pairing(tao1,g2).powZn((ru1.add(ru2)).negate()).getImmutable();
        Element D_34=bp.pairing(g1,g2).powZn(ry).getImmutable();
        Element D_35=bp.pairing(C_3,oumiga1).powZn(c).getImmutable();
        Element D_36=bp.pairing(g1,oumiga2).powZn(c.negate()).getImmutable();
        Element D_3=D_31.mul(D_32.mul(D_33.mul(D_34.mul(D_35.mul(D_36))))).getImmutable();
        Element t1=T_i.powZn(g1).getImmutable();
        byte[] bH1=sha1(t1.toString()+C_1.toString()+C_2.toString()+C_3.toString()+D_1.toString()+D_2.toString()+D_3.toString());
        Element c1=bp.getZr().newElementFromHash(bH1,0,bH1.length).getImmutable();
    }


    public static  Element fai(String pairingFile,Element g) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Element a=bp.getZr().newRandomElement().getImmutable();
        Element g1=g.powZn(a).getImmutable();
        byte[] bg1=sha1(g1.toString());
        Element g2=bp.getG1().newElementFromHash(bg1,0,bg1.length).getImmutable();
        return g2;
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
        String dir = "./storeFile/liuxinxin/"; //根路径
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
        setup1(pairingParametersFileName,publicKeyFileName,mskFileName);
        service(pairingParametersFileName,publicKeyFileName,mskFileName,ID_i);
        Join1(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,ID_i);
        Join2(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,ID_i);
        service(pairingParametersFileName,publicKeyFileName,mskFileName,ID_j);
        Join1(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,ID_j);
        Join2(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,ID_j);
        Join3(pairingParametersFileName,publicKeyFileName,mskFileName,publicKeyFileName,secretKeyFileName,ID_i,ID_j);
        long nums = 0;
        for (int i = 0; i < 10; i++) {
            long start_nanoTime = System.nanoTime();
            Authentication(pairingParametersFileName,publicKeyFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,KGC_A,ID_i,ID_j);
            Verify(pairingParametersFileName, publicKeyFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,verifyFileName,KGC_A,ID_i,ID_j);
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
