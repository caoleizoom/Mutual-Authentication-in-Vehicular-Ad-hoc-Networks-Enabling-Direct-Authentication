package Ours;

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

public class Ours {

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
        mskProp.setProperty("s_"+KGC_i, Base64.getEncoder().encodeToString(s_i.toBytes()));//element和string类型之间的转换需要通过bytes
        storePropToFile(mskProp, mskFile);

        //设置主公钥
        Element BSN_i = bp.getZr().newRandomElement().getImmutable();
        long sta = System.nanoTime();
        Element P_pubi = P.powZn(s_i).getImmutable();
        long end = System.nanoTime();
       // out.println(end-sta);

        PubProp.setProperty("BSN_"+KGC_i, BSN_i.toString());
        PubProp.setProperty("P_pub_"+KGC_i, P_pubi.toString());
        storePropToFile(PubProp,publicFile);

    }


    //Registration阶段
    public static void Registration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {

        //获得主公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);

        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String BSN_istr=pubProp.getProperty("BSN_"+KGC_i);
        String P_pubistr=pubProp.getProperty("P_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element BSN_i=bp.getZr().newElementFromBytes(BSN_istr.getBytes()).getImmutable();
        Element P_pubi=bp.getG1().newElementFromBytes(P_pubistr.getBytes()).getImmutable();
        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
        Element r_i=bp.getZr().newRandomElement().getImmutable();
        Element R_i=P.powZn(r_i).getImmutable();
        Element R_iH=P_pubi.powZn(r_i).getImmutable();
        byte[] bH1_i=sha1(R_iH.toString()+BSN_i.toString());
        Element H1_i=bp.getZr().newElementFromHash(bH1_i,0,bH1_i.length).getImmutable();

        pkp.setProperty("R_"+ID_i,R_i.toString());
        pkp.setProperty("H1_"+ID_i, H1_i.toString());
        skp.setProperty("r_"+ID_i,Base64.getEncoder().encodeToString(r_i.toBytes()));
        //设置车辆i的假名
        byte[] bID_i=ID_i.getBytes();
        Element h1R_i=R_i.powZn(H1_i).getImmutable();
        byte[] bh1R_i=h1R_i.toBytes();
        int n = Math.max(bh1R_i.length, bID_i.length);
        int m = Math.min(bh1R_i.length, bID_i.length);
        byte[] bPID_i=new byte[n];
        for (int i=0;i<m;i++)
            bPID_i[i]= (byte) (bh1R_i[i]^bID_i[i]);
        Element Pid_i=bp.getZr().newElementFromHash(bPID_i,0,bPID_i.length).getImmutable();
        pkp.setProperty("Pid_"+ID_i,Pid_i.toString());

        //KGC
        Element x_i=bp.getZr().newRandomElement().getImmutable();
        Element X_i=P.powZn(x_i).getImmutable();
        skp.setProperty("x_"+ID_i,Base64.getEncoder().encodeToString(x_i.toBytes()));
        pkp.setProperty("X_"+ID_i,X_i.toString());

        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }


    public static void Join(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String BSN_istr=pubProp.getProperty("BSN_"+KGC_i);
        String P_pubistr=pubProp.getProperty("P_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element i=bp.getZr().newElementFromBytes(BSN_istr.getBytes()).getImmutable();
        Element P_pubi=bp.getG1().newElementFromBytes(P_pubistr.getBytes()).getImmutable();

        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        //获取假名
        Properties pkp=loadPropFromFile(pkFile);
        String Pid_istr=pkp.getProperty("Pid_"+ID_i);
        String R_istr=pkp.getProperty("R_"+ID_i);
        Element Pid_i=bp.getZr().newElementFromBytes(Pid_istr.getBytes()).getImmutable();
        Element R_i=bp.getG1().newElementFromBytes(R_istr.getBytes()).getImmutable();
        //获得私钥
        Properties skp=loadPropFromFile(skFile);
        String r_istr=skp.getProperty("r_"+ID_i);
        Element r_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r_istr)).getImmutable();

        Properties certiProp=loadPropFromFile(certiFile);

        Element alfa_i=bp.getZr().newRandomElement().getImmutable();
        byte[] bf_i=sha1(Pid_i.toString()+alfa_i.toString());
        Element f_i=bp.getZr().newElementFromHash(bf_i,0,bf_i.length).getImmutable();
        Element bt_i=bp.getZr().newRandomElement().getImmutable();
        Element U_i=P.powZn(bt_i).getImmutable();
        Element Q_i=R_i.add(U_i).getImmutable();
        byte[] bc_i=sha1(Pid_i.toString()+Q_i.toString()+ f_i.toString());
        Element c_i=bp.getZr().newElementFromHash(bc_i,0,bc_i.length).getImmutable();
        Element l_i1=s_i.mul(c_i).getImmutable();
        Element l_i=bt_i.add(l_i1).getImmutable();

        certiProp.setProperty("alfa_"+ID_i,Base64.getEncoder().encodeToString(alfa_i.toBytes()));
        certiProp.setProperty("f_"+ID_i,Base64.getEncoder().encodeToString(f_i.toBytes()));
        certiProp.setProperty("bt_"+ID_i,Base64.getEncoder().encodeToString(bt_i.toBytes()));
        certiProp.setProperty("U_"+ID_i,Base64.getEncoder().encodeToString(U_i.toBytes()));
        certiProp.setProperty("Q_"+ID_i,Base64.getEncoder().encodeToString(Q_i.toBytes()));
        certiProp.setProperty("c_"+ID_i,Base64.getEncoder().encodeToString(c_i.toBytes()));
        certiProp.setProperty("l_"+ID_i,Base64.getEncoder().encodeToString(l_i.toBytes()));


        //车辆验证
        if (((P.powZn(l_i)).add(R_i)).isEqual(Q_i.add(P_pubi.powZn(c_i)))){
            Element t_i=r_i.add(l_i).getImmutable();
            certiProp.setProperty("t_"+ID_i,Base64.getEncoder().encodeToString(t_i.toBytes()));
        }

        storePropToFile(certiProp,certiFile);

    }

    public static void Authentication(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String BSN_istr=pubProp.getProperty("BSN_"+KGC_i);
        String P_pubistr=pubProp.getProperty("P_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element BSN_i=bp.getZr().newElementFromBytes(BSN_istr.getBytes()).getImmutable();
        Element P_pubi=bp.getG1().newElementFromBytes(P_pubistr.getBytes()).getImmutable();

        //获取假名
        Properties pkp=loadPropFromFile(pkFile);
        String Pid_istr=pkp.getProperty("Pid_"+ID_i);
        String X_jstr=pkp.getProperty("X_"+ID_j);
        Element Pid_i=bp.getZr().newElementFromBytes(Pid_istr.getBytes()).getImmutable();
        Element X_j=bp.getG1().newElementFromBytes(X_jstr.getBytes()).getImmutable();

        //获取证书
        Properties certip=loadPropFromFile(certiFile);
        String t_istr=certip.getProperty("t_"+ID_i);
        String c_istr=certip.getProperty("c_"+ID_i);
        String Q_istr=certip.getProperty("Q_"+ID_i);
        Element t_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(t_istr)).getImmutable();
        Element c_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(c_istr)).getImmutable();
        Element Q_i=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q_istr)).getImmutable();


        //V_i向V_j发消息
        byte[] N1=sha1(BSN_i.toString()+P_pubi.toString());
        Element N=bp.getG1().newElementFromHash(N1,0,N1.length).getImmutable();
        Element n=bp.getZr().newRandomElement().getImmutable();
        Element y=bp.getZr().newRandomElement().getImmutable();
        Element E=P.powZn(n.mul(t_i)).getImmutable();
        Element Z=Q_i.powZn(n).getImmutable();
        Element V=P.powZn(n.mul(c_i)).getImmutable();
        Element Y=P.powZn(y).getImmutable();
        Element Y1=X_j.powZn(y).getImmutable();
        byte[] bH51=sha1(Y.toString()+Y1.toString()+Pid_i.toString());
        Element H51=bp.getZr().newElementFromHash(bH51,0,bH51.length).getImmutable();
        Element sigema=y.add(n.mul(t_i.mul(H51))).getImmutable();
        Properties authp=new Properties();
        authp.setProperty("E",E.toString());
        authp.setProperty("Z",Z.toString());
        authp.setProperty("V",V.toString());
        authp.setProperty("sigema",sigema.toString());
        authp.setProperty("N",N.toString());
        authp.setProperty("Y1",Y1.toString());
        authp.setProperty("n",Base64.getEncoder().encodeToString(n.toBytes()));
        authp.setProperty("y",Base64.getEncoder().encodeToString(y.toBytes()));
        authp.setProperty("Y",Base64.getEncoder().encodeToString(Y.toBytes()));
        storePropToFile(authp,authFile);

    }
    public static void Verify(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String certiFile,String authFile,String veriFile,String KGC_i,String ID_i,String ID_j) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String Pstr=pubProp.getProperty("P");
        String P_pubistr=pubProp.getProperty("P_pub_"+KGC_i);
        Element P=bp.getG1().newElementFromBytes(Pstr.getBytes()).getImmutable();
        Element P_pubi=bp.getG1().newElementFromBytes(P_pubistr.getBytes()).getImmutable();

        //获取假名
        Properties pkp=loadPropFromFile(pkFile);
        String Pid_istr=pkp.getProperty("Pid_"+ID_i);
        Element Pid_i=bp.getZr().newElementFromBytes(Pid_istr.getBytes()).getImmutable();

        //获得私钥
        Properties skp=loadPropFromFile(skFile);
        String x_jstr=skp.getProperty("x_"+ID_j);
        Element x_j=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_jstr)).getImmutable();

        Properties authp=loadPropFromFile(authFile);
        String Estr=authp.getProperty("E");
        String Zstr=authp.getProperty("Z");
        String sigemastr=authp.getProperty("sigema");
        String Vstr=authp.getProperty("V");
        String Y1str=authp.getProperty("Y1");
        String Ystr=authp.getProperty("Y");
        String ystr=authp.getProperty("Y");
        String Nstr=authp.getProperty("N");
        Element E=bp.getG1().newElementFromBytes(Estr.getBytes()).getImmutable();
        Element Z=bp.getG1().newElementFromBytes(Zstr.getBytes()).getImmutable();
        Element V=bp.getG1().newElementFromBytes(Vstr.getBytes()).getImmutable();
        Element Y1=bp.getG1().newElementFromBytes(Y1str.getBytes()).getImmutable();
        Element Y=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ystr)).getImmutable();
        Element y=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ystr)).getImmutable();
        Element N=bp.getG1().newElementFromBytes(Nstr.getBytes()).getImmutable();
        Element sigema=bp.getZr().newElementFromBytes(sigemastr.getBytes()).getImmutable();


        Properties verip=new Properties();

        //V_j验证

        Element l1= bp.pairing(E, P).getImmutable();
        Element r1=bp.pairing(Z,P).getImmutable();
        Element r2=bp.pairing(V,P_pubi).getImmutable();
        if(l1.isEqual(r1.mul(r2))){
           // out.println("1");
            Element Y_j=Y1.powZn(x_j.invert()).getImmutable();

            byte[] bH52=sha1(Y_j.toString()+Y1.toString()+Pid_i.toString());
            Element H52=bp.getZr().newElementFromHash(bH52,0,bH52.length).getImmutable();


            if ((P.powZn(sigema)).isEqual(Y_j.add(E.powZn(H52)))){
                //out.println("2");
                //out.println("V_i验证成功");
                Element w=bp.getZr().newRandomElement().getImmutable();
                Element W=P.powZn(w).getImmutable();
                verip.setProperty("W",W.toString());
                Element R=Y_j.powZn(w).getImmutable();
                Element L=W.powZn(y).getImmutable();
                //if ((R).isEqual(L))
                    //out.println("6");
                //out.println(Y);
                //out.println(Y_j);
               // if ((Y_j).equals(Y))
                   // out.println("1");

                byte[] bK_j=sha1(Y_j.toString()+W.toString()+R.toString());
                Element K_j=bp.getZr().newElementFromHash(bK_j,0,bK_j.length);

                byte[] bK_i=sha1(Y.toString()+W.toString()+L.toString());
                Element K_i=bp.getZr().newElementFromHash(bK_i,0,bK_i.length);
                //out.println(K_i);

                skp.setProperty("K1",K_j.toString());
                storePropToFile(skp,skFile);
                storePropToFile(verip,veriFile);
            }
            else {
                out.println("验证失败2");
            }
        }
        else{
            out.println("验证失败1");
        }

    }
    public static void Sessionkey(String pairingFile,String skFile,String authFile,String veriFile) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties skp=loadPropFromFile(skFile);
        Properties authp=loadPropFromFile(authFile);
        String Ystr = authp.getProperty("Y");
        String ystr = authp.getProperty("y");

        Element Y=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ystr)).getImmutable();
        Element y=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ystr)).getImmutable();

        Properties verip=loadPropFromFile(veriFile);
        String Wstr=verip.getProperty("W");

        Element W=bp.getG1().newElementFromBytes(Wstr.getBytes()).getImmutable();

        byte[] bK_i=sha1(Y.toString()+W.toString()+(W.powZn(y)).toString());
        Element K_i=bp.getZr().newElementFromHash(bK_i,0,bK_i.length).getImmutable();
        skp.setProperty("K2",K_i.toString());
        storePropToFile(skp,skFile);


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
        String dir = "./storeFile/Ours_File/"; //根路径
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
        Join(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,certificateFileName,KGC_A,ID_i);
        Join(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,certificateFileName,KGC_B,ID_j);

        long nums = 0;
        for (int i = 0; i < 10; i++) {
            long start_nanoTime = System.nanoTime();
            Authentication(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,KGC_A,ID_i,ID_j);
            long end_nanoTime = System.nanoTime();
            nums += end_nanoTime-start_nanoTime;
        }
        System.out.println((double) nums/10000000);

        Verify(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, certificateFileName,authenticationFileName,verifyFileName,KGC_A,ID_i,ID_j);
        Sessionkey(pairingParametersFileName,secretKeyFileName,authenticationFileName,verifyFileName);








        }





        /*long start1 = System.currentTimeMillis();

            long end1= System.currentTimeMillis();
            System.out.println(end1 - start1);


        */



}
