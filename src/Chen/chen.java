package Chen;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.zip.ZipEntry;

import static java.lang.System.out;

public class chen {

    public static void setup1(String pairingFile,String publicFile) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P1 = bp.getG1().newRandomElement().getImmutable();
        Element P2 = bp.getG1().newRandomElement().getImmutable();
        Properties PubProp =new Properties();
        PubProp.setProperty("P1",P1.toString());
        PubProp.setProperty("P2",P2.toString());
        storePropToFile(PubProp,publicFile);

    }
    public static void setup(String pairingFile,  String publicFile,String mskFile,String KGC_i) {
        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Properties PubProp =loadPropFromFile(publicFile);
        String P1str=PubProp.getProperty("P1");
        String P2str=PubProp.getProperty("P2");
        Element P1=bp.getG1().newElementFromBytes(P1str.getBytes()).getImmutable();
        Element P2=bp.getG1().newElementFromBytes(P2str.getBytes()).getImmutable();
        //调用两次setup函数为了不代替之前的数据，用loadPropFromFile打开文件并直接取其中数据

        Properties mskProp = loadPropFromFile(mskFile);  //定义一个对properties文件操作的对象
        //设置KGC_A和KGC_B的主私钥
        Element d_i = bp.getZr().newRandomElement().getImmutable();//从Zq上任选一个数
        Element s_i = bp.getZr().newRandomElement().getImmutable();
        Element u_i = bp.getZr().newRandomElement().getImmutable();
        Element v_i = bp.getZr().newRandomElement().getImmutable();
        mskProp.setProperty("d_"+KGC_i, Base64.getEncoder().encodeToString(d_i.toBytes()));//element和string类型之间的转换需要通过bytes
        mskProp.setProperty("s_"+KGC_i, Base64.getEncoder().encodeToString(s_i.toBytes()));
        mskProp.setProperty("u_"+KGC_i, Base64.getEncoder().encodeToString(u_i.toBytes()));
        mskProp.setProperty("v_"+KGC_i, Base64.getEncoder().encodeToString(v_i.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥
        Element D_i = P2.powZn(d_i).getImmutable();
        Element S_i = P2.powZn(s_i).getImmutable();
        Element U_i = P1.powZn(u_i).getImmutable();
        Element V_i = P2.powZn(v_i).getImmutable();
        Element g1_i=bp.pairing(P1,P2).getImmutable();
        Element g2_i=bp.pairing(P1,V_i).getImmutable();
        Element g3_i=bp.pairing(U_i,S_i).getImmutable();

        PubProp.setProperty("D_"+KGC_i, D_i.toString());
        PubProp.setProperty("S_"+KGC_i, S_i.toString());
        PubProp.setProperty("U_"+KGC_i, U_i.toString());
        PubProp.setProperty("V_"+KGC_i, V_i.toString());
        PubProp.setProperty("g1_"+KGC_i, g1_i.toString());
        PubProp.setProperty("g2_"+KGC_i, g2_i.toString());
        PubProp.setProperty("g3_"+KGC_i, g3_i.toString());
        storePropToFile(PubProp,publicFile);

    }


    public static void Registration(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String KGC_i,String ID_i) throws NoSuchAlgorithmException {

        //获得主公钥
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String P1str=pubProp.getProperty("P1");
        String P2str=pubProp.getProperty("P2");
        Element P1=bp.getG1().newElementFromBytes(P1str.getBytes()).getImmutable();
        Element P2=bp.getG2().newElementFromBytes(P2str.getBytes()).getImmutable();

        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String d_istr=mskp.getProperty("d_"+KGC_i);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        Element d_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(d_istr)).getImmutable();
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        Properties skp=loadPropFromFile(skFile);

        //生成私钥
        Element x_i=bp.getZr().newRandomElement().getImmutable();
        Element Z_i=P1.powZn((s_i.invert()).mul(d_i.add(x_i.negate()))).getImmutable();
        Element tag_i1=bp.pairing(Z_i,P2).getImmutable();
        byte[] btag_i=sha1(tag_i1.toString());
        Element tag_i=bp.getZr().newElementFromHash(btag_i,0,btag_i.length).getImmutable();

        pkp.setProperty("tag_"+ID_i,tag_i.toString());
        skp.setProperty("x_"+ID_i,Base64.getEncoder().encodeToString(x_i.toBytes()));
        skp.setProperty("Z_"+ID_i,Base64.getEncoder().encodeToString(Z_i.toBytes()));

        storePropToFile(pkp,pkFile);
        storePropToFile(skp,skFile);

    }

    public static void sign(String pairingFile,String publicFile,String mskFile,String pkFile,String skFile,String signFile,String msg,String KGC_i,String ID_i) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String P1str=pubProp.getProperty("P1");
        String P2str=pubProp.getProperty("P2");
        String D_istr=pubProp.getProperty("D_"+KGC_i);
        String S_istr=pubProp.getProperty("S_"+KGC_i);
        String U_istr=pubProp.getProperty("U_"+KGC_i);
        String V_istr=pubProp.getProperty("V_"+KGC_i);
        String g1_istr=pubProp.getProperty("g1_"+KGC_i);
        String g2_istr=pubProp.getProperty("g2_"+KGC_i);
        String g3_istr=pubProp.getProperty("g3_"+KGC_i);

        Element P1=bp.getG1().newElementFromBytes(P1str.getBytes()).getImmutable();
        Element P2=bp.getG2().newElementFromBytes(P2str.getBytes()).getImmutable();
        Element D_i=bp.getG2().newElementFromBytes(D_istr.getBytes()).getImmutable();
        Element S_i=bp.getG2().newElementFromBytes(S_istr.getBytes()).getImmutable();
        Element U_i=bp.getG1().newElementFromBytes(U_istr.getBytes()).getImmutable();
        Element V_i=bp.getG2().newElementFromBytes(V_istr.getBytes()).getImmutable();
        Element g1_i=bp.getGT().newElementFromBytes(g1_istr.getBytes()).getImmutable();
        Element g2_i=bp.getGT().newElementFromBytes(g2_istr.getBytes()).getImmutable();
        Element g3_i=bp.getGT().newElementFromBytes(g3_istr.getBytes()).getImmutable();

        //获得主私钥
        Properties mskp=loadPropFromFile(mskFile);
        String d_istr=mskp.getProperty("d_"+KGC_i);
        String s_istr=mskp.getProperty("s_"+KGC_i);
        String u_istr=mskp.getProperty("u_"+KGC_i);
        String v_istr=mskp.getProperty("v_"+KGC_i);
        Element d_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(d_istr)).getImmutable();
        Element s_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element u_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(u_istr)).getImmutable();
        Element v_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(v_istr)).getImmutable();

        Properties pkp=loadPropFromFile(pkFile);
        String tag_istr=pkp.getProperty("tag_"+ID_i);
        Element tag_i=bp.getZr().newElementFromBytes(tag_istr.getBytes()).getImmutable();
        Properties skp=loadPropFromFile(skFile);
        String x_istr=skp.getProperty("x_"+ID_i);
        String Z_istr=skp.getProperty("Z_"+ID_i);
        Element x_i=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_istr)).getImmutable();
        Element Z_i=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Z_istr)).getImmutable();

        //V_i向V_j发消息
        Element k=bp.getZr().newRandomElement().getImmutable();
        Element r=bp.getZr().newRandomElement().getImmutable();
        Element C1=P1.powZn(k).getImmutable();
        Element C2=(Z_i.powZn(r)).add(U_i.powZn(k)).getImmutable();
        Element C3=P1.powZn(r).getImmutable();
        Element C4=V_i.powZn(r.invert()).getImmutable();
        Element Q=g3_i.powZn(k).getImmutable();
        Element C5=bp.pairing(C1,P2).getImmutable();
        Element C6=g1_i.powZn(x_i.mul(r)).getImmutable();
        Element C7=g3_i.powZn(x_i.mul(r)).getImmutable();
        byte[] bc=sha1(C1.toString()+C2.toString()+C3.toString()+C4.toString()+Q.toString()+C5.toString()+C6.toString()+C7.toString()+msg);
        Element c=bp.getZr().newElementFromHash(bc,0,bc.length);
        Element w=(x_i.mul(r)).add((k.mul(c)).negate()).getImmutable();

        Properties signp=new Properties();
        signp.setProperty("C1",C1.toString());
        signp.setProperty("C2",C2.toString());
        signp.setProperty("C3",C3.toString());
        signp.setProperty("C4",C4.toString());
        signp.setProperty("c",c.toString());
        signp.setProperty("w",w.toString());
        skp.setProperty("k",Base64.getEncoder().encodeToString(k.toBytes()));
        storePropToFile(skp,skFile);

        storePropToFile(signp,signFile);
    }
    public static void Verify(String pairingFile,String publicFile,String skFile,String signFile,String msg,String veriFile,String KGC_i) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String P1str=pubProp.getProperty("P1");
        String P2str=pubProp.getProperty("P2");
        String D_istr=pubProp.getProperty("D_"+KGC_i);
        String S_istr=pubProp.getProperty("S_"+KGC_i);
        String g1_istr=pubProp.getProperty("g1_"+KGC_i);
        String g2_istr=pubProp.getProperty("g2_"+KGC_i);
        String g3_istr=pubProp.getProperty("g3_"+KGC_i);

        Element P1=bp.getG1().newElementFromBytes(P1str.getBytes()).getImmutable();
        Element P2=bp.getG2().newElementFromBytes(P2str.getBytes()).getImmutable();
        Element D_i=bp.getG2().newElementFromBytes(D_istr.getBytes()).getImmutable();
        Element S_i=bp.getG2().newElementFromBytes(S_istr.getBytes()).getImmutable();
        Element g1_i=bp.getGT().newElementFromBytes(g1_istr.getBytes()).getImmutable();
        Element g2_i=bp.getGT().newElementFromBytes(g2_istr.getBytes()).getImmutable();
        Element g3_i=bp.getGT().newElementFromBytes(g3_istr.getBytes()).getImmutable();



        Properties skp=loadPropFromFile(skFile);

        Properties signp=loadPropFromFile(signFile);
        String C1str=signp.getProperty("C1");
        String C2str=signp.getProperty("C2");
        String C3str=signp.getProperty("C3");
        String C4str=signp.getProperty("C4");
        String cstr=signp.getProperty("c");
        String wstr=signp.getProperty("w");

        Element C1=bp.getG1().newElementFromBytes(C1str.getBytes()).getImmutable();
        Element C2=bp.getG1().newElementFromBytes(C2str.getBytes()).getImmutable();
        Element C3=bp.getG1().newElementFromBytes(C3str.getBytes()).getImmutable();
        Element C4=bp.getG2().newElementFromBytes(C4str.getBytes()).getImmutable();
        Element c=bp.getZr().newElementFromBytes(cstr.getBytes()).getImmutable();
        Element w=bp.getZr().newElementFromBytes(wstr.getBytes()).getImmutable();

        Properties verip=new Properties();

        //V_j验证
        Element Y1=bp.pairing(C2,S_i).getImmutable();
        Element Y2=bp.pairing((P1.powZn(w)).add(C1.powZn(c)),P2).getImmutable();
        Element Y3=bp.pairing(C3,D_i).getImmutable();
        Element Q1=((Y1.mul(Y2)).div(Y3)).getImmutable();
        Element Y4=bp.pairing(C1,P2).getImmutable();
        Element Y5=(g1_i.powZn(w)).mul(bp.pairing(C1,P2).powZn(c)).getImmutable();
        Element Y6=(g3_i.powZn(w)).mul(Q1.powZn(c)).getImmutable();
        byte[] bc1=sha1(C1.toString()+C2.toString()+C3.toString()+C4.toString()+Q1.toString()+Y4.toString()+Y5.toString()+Y6.toString()+msg);
        Element c1=bp.getZr().newElementFromHash(bc1,0,bc1.length);
        if (g2_i.isEqual(bp.pairing(C3,C4))){
            out.println("1成功");
            if (c.isEqual(c1)) {
                String equtation="2chenggong";
                out.println("2chenggong");
                verip.setProperty("equtation",equtation);
            }
            else {
                String equtation="2shibai";
                out.println("2shibai");
                verip.setProperty("equtation",equtation);
            }
        }
        else{
            String equtation="1shibai";
            out.println("1shibai");
            verip.setProperty("equtation",equtation);
        }
        storePropToFile(verip,veriFile);

        String kstr = skp.getProperty("k");
        Element k=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(kstr)).getImmutable();
        Element t=bp.getZr().newRandomElement().getImmutable();
        byte[] bh=sha1(msg);
        Element h=bp.getZr().newElementFromHash(bh,0,bh.length);
        Element l=P1.powZn(t).getImmutable();
        Element m=(t.invert()).mul((h.add(k))).getImmutable();
        skp.setProperty("t",Base64.getEncoder().encodeToString(t.toBytes()));
        skp.setProperty("h",Base64.getEncoder().encodeToString(h.toBytes()));
        skp.setProperty("l",Base64.getEncoder().encodeToString(l.toBytes()));
        skp.setProperty("m",Base64.getEncoder().encodeToString(m.toBytes()));
        storePropToFile(skp,skFile);
    }
    public static void Sessionkey(String pairingFile,String publicFile,String skFile,String signFile) throws NoSuchAlgorithmException {
        Pairing bp=PairingFactory.getPairing(pairingFile);
        Properties pubProp=loadPropFromFile(publicFile);
        String P1str=pubProp.getProperty("P1");
        Element P1=bp.getG2().newElementFromBytes(P1str.getBytes()).getImmutable();

        Properties signp=loadPropFromFile(signFile);
        String C1str=signp.getProperty("C1");
        Element C1=bp.getG1().newElementFromBytes(C1str.getBytes()).getImmutable();

        Properties skp=loadPropFromFile(skFile);
        String hstr=skp.getProperty("h");
        String lstr=skp.getProperty("l");
        String mstr=skp.getProperty("m");
        Element h=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(hstr)).getImmutable();
        Element l=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lstr)).getImmutable();
        Element m=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mstr)).getImmutable();

       Element u1=(m.invert()).mul(h).getImmutable();
       Element u2=l.mul(m.invert()).getImmutable();
       Element l1=(P1.powZn(u1)).add(C1.powZn(u2)).getImmutable();

       skp.setProperty("u1",u1.toString());
       skp.setProperty("u2",u2.toString());
       skp.setProperty("l1",l1.toString());

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
        String dir = "./storeFile/Chen/"; //根路径
        String pairingParametersFileName = dir + "a.properties";

        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String publicKeyFileName = dir + "pk.properties";
        String secretKeyFileName = dir + "sk.properties";
        String signFileName = dir + "sign.properties";
        String verifyFileName = dir + "Veri.properties";

        String KGC_A = "KGC_A";
        String KGC_B = "KGC_B";
        String ID_i = "Alice";
        String ID_j = "Bob";
        String msg = "abcdef";
        setup1(pairingParametersFileName, publicParameterFileName);
        setup(pairingParametersFileName, publicParameterFileName, mskFileName, KGC_A);
        setup(pairingParametersFileName, publicParameterFileName, mskFileName, KGC_B);
        Registration(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, KGC_A, ID_i);
        Registration(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, KGC_B, ID_j);
        long nums = 0;
        for (int i = 0; i < 1; i++) {
            long start_nanoTime = System.nanoTime();
            sign(pairingParametersFileName, publicParameterFileName, mskFileName, publicKeyFileName, secretKeyFileName, signFileName, msg, KGC_A, ID_i);
            Verify(pairingParametersFileName, publicParameterFileName, secretKeyFileName, signFileName, msg, verifyFileName, KGC_A);
            Sessionkey(pairingParametersFileName, publicParameterFileName, secretKeyFileName, signFileName);
            long end_nanoTime = System.nanoTime();
            nums += end_nanoTime-start_nanoTime;
        }
        System.out.println((double) nums/1000000);








       /* for (int i=0;i<10;i++){
            //long sta = System.currentTimeMillis();
            setup1(pairingParametersFileName,publicParameterFileName);
            setup(pairingParametersFileName,publicParameterFileName,mskFileName,KGC_A);
            //long end = System.currentTimeMillis();
            //out.println(end-sta);
        }

        setup(pairingParametersFileName,publicParameterFileName,mskFileName,KGC_B);


        Join(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,certificateFileName,KGC_A,ID_i);
        Join(pairingParametersFileName,publicParameterFileName,mskFileName,publicKeyFileName,secretKeyFileName,certificateFileName,KGC_B,ID_j);










        /*long start1 = System.currentTimeMillis();

            long end1= System.currentTimeMillis();
            System.out.println(end1 - start1);


        */

    }

}
