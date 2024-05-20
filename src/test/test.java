package test;

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

public class test {

    public static void setup1(String pairingFile) {

        //第一个变量是公共的参数文件，第二个变量是公共变量文件，第三个变量是主私钥变量文件
        Pairing bp = PairingFactory.getPairing(pairingFile);  //用于生成群G或者Zq元素的对象
        Element P1 = bp.getG1().newRandomElement().getImmutable();
        Element P2 = bp.getG1().newRandomElement().getImmutable();
        Element G = bp.pairing(P1,P2).getImmutable();
        Element G2 = bp.getGT().newRandomElement().getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        long nums = 0;
        for (int i = 0; i < 10; i++) {
            long start_nanoTime = System.nanoTime();
            Element K = bp.pairing(P1,P2);
            long end_nanoTime = System.nanoTime();
            nums += end_nanoTime-start_nanoTime;
        }
        System.out.println((double) nums/10000000);
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

        setup1(pairingParametersFileName);







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
