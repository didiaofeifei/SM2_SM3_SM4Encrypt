package cn.xjfme.encrypt.test;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2SignVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVerUtils;

public class SecuritySM2to4Test {
    public static void main(String[] args) throws Exception {
        String src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
        String text = "这是一段明文";
        byte[] sourceData = text.getBytes();
        //String publicKey ="FA05C51AD1162133DFDF862ECA5E4A481B52FB37FF83E53D45FD18BBD6F32668A92C4692EEB305684E3B9D4ACE767F91D5D108234A9F07936020A92210BA9447";
        //String privatekey = "5EB4DF17021CC719B678D970C620690A11B29C8357D71FA4FF9BF7FB6D89767A";
        String publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
        String privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";

        SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexStringToBytes(privatekey), Util.hexToByte(src));
        System.out.println("R:"+sign.sign_r);
        System.out.println("S:"+sign.sign_s);
        //验签硬加密的串
        String signYJ = "54720652E5EE53D14F338A03EDAC10E7F93D877EC2168F9287810807D02D2409F3EEE542638AD0B204BC3C8F93EDBCFBE87DEEFB07C0B36F34508AB49B6F90EF";
        SM2SignVO verify = SM2SignVerUtils.VerifySignSM2(Util.hexStringToBytes(publicKey), Util.hexToByte(src), Util.hexToByte(SecurityTestAll.SM2SignHardToSoft(signYJ)));
        System.err.println("验签结果" + verify.isVerify());
    }
}
