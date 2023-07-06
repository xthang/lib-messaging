//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package com.cystack.ready.libmessaging.crypto;

import java.io.IOException;
import junit.framework.TestCase;
import com.cystack.ready.libmessaging.protocol.InvalidKeyException;
import com.cystack.ready.libmessaging.protocol.util.Hex;

public class Aes256Ctr32Tests extends TestCase {

  public void testAesCtr32Kats() throws Exception {
    testAesCtr32Kat(
       "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
       "fd4c14729f5004ba49d832ad7be87c18f4fafb58962b9a43c3be41713ded93dbf854ac4ca26285b7f76e04b8f8d4e7d9f7548f9b465c8f713c106e9f63f54305331a4983a2f4b718de29fa794da12eee808642faeff8271a0ea28e3cc80eeb65a8eb61f69d8ba97f6bf9054453f55efb8f9422081f1620fe44acf99e81122f73d3f921d5e3391654e9947904984375b725fdfba895c5cde3d225d7be3a213c3965178a7dc1e3b552ec7b2ffd9c77ebcc243c4500dfdfbe3b7554aa427c01305bec48d71af27c5911d1e649c620d22cf5f3a5aeb9468651da796f369522faf91efabf0febd33fca41c9534606a4ea0199b904b243ba9cb8f37a792df02efab8f0e2e0cf1d579daba042cfe4c9430ad4eda786052fcf15e7acfa2736aab4590f73675fa1805fe23892c63e0cd01d006935a6e3f8e105a754803d00d9857e49636ab034164156856d58a244ead475300d93b31e44b5be3bbf6994edb895804b4f1bad43ecfe08b4e130148b669fe620e4f73034fc3e748237870bec3b1f517684654d1d6bc074ddf7b759a2405f78ed84d1006d25af9bbc12d6c632f5d543da0cbe9ea866b2c92126009c27ad59394b76337de246b50895317e2e345df3629a5f6227f64522866e7a39121ccc552e3dabc989dce066dea355f788c5d92ada099917a297cfefa867ce37656fac6a50798c10b394d5ba54f85cf0f7ef1eeddfca1e53e93f1349888cc745190c196f84ecf0721287cc592d406f0a6cc5a55294bf7aa3b35f6cefc61cab794b12444312b5e50ec0712e221cc95e9e26e9c3d000881e792afcb58641b1a94613d64ec72f3db9ab65ba07a4f05b7e9ee7b335d86a06fcbdb8cbd695aeef53964a965ffe4c6d7b4e580ab139f8422a702e09eacbea5d512c31a955b3d60310be2bbdd73484bae6612791a19da3c7b0fd1487e72131a8f9cb801790ce8a6e1e378662cedcd5ee82bd390576acfe5334ecd9d907273aefe67058916388210638e5e60f20ee92389b3533fd6affd33095b23d169f0913657f033b8d5c4ea517f167c1d53e031787bbe6d5b577245fff8151cd8fdcc5d6c32df70fb8043d42f896cd513b4c85cff292676cf13b6a1931e87727a561711a3105d9f3519b90c9429b5cd3edaae3ee334826a3fd74d6175b5589db392f956a67c5e67be59656f1cb37e52c636b2692a60c2044327472fa9af651afbcf55d8398a31d343074931a72d54833b29ef21fcb6ef419bb56313513e46c65d833677dbb0f2813e9ce5ef70676102ca0d3c14bbdd659a7498fa08cd359d428a803aefcc660e9fc704e9bacc5f1d27f2528d46b3fcaa2d47dfa28bf4c",
       "f0c1dd48e5843eb03de5abb298697dc0f103a9d0c230620bcd86467758379daa01ae18087d96096a8814e98808ab9b9c943917273054201ca3cdf2d49f3ac7896d34db1cb1d7959b4dd503f7b25b3390e0dbcacb15bbe8978236d75ae24d7ca0c4d516846ec0cc0e05b505b3d9d1c6e50165918c26672ed1525265b29f6336138cedca58e7f447a81b9485f743b5e01fd5a543f18d9335c5e2d19cae8245a9224a2baabdf7670e47bd22cf465df8563621124a8091325c670e4f8fa028686505cee87d52d63d1965e65daf61f5e1b00ae33d4e5a42496950e8d75710cf8c47718f6071850d11b552e19ba0fabef5ccc7813ba4bd0b593694b317f04fbe9caf48aff14a4555f78ab056d4148747c7bd5a8b6e4bc85d42aae4e2634ad9028e5f32345a6813c291588362a7ecf6e0c3b3a3db9dbaa82d2754962f5d9b3e0fd166cb11b5254081417dac0e35c00b56ebebd12112ae202c094fe3b24252f0787fb09c6c51036ceac6ddde4ac59aada7c76bc79e950b66ffe6a015450e8770c8b2b491ccec7610bf9a7f523e5a579ff64c62700a7e8304139c68cfdab34f7ad18b8989a9802ed9dd393d889cf4d526c9b53fdb0b78dcfad47b88c23d6992e0e63c31f80d69b427ea7e71944a61013a0c70b2e9cfe233a61cb4939d2fdde75e6ff8fee6b45d481ad0ad0110469edffc01b1bf2e4f1414f925d86ad198a27a0388637edc7dd547b8aeca86eccb3ad5c0615af8428096c8142d75235c465995e5eff6225e94913457551c1c185e1d7bfa2437ab56da49954834628ac480d7bada35ecbc34dc6efeb26009c82a0cc3f477757a91dc6d652ce7edd82cb891ba3b49bfeb74bd2a35b3f5bce74a34359dc00db8e0961cb9758cd99ef25cf718974d60ed5e7733f525c81edb0464c7930add3e9336d8715aeb37bb624844246a19d433c0ed615c221e5e89745d2467743773560639894b1abd0f6e5289b5826cee5fca76bdd6d0d4dd69fb4a50d7d814a48c7e35920abb8f0c1e60ba92d612f4f4bf5695a089de639bfbc6f317f4fd895d3257efbe1d49e944b82badd4b21164d4bae7a872f183a3c8385f54fdd8f471672132dd44e51ccdcfe183c0ce00032a048866af6dfea9e15b58a1709320e8fca16defeab233027a9ea3118a521c94be5c48a72de9c6fabf2196e123fc1356dea223712599758a2f6ffe91921c1acee3ec6c7b7a29a1d3c5f88ae6fb50b42e36c0773731e28ca3c93a18627d287ed5f538691421dffd36e3bb871854bc585f367edbe70b029f81f3605982eafa4135e54b78d0c6cdf18afe22ff7308da7011f15d3524906f10fb6b780fa9cc4b",
       "a6aad9eced14bf1c61910dba",
       35);
  }

  private static void testAesCtr32Kat(
      String hex_key,
      String hex_plaintext,
      String hex_ciphertext,
      String hex_nonce,
      int initialCtr) throws IOException, InvalidKeyException {

    byte[] key = Hex.fromStringCondensed(hex_key);
    byte[] plaintext = Hex.fromStringCondensed(hex_plaintext);
    byte[] nonce = Hex.fromStringCondensed(hex_nonce);

    Aes256Ctr32 ctr = new Aes256Ctr32(key, nonce, initialCtr);

    byte[] ciphertext = plaintext.clone();
    ctr.process(ciphertext);
    assertEquals(Hex.toStringCondensed(ciphertext), hex_ciphertext);
  }
}
