// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SolRsaVerify} from "@libraries/RsaVerify.sol";

contract pkcs1Sha256Verify is Test {
    using SolRsaVerify for bytes32;

    bytes32 internal constant DIGEST = hex"8350ef0cdbc7e5731e6a5a1eba9a25deaff11133fc74df5bc16f68a026410aa2";
    bytes32 internal constant SHA256_HASHED = hex"a7b437b954aec5b28791525a83e0a43fe52c4212b52dd8af155d83a286347f13";
    bytes internal constant EXPONENT =
        hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    bytes internal constant SIGNATURE =
        hex"2f3e75ef281ab26ede549adb90efc875f1eb6fbfad47fa3e7d84b9e1d67a536672fdb9b3e7ec2b9a0ed50ffe1825e90aa289ba596f1f0196db82f34bea7e9d1afc79fd631a5e354b3bb845a6bbb8a3418d738ad0f2211313903476afea8438a63a3049444da44d97b3f0064c8d33a21b765327a37cef2f42788619a37eebf7e8919524b55b0dc2c78b89a1f680a00ce8762ce61f4054514640ad5221a9e5961e44499dc00d98d57c66e4a5276e4a44adae4f1da8200410a0fe237fd85c7bfe4c7f122bb01cfa9f2409c5fad9cc8de22b3720d856afdae8f7eb8c9cb3b2f16be1bb45ae21b844a11837d00ba48962862332b3e49dc00a132772892eceb2ad1b90";
    bytes internal constant MODULUS =
        hex"8f6047064f400fd2ff80ad6569c2cffc238079e2cb18648305a59b9f1f389730f9bf9b5e3e436f88065c06241c7189ba43b6adbe5ec7a979d4b42f2a450cd19e8075e5a817b04328a0d16ebfcb6bc09a96020217af6218f3765dbc129131edd004472ab45908bf02ec35b7c044e1c900f7df179fc19c94835802e58c432bc73cee54148a6f24d7316cca195791c87e07e85b07f80b71ddc15b9b053e6f0265a8e81c27c7546dea38cbb951ca71c384892b81df12c8cb0444f9e04d24d0d3323fa857075be26746f4b731a186a51cec24151597b9d31c9ef78db83f27ef0d973d4d2a2d8a9093c7118bf86322603a17d7814a05f6150963b72a275f645a099319";

    function test_Success() public {
        uint256 ret = SHA256_HASHED.pkcs1Sha256Verify(SIGNATURE, EXPONENT, MODULUS);
        assertTrue(ret == 0, "Expected pkcs1Sha256Verify to succeed, but it actually failed.");
    }

    // Test to validate the prefix should start with 0x00 0x01
    function test_Fail_RsaSignatureHasInvalidPrefix() public {
        bytes memory INVALID_MODULUS =
            hex"ca5cec413f678e01813c72c1386737098f0f03007d84634387abb332163d29161da824a2a2bd676463a3eb5929d84e24083e21ae2705b11ca6e5249e2516faf93c7fb5f9e5dfaf6cf3e59e43d70133c45ab1a965b2998278741e1ed30788857fa2987e75d60f461c832fdf9e41fa08f9b8d9fe4ca2081a8f46ffa371876050399718513d3b9ff2fff834ef317eb4f725d24176d127aed19e72ac0cc98dfefccadf7949b4bf494b7e6d43d4cf346bfd822c735371740c8e5b668a42617cc4ba6b91029fb0e14a30c9b3bba429c2c42929cbca00ea5053ccd48236a2235347bdf0982212e6cd9c31b2083190633836612c239555ac0df8d3ce173ede2291ce16b5";
        uint256 ret = SHA256_HASHED.pkcs1Sha256Verify(SIGNATURE, EXPONENT, INVALID_MODULUS);
        assertTrue(
            ret == 1,
            "Expected pkcs1Sha256Verify to fail due to an invalid prefix; the prefix should start with 0x00 0x01. However, this issue was not encountered."
        );
    }

    // Test to validate that the padding is as expected
    // RSA PKCS#1 v1.5 requires the padding to be in a specific format starting with 0x0001 and filled with 0xFF bytes.
    // This test verifies that the padding adheres to this specification.
    function test_Fail_RsaSignatureHasInvalidPaddingScheme() public {
        bytes memory SHA512_SIGNATURE =
            hex"8dd73fee384987ee90983501dfd6972e458fd40349593e55b207c9eb03dd348b5637852b6fb1413496f4a113cc1c3cd31488458af54bb0fe88973a8465267673026c3b9498848ee513ad6e3482d0a234c4f0232d503f6e4b36c33dbc84c802b40e08f01b1a1d65d7975e73b4d44d03d8fc29980b7a167b8a1b1d0dbc7cc06fc959cc0a0047e548091af3b55ea15edc5304ffd55dd5739b1d7bcc9e72f14bf844754e807fef963c9b43e54f850ec6438d6e67e11485bb3fa047994e429c606747704ac0b8f902a71b0d20c3050685bb8e99f234538f36b1f4c8f2c2b7ea5cacd4e766cd36ed2ccddf6d461aca3eb5fc9fb75634a29568e89c001c6e0013d9ba09";
        bytes memory SHA512_MODULUS =
            hex"AC686AC03C51F641F94534EA7EF67901C5275F694269E1252EB6B2BDE4458FD7471F1033D719522FBEAC6A7FFC27435896FB5152A593DF2E14329B4918440319491893CC820FA86E3442820244469141F9399E56980EE7AAC1765E29C0AE4DC2E8315FE518674E24E24A88DA875DBE808E68C1A81A586053AC7956E8B3A1D4F3421E81E0F2F7694F064F04E637951B665A9BD547894E23682C0C47845CF080B95AD798FA1CC2C8020F78908F80C99320287F8C657BFB4747B9496AB82B98738D5B7796DEA54F885C5E197B74118D181BF1E7AD35BF2C7B0178F8229C13CFC3CDDD5FCB76E295F246472637E40499C9742861F03786CA2B011EA54E6B501A0F33";
        uint256 ret = SHA256_HASHED.pkcs1Sha256Verify(SHA512_SIGNATURE, EXPONENT, SHA512_MODULUS);
        assertTrue(
            ret == 2,
            "Expected pkcs1Sha256Verify to fail due to unexpected padding. The padding should start with 0x0001, followed by 0xFF bytes until the digest info. For example: 0x0001FFFFFFFF...003031300d060960864801650304020105000420. However, this issue was not encountered."
        );
    }

    // Test to validate that the delimiter is 0x00
    // During signature verification, there should be a proper delimiter.
    function test_Fail_RsaSignatureHasInvalidDelimiter() public {
        bytes memory MD5_SIGNATURE =
            hex"6694e6cff07b38465f8008469e45d8a1ae805cd69ec61a8b76d2e420795a30cea3c2c36371343fe6d39a795d035235d62bda54541f36d8d24a40844216c3c43458edfd952b2dbb2271762193e7a449b61c1372e28a630619d81d996be065d28d7d2bf13770549e2f8fcd83c24a5276a8806a6262526e13b2e33677c0949d8775e2fc54ca1f540892fda5b66346faa93a9acf9b4c6c99ebae3e615dc68dc9132e271f261dc38889656c07a4630759f141d6b1f7a45f476a1f77af9ac21b0a535970e005db52923b9508cfdfc1c80dcad768caccb7147dd7c38d9dfef58beb75b2a936827adfdcd509a81bcf167f2e89454833a9de4f2a837efa5fd14961778421";
        bytes memory MD5_MODULUS =
            hex"9A83848F3DE3C07115C6C1ADDE5091DE5286D9672CD163ACF3F4F589C3BC47F45969C5CDD70E7EE13212D28A371ED6FBA5D61A0A8D8AE27A812119E1E0A073AF2C2BA046316332C39D7AD7CD53184C724EA2F14307CB828A282AAABF4D3F2157BE60BA74C06F1BADC0CF14DC7A75F92A7B5C16C7E00C9FB802F8A7D92D6F9C9F5A0A674062AB690A8D7314E2D8FDF369C20AF8AD444D2FC8E212F5F9B981E8C699BFFDD59956E6DDAEF0741A14D15F7AB8C7797A1DC250D40CB574BEA931108AD9D3F1BB9979A6957913B175AACB0BF771746C6E8ECE77A5738CE26CDFE5616B5C9729BC4F223B874B324127BBBA4AA1D810D2F4A4EDDACDB26A66AF7B918395";
        uint256 ret = SHA256_HASHED.pkcs1Sha256Verify(MD5_SIGNATURE, EXPONENT, MD5_MODULUS);
        assertTrue(
            ret == 3,
            "Expected pkcs1Sha256Verify to fail due to an unexpected delimiter; the delimiter should be 0x00. However, this issue was not encountered."
        );
    }

    // Test to validate that the DER encoding of DigestInfo is in SHA256 format
    // During signature verification, DigestInfo should be using the correct DER encoding.
    function test_Fail_RsaSignatureHasInvalidDigestInfoCode() public {
        bytes memory SHA512_256_SIGNATURE =
            hex"ae8f62b68118b310f094122dcb87fee208823cf093b5d4be9d97a56a5b974fc7326ab9883dc2ccea10a89736fd650cda555e3a567feed4c95ae81e987930bd32ec7637bf25fe5967dfb5a38ea4b713d7c016ee8dbe7b8b14104e4d2146817e7fba35d59027c68b71f87f0a35b3c93c565c6872da0b3b368879818702e741f629e80ccc9bff5417cbf50a8a8f72a4b243d21c08bbc9b51711765baf6cadc0d7e474537d22f009ecb592aa134e9de645dcb161c5e3efde638342b96308f134215f2c720749878f11443633012f4741e30e86e73985767f969675e1c743fa4637a8467751df1bc1e5c3189c69e773422580f6c031369dcb285b79164520e87568e5";
        bytes memory SHA512_256_MODULUS =
            hex"B585BBCA53EA972FF8137DF807DF0EFF9C384B526D8DB70011256614905AA5B728E01EFFC73FEE46A93194C0F67033BB21A4193D1A2A917EC8FCFCCC8C6CC2797FC7FCACBD487F8CD396332A906B4E647B7DBEE8625C4771EFB6668D0B61E6AA5F07DC226595F9AFFFC0704F2DA8C4D1AAF5724809DA76E2BA4DC3323A9B42102383226935E5964559A5D7542302B5116A4867E6E285098014042B3FA86A30F67F7C6741202BA9FD025ED0254D9608D5717C6A113FD677150B16B8C9C3E6B690613308C619ED42333C14FCC8D987464CA5BB0CCE3ED5A1547CB30F94D28A4B33826D8951B5D169D71938126285F3D9A0224CDE0CA7CD66950EB19EE6AF07031F";
        uint256 ret = SHA256_HASHED.pkcs1Sha256Verify(SHA512_256_SIGNATURE, EXPONENT, SHA512_256_MODULUS);
        assertTrue(
            ret == 4,
            "Expected pkcs1Sha256Verify to fail due to invalid digest info code; the code should represent the SHA-256 encoding method as 0x3031300d060960864801650304020105000420. However, this issue was not encountered."
        );
    }

    function test_Fail_RsaSignatureHasDigestMismatchingGivenHash() public {
        bytes32 INVALID_SHA256_HASHED = hex"47707cfb91cc6bede5f48cde4f1cea391e0ed78338e9240889b045e8808b32d3";
        uint256 ret = INVALID_SHA256_HASHED.pkcs1Sha256Verify(SIGNATURE, EXPONENT, MODULUS);
        assertTrue(
            ret == 5,
            "Expected pkcs1Sha256Verify to fail due to a digest mismatch with the given hash. However, this issue was not encountered."
        );
    }
}
