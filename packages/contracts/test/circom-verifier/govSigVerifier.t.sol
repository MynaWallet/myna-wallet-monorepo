// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {MynaGovSigVerifier} from "../../src/circom-verifier/govSigVerifier.sol";

contract MynaGovSigVerifierTest is Test {
    MynaGovSigVerifier public verifier;

    function setUp() public {
        verifier = new MynaGovSigVerifier();
    }

    function test_Success() public {
        uint[2] memory pA = [
            0x2ad86e80f5088acbb9c210cdc26e265ad9d9c3e515b2cf1c718e57b8b3548b03,
            0x204d4674ec339c8eb0d62a21789434a7357ca13e03680f481473c8423c81c84d
        ];
        uint[2][2] memory pB = [
            [
                0x172d25b29113fc034a1694f7ee465ffcc05c727c372e5e606905248fbb93f447,
                0x26956d109bec2ddb20a40d189c053ecb95db9efaa3c822ddee2683f11c072da2
            ],
            [
                0x09c7d0312263f3e3b74f60aa92114268c93b1e8b44a475433064924e12194860,
                0x28861b62ceb33a0bde830472b3b4012cecc93dba8a1a89894d5641f63184601a
            ]
        ];
        uint[2] memory pC = [
            0x26d24f4665feca1d03461adf5928ab25612fb645b9c59d76b393b402729f0b03,
            0x03a1ca6224c6537bf729ac6087821bf9ceea3b4aa94a0ca04039c479e148d01a
        ];
        uint[35] memory pubSignals = [
            0x1bfdeb68d2cb034ee48ec29340ff2ed6f738f6d22e764e3ac003cd9938b02488,
            0x0000000000000000000000000000000001ca4350eadda8587ec0d5edbfa1f853,
            0x00000000000000000000000000000000017b17fedf34f0ed646607f6aeae7814,
            0x0000000000000000000000000000000001cb56d9fbab3eccf37f5e0b2700b751,
            0x000000000000000000000000000000000061fa0a5ea81cebc8214d56b6a7030f,
            0x00000000000000000000000000000000005e4fc985ccf199ff804464f3c1876b,
            0x000000000000000000000000000000000186a52b6fbc5b78b1f94e851bd758b3,
            0x000000000000000000000000000000000091aaf257540b259ec3d819a8c22b98,
            0x0000000000000000000000000000000001a0dbb05ef2d09c9b4c209f39274af6,
            0x00000000000000000000000000000000004c5ece6355514bb3cb400759a08996,
            0x00000000000000000000000000000000000eb8cfc61e6aa7e89638295151d26b,
            0x00000000000000000000000000000000016c023517b0e0c54662f338bb0a6d7a,
            0x000000000000000000000000000000000171cc0fe3cf8014a47b8aa855b68adf,
            0x000000000000000000000000000000000086d85e7aa646d5a42efc8913a2240f,
            0x000000000000000000000000000000000180e432f6e7c1a062ebc296bb2e236f,
            0x0000000000000000000000000000000000c5392196b6bb1a71647704e3d9ed0e,
            0x00000000000000000000000000000000007e216b580922cf9d39fb5c209865f0,
            0x000000000000000000000000000000000000945f7c265acd7169012267b3d981,
            0x0000000000000000000000000000000001426cbe17d68402a8ab7c8baaec1ef8,
            0x00000000000000000000000000000000006080218080802ede37f5f3dbc004d5,
            0x000000000000000000000000000000000088a7f15c2c80084b82b3bb57438633,
            0x000000000000000000000000000000000151d081769f14eed8b68dd18207b031,
            0x0000000000000000000000000000000000e842b0a3039976cbbfba6d78217439,
            0x000000000000000000000000000000000156c4508311f0ddc755e714c1a6ef15,
            0x0000000000000000000000000000000001dc4e68ba5bfbe17c2c38ddb357a937,
            0x00000000000000000000000000000000015f79aef53f9fef28b4a24096ed7cd6,
            0x0000000000000000000000000000000000d9faa0ba79b5a97e82602b55c6bcc2,
            0x00000000000000000000000000000000013d488853014626f4e24c44f2a72042,
            0x0000000000000000000000000000000001e9a6361e349bd4e1856e6cb32ee11a,
            0x0000000000000000000000000000000000469901be9fe64cc4be89571f88cd3c,
            0x00000000000000000000000000000000012a3c7a0e37ace1a5d82c082af0f186,
            0x0000000000000000000000000000000000c65df5a32eef0aa4a45623c2305ed0,
            0x0000000000000000000000000000000000b4dffaf05ac89a919648d3bda72a60,
            0x000000000000000000000000000000000058f2a40e963e4d76bb817406ef9a7e,
            0x00000000000000000000000000000000000046b35d93f0486d132aff57d64ff9
        ];

        bool ret = verifier.verifyProof(pA, pB, pC, pubSignals);
        assertTrue(ret == true, "fail!");
    }
}
