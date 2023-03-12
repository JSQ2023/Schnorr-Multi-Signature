# Schnorr-Multi-Signature
This is the implementation for Schnorr-based Multi-signature, described at section 7 in paper https://arxiv.org/abs/2301.08668 

The implemmentation is for any number of signers. At the end of the source file, we give a test for the multi-signature of 3-signer case. 
To execute, just the following functions in sequence. 

x.test_publicKeyPointGetFromInt1()

x.test_publicKeyPointGetFromInt2()

x.test_publicKeyPointGetFromInt3()

x.test_XGen1()

x.test_XGen2()

x.test_XGen3()

x.test_computeR1()

x.test_computeR2()

x.test_computeR3()

x.test_doRoundThree1()

x.test_doRoundThree2()

x.test_doRoundThree3()

x.test_leader()

x.test_verify()
