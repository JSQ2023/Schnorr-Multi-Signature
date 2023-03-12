# Schnorr-Multi-Signature
This is the implementation for Schnorr-based Multi-signature, described at https://arxiv.org/abs/2301.08668 

The or three users,
the test for multi-signature can be executed by running the following functions in sequence.
This starts from creating public keys to the final verification:

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
