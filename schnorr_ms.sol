pragma solidity ^0.8.17;
import "truffle/console.sol";

library EllipticCurve {

  // Pre-computed constant for 2 ** 255
  uint256 constant private U255_MAX_PLUS_1 = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  /// @dev Modular euclidean inverse of a number (mod p).
  /// @param _x The number
  /// @param _pp The modulus
  /// @return q such that x*q = 1 (mod _pp)
  function invMod(uint256 _x, uint256 _pp) internal pure returns (uint256) {
    require(_x != 0 && _x != _pp && _pp != 0, "Invalid number");
    uint256 q = 0;
    uint256 newT = 1;
    uint256 r = _pp;
    uint256 t;
    while (_x != 0) {
      t = r / _x;
      (q, newT) = (newT, addmod(q, (_pp - mulmod(t, newT, _pp)), _pp));
      (r, _x) = (_x, r - t * _x);
    }

    return q;
  }

  /// @dev Modular exponentiation, b^e % _pp.
  /// Source: https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/ECCMath.sol
  /// @param _base base
  /// @param _exp exponent
  /// @param _pp modulus
  /// @return r such that r = b**e (mod _pp)
  function expMod(uint256 _base, uint256 _exp, uint256 _pp) internal pure returns (uint256) {
    require(_pp!=0, "Modulus is zero");

    if (_base == 0)
      return 0;
    if (_exp == 0)
      return 1;

    uint256 r = 1;
    uint256 bit = U255_MAX_PLUS_1;
    assembly {
      for { } gt(bit, 0) { }{
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, bit)))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 2))))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 4))))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 8))))), _pp)
        bit := div(bit, 16)
      }
    }

    return r;
  }

  /// @dev Converts a point (x, y, z) expressed in Jacobian coordinates to affine coordinates (x', y', 1).
  /// @param _x coordinate x
  /// @param _y coordinate y
  /// @param _z coordinate z
  /// @param _pp the modulus
  /// @return (x', y') affine coordinates
  function toAffine(uint256 _x, uint256 _y, uint256 _z, uint256 _pp) internal pure returns (uint256, uint256) {
    uint256 zInv = invMod(_z, _pp);
    uint256 zInv2 = mulmod(zInv, zInv, _pp);
    uint256 x2 = mulmod(_x, zInv2, _pp);
    uint256 y2 = mulmod(_y, mulmod(zInv, zInv2, _pp), _pp);

    return (x2, y2);
  }

  /// @dev Derives the y coordinate from a compressed-format point x [[SEC-1]](https://www.secg.org/SEC1-Ver-1.0.pdf).
  /// @param _prefix parity byte (0x02 even, 0x03 odd)
  /// @param _x coordinate x
  /// @param _aa constant of curve
  /// @param _bb constant of curve
  /// @param _pp the modulus
  /// @return y coordinate y
  function deriveY(uint8 _prefix, uint256 _x, uint256 _aa, uint256 _bb, uint256 _pp) internal pure returns (uint256) {
    require(_prefix == 0x02 || _prefix == 0x03, "Invalid compressed EC point prefix");

    // x^3 + ax + b
    uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, _pp), _pp), addmod(mulmod(_x, _aa, _pp), _bb, _pp), _pp);
    y2 = expMod(y2, (_pp + 1) / 4, _pp);
    // uint256 cmp = yBit ^ y_ & 1;
    uint256 y = (y2 + _prefix) % 2 == 0 ? y2 : _pp - y2;

    return y;
  }

  /// @dev Check whether point (x,y) is on curve defined by a, b, and _pp.
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _aa constant of curve
  /// @param _bb constant of curve
  /// @param _pp the modulus
  /// @return true if x,y in the curve, false else
  function isOnCurve(uint _x, uint _y, uint _aa, uint _bb, uint _pp) internal pure returns (bool) {
    if (0 == _x || _x >= _pp || 0 == _y || _y >= _pp) {
      return false;
    }
    // y^2
    uint lhs = mulmod(_y, _y, _pp);
    // x^3
    uint rhs = mulmod(mulmod(_x, _x, _pp), _x, _pp);
    if (_aa != 0) {
      // x^3 + a*x
      rhs = addmod(rhs, mulmod(_x, _aa, _pp), _pp);
    }
    if (_bb != 0) {
      // x^3 + a*x + b
      rhs = addmod(rhs, _bb, _pp);
    }

    return lhs == rhs;
  }

  /// @dev Calculate inverse (x, -y) of point (x, y).
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _pp the modulus
  /// @return (x, -y)
  function ecInv(uint256 _x, uint256 _y, uint256 _pp) internal pure returns (uint256, uint256) {
    return (_x, (_pp - _y) % _pp);
  }

  /// @dev Add two points (x1, y1) and (x2, y2) in affine coordinates.
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _x2 coordinate x of P2
  /// @param _y2 coordinate y of P2
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = P1+P2 in affine coordinates
  function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2, uint256 _aa, uint256 _pp) internal pure returns(uint256, uint256) {
    uint x = 0;
    uint y = 0;
    uint z = 0;

    // Double if x1==x2 else add
    if (_x1==_x2) {
      // y1 = -y2 mod p
      if (addmod(_y1, _y2, _pp) == 0) {
        return(0, 0);
      } else {
        // P1 = P2
        (x, y, z) = jacDouble(_x1, _y1, 1, _aa, _pp);
      }
    } else {
      (x, y, z) = jacAdd(_x1, _y1, 1, _x2, _y2, 1, _pp);
    }
    // Get back to affine
    return toAffine(x, y, z, _pp);
  }

  /// @dev Substract two points (x1, y1) and (x2, y2) in affine coordinates.
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _x2 coordinate x of P2
  /// @param _y2 coordinate y of P2
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = P1-P2 in affine coordinates
  function ecSub(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2, uint256 _aa, uint256 _pp) internal pure returns(uint256, uint256) {
    // invert square
    (uint256 x, uint256 y) = ecInv(_x2, _y2, _pp);
    // P1-square
    return ecAdd(_x1, _y1, x, y, _aa, _pp);
  }

  /// @dev Multiply point (x1, y1, z1) times d in affine coordinates.
  /// @param _k scalar to multiply
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = d*P in affine coordinates
  function ecMul(uint256 _k, uint256 _x, uint256 _y, uint256 _aa, uint256 _pp) internal pure returns(uint256, uint256) {
    // Jacobian multiplication
    (uint256 x1, uint256 y1, uint256 z1) = jacMul(_k, _x, _y, 1, _aa, _pp);
    // Get back to affine
    return toAffine(x1, y1, z1, _pp);
  }

  /// @dev Adds two points (x1, y1, z1) and (x2 y2, z2).
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _z1 coordinate z of P1
  /// @param _x2 coordinate x of square
  /// @param _y2 coordinate y of square
  /// @param _z2 coordinate z of square
  /// @param _pp the modulus
  /// @return (qx, qy, qz) P1+square in Jacobian
  function jacAdd(uint256 _x1, uint256 _y1, uint256 _z1, uint256 _x2, uint256 _y2, uint256 _z2, uint256 _pp) internal pure returns (uint256, uint256, uint256) {
    if (_x1==0 && _y1==0)
      return (_x2, _y2, _z2);
    if (_x2==0 && _y2==0)
      return (_x1, _y1, _z1);

    // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
    uint[4] memory zs; // z1^2, z1^3, z2^2, z2^3
    zs[0] = mulmod(_z1, _z1, _pp);
    zs[1] = mulmod(_z1, zs[0], _pp);
    zs[2] = mulmod(_z2, _z2, _pp);
    zs[3] = mulmod(_z2, zs[2], _pp);

    // u1, s1, u2, s2
    zs = [
      mulmod(_x1, zs[2], _pp),
      mulmod(_y1, zs[3], _pp),
      mulmod(_x2, zs[0], _pp),
      mulmod(_y2, zs[1], _pp)
    ];

    // In case of zs[0] == zs[2] && zs[1] == zs[3], double function should be used
    require(zs[0] != zs[2] || zs[1] != zs[3], "Use jacDouble function instead");

    uint[4] memory hr;
    //h
    hr[0] = addmod(zs[2], _pp - zs[0], _pp);
    //r
    hr[1] = addmod(zs[3], _pp - zs[1], _pp);
    //h^2
    hr[2] = mulmod(hr[0], hr[0], _pp);
    // h^3
    hr[3] = mulmod(hr[2], hr[0], _pp);
    // qx = -h^3  -2u1h^2+r^2
    uint256 qx = addmod(mulmod(hr[1], hr[1], _pp), _pp - hr[3], _pp);
    qx = addmod(qx, _pp - mulmod(2, mulmod(zs[0], hr[2], _pp), _pp), _pp);
    // qy = -s1*z1*h^3+r(u1*h^2 -x^3)
    uint256 qy = mulmod(hr[1], addmod(mulmod(zs[0], hr[2], _pp), _pp - qx, _pp), _pp);
    qy = addmod(qy, _pp - mulmod(zs[1], hr[3], _pp), _pp);
    // qz = h*z1*z2
    uint256 qz = mulmod(hr[0], mulmod(_z1, _z2, _pp), _pp);
    return(qx, qy, qz);
  }

  /// @dev Doubles a points (x, y, z).
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _z coordinate z of P1
  /// @param _aa the a scalar in the curve equation
  /// @param _pp the modulus
  /// @return (qx, qy, qz) 2P in Jacobian
  function jacDouble(uint256 _x, uint256 _y, uint256 _z, uint256 _aa, uint256 _pp) internal pure returns (uint256, uint256, uint256) {
    if (_z == 0)
      return (_x, _y, _z);

    // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
    // Note: there is a bug in the paper regarding the m parameter, M=3*(x1^2)+a*(z1^4)
    // x, y, z at this point represent the squares of _x, _y, _z
    uint256 x = mulmod(_x, _x, _pp); //x1^2
    uint256 y = mulmod(_y, _y, _pp); //y1^2
    uint256 z = mulmod(_z, _z, _pp); //z1^2

    // s
    uint s = mulmod(4, mulmod(_x, y, _pp), _pp);
    // m
    uint m = addmod(mulmod(3, x, _pp), mulmod(_aa, mulmod(z, z, _pp), _pp), _pp);

    // x, y, z at this point will be reassigned and rather represent qx, qy, qz from the paper
    // This allows to reduce the gas cost and stack footprint of the algorithm
    // qx
    x = addmod(mulmod(m, m, _pp), _pp - addmod(s, s, _pp), _pp);
    // qy = -8*y1^4 + M(S-T)
    y = addmod(mulmod(m, addmod(s, _pp - x, _pp), _pp), _pp - mulmod(8, mulmod(y, y, _pp), _pp), _pp);
    // qz = 2*y1*z1
    z = mulmod(2, mulmod(_y, _z, _pp), _pp);

    return (x, y, z);
  }

  /// @dev Multiply point (x, y, z) times d.
  /// @param _d scalar to multiply
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _z coordinate z of P1
  /// @param _aa constant of curve
  /// @param _pp the modulus
  /// @return (qx, qy, qz) d*P1 in Jacobian
  function jacMul(uint256 _d, uint256 _x, uint256 _y, uint256 _z, uint256 _aa, uint256 _pp) internal pure returns (uint256, uint256, uint256) {
    // Early return in case that `_d == 0`
    if (_d == 0) {
      return (_x, _y, _z);
    }

    uint256 remaining = _d;
    uint256 qx = 0;
    uint256 qy = 0;
    uint256 qz = 1;

    // Double and add algorithm
    while (remaining != 0) {
      if ((remaining & 1) != 0) {
        (qx, qy, qz) = jacAdd(qx, qy, qz, _x, _y, _z, _pp);
      }
      remaining = remaining / 2;
      (_x, _y, _z) = jacDouble(_x, _y, _z, _aa, _pp);
    }
    return (qx, qy, qz);
  }
}

library CommonStructs {
    struct Point {
    uint256 x;
    uint256 y;
  }

  struct Points {
    Point[] X;
    Point[] PK;
  }

  struct Others {
    uint256 own_s; 
    uint256 own_x;
    bytes32[] R;
    bytes message;
  }

}

contract schnorr {


  uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  uint256 public constant AA = 0;
  uint256 public constant BB = 7;
  uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
  uint256 public constant QQ = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

// Round 1
// Creates a public key for the user by returning a point
function publicKeyPointGetFromInt(uint256 secretKey) pure public returns (CommonStructs.Point memory) {
    (uint256 x, uint256 y) = EllipticCurve.ecMul(secretKey, GX, GY, AA, PP);
    return CommonStructs.Point(x, y);
}

// Multiplies x by G
// Creates the concept of "X" for each user by receiving a random number
// This number will be sent to other users 
function XGen(uint256 x) pure public returns (CommonStructs.Point memory) {
    (uint256 x, uint256 y) = EllipticCurve.ecMul(x, GX, GY, AA, PP);
    return CommonStructs.Point(x, y);
}

// Concatenates X and PK and computes the hash
function computeR(CommonStructs.Point memory X, CommonStructs.Point memory PK) pure public returns (bytes32) {
  return keccak256(abi.encodePacked(X.x, X.y, PK.x, PK.y));
    // return keccak256(bytes.concat(bytes32(X.x), bytes32(X.y), bytes32(PK.x), bytes32(PK.y)));
}

function compareStrings(string memory a, string memory b) public pure returns (bool) {
    return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))));
}

// function mergePoints(CommonStructs.Point[] memory points, CommonStructs.Point memory point) public pure returns (CommonStructs.Point[] memory) {
//   CommonStructs.Point[] memory newPoints = new CommonStructs.Point[](points.length + 1);
//   for (uint i = 0; i < points.length; i++)
//     newPoints[i] = points[i];
//   newPoints[points.length] = point;

//   return newPoints;
// }

function computePkBar(CommonStructs.Point[] memory totalPK) pure public returns (CommonStructs.Point memory) {
  uint[] memory hashBar = hashBar(totalPK);
  CommonStructs.Point[] memory pkBarMul = hashBarMulPoint(hashBar, totalPK); 
  CommonStructs.Point memory pkBarSum = hashBarSumPoint(pkBarMul);

  return pkBarSum;
}

function computeXBar(CommonStructs.Point[] memory totalPK, CommonStructs.Point[] memory totalX) pure public returns (CommonStructs.Point memory) {
  uint256[] memory hashBar = hashBar(totalPK);
  CommonStructs.Point[] memory xBarMul = hashBarMulPoint(hashBar, totalX); 
  CommonStructs.Point memory xBarSum = hashBarSumPoint(xBarMul);

  return xBarSum;
}

function computeZBar(CommonStructs.Point[] memory totalPK, uint256[] memory z) pure public returns (uint256) {
  uint[] memory hashBar = hashBar(totalPK);
  uint256[] memory zBarMul = hashBarMulNumber(hashBar, z);
  uint256 zBarSum = hashBarSumNumber(zBarMul);

  return zBarSum;
}

function temple(CommonStructs.Points memory points,
                      CommonStructs.Others memory others) view public returns (uint) {
  
  // console.log("XXXXXXXXXXXXXXXXXXXXXXXX Staring doRoundThree");                  
  // for (uint i = 0; i < points.othersX.length; i++) {
  //   string memory strR = string(abi.encodePacked(others.othersR[i]));
  //   string memory computedR = string(abi.encodePacked(computeR(points.othersX[i], points.othersPK[i])));
    
  //   console.log("XXXXXXXXXXXXXXXXXXXXXXXX Checking require");
  //   require(compareStrings(strR, computedR)); 
  // }
  
  CommonStructs.Point memory pkBarSum = computePkBar(points.PK);
  CommonStructs.Point memory xBarSum = computeXBar(points.PK, points.X);
  
  // uint256 c = uint256(keccak256(bytes.concat(bytes32(pkBarSum.x), bytes32(pkBarSum.y), bytes32(xBarSum.x), bytes32(xBarSum.y), others.message)));
  uint c = uint(keccak256(abi.encodePacked(pkBarSum.x, pkBarSum.y, xBarSum.x, xBarSum.y, others.message)));

  return c;
}


function doRoundThree(CommonStructs.Points memory points,
                      CommonStructs.Others memory others) view public returns (uint256) {
  for (uint i = 0; i < points.X.length; i++) {
    bytes32 receivedR = others.R[i];
    bytes32 actualR = keccak256(abi.encodePacked(points.X[i].x, points.X[i].y, points.PK[i].x, points.PK[i].y));

    require(receivedR == actualR); 
  }

  CommonStructs.Point memory pkBar = computePkBar(points.PK);
  CommonStructs.Point memory xBar = computeXBar(points.PK, points.X);
  
  uint c = uint(keccak256(abi.encodePacked(pkBar.x, pkBar.y, xBar.x, xBar.y, others.message)));
  uint256 z = addmod(mulmod(others.own_s, c, QQ), others.own_x, QQ);

  return z;
}


function hashBarSumNumber(uint256[] memory number) pure public returns (uint256) {
  uint256 sum;
  for (uint i = 0; i < number.length; i++) {
    sum = addmod(sum, number[i], QQ);
  }

  return sum;
}

function hashBarMulNumber(uint256[] memory hashBar, uint256[] memory number) pure public returns (uint256[] memory) {
  uint size = number.length;
  uint256[] memory arr = new uint256[](size);
  for (uint i = 0; i < size; i++) {
    arr[i] = mulmod(hashBar[i], number[i], QQ);
  }

  return arr;
}

function hashBarSumPoint(CommonStructs.Point[] memory points) pure public returns (CommonStructs.Point memory) {
  uint256 x;
  uint256 y;
  for (uint i = 0; i < points.length; i++) {
    (x, y) = EllipticCurve.ecAdd(points[i].x, points[i].y, x, y, AA, PP);
  }

  return CommonStructs.Point(x, y);
}

function hashBarMulPoint(uint256[] memory hashBar, CommonStructs.Point[] memory points) pure public returns (CommonStructs.Point[] memory) {
  uint size = points.length;
  CommonStructs.Point[] memory mul = new CommonStructs.Point[](size);
  for (uint i = 0; i < size; i++) {
    (mul[i].x, mul[i].y) = EllipticCurve.ecMul(hashBar[i], points[i].x, points[i].y, AA, PP);
  }

  return mul;
}

function hashBar(CommonStructs.Point[] memory pk) pure public returns (uint[] memory) {
  uint size = pk.length;
  bytes memory pk_concatenated = concatenate(pk);
  uint[] memory hashBarArray = new uint[](size);
  for (uint i = 0; i < size; i++) {
    // hashBarArray[i] = uint256(keccak256(bytes.concat(bytes32(pk[i].x), bytes32(pk[i].y), bytes32(pk_concatenated))));
    hashBarArray[i] = uint(keccak256(abi.encodePacked(pk[i].x, pk[i].y, pk_concatenated)));
  }
  return hashBarArray;
}

function concatenate(CommonStructs.Point[] memory pk) pure public returns (bytes memory) {
  bytes memory pk_concatenated;
  for (uint i = 0; i < pk.length; i++)
    // pk_concatenated = abi.encodePacked(pk_concatenated, bytes.concat(bytes32(pk[i].x), bytes32(pk[i].y)));   
    pk_concatenated = abi.encodePacked(pk_concatenated, pk[i].x, pk[i].y);   
  return pk_concatenated;
}

function leader(uint256[] memory z, CommonStructs.Point[] memory pk, CommonStructs.Point[] memory x) pure public returns (uint256, CommonStructs.Point memory, CommonStructs.Point memory) {
  CommonStructs.Point memory pkBar = computePkBar(pk);
  CommonStructs.Point memory xBar = computeXBar(pk, x);
  uint256 zBar = computeZBar(pk, z);
  
  return (zBar, pkBar, xBar);
}

function verify(uint256 zBar, CommonStructs.Point memory pkBar, CommonStructs.Point memory xBar, bytes memory message) pure public returns (bool) {
  (uint256 actual_x, uint256 actual_y) = EllipticCurve.ecMul(zBar, GX, GY, AA, PP);

  // uint256 c = uint256(keccak256(bytes.concat(bytes32(pkBarSum.x), bytes32(pkBarSum.y), bytes32(xBarSum.x), bytes32(xBarSum.y), bytes32(message))));
  uint c = uint(keccak256(abi.encodePacked(pkBar.x, pkBar.y, xBar.x, xBar.y, message)));

  // return c;
  (uint256 mul_x, uint256 mul_y) = EllipticCurve.ecMul(c, pkBar.x, pkBar.y, AA, PP);
  (uint256 expected_x, uint256 expected_y) = EllipticCurve.ecAdd(mul_x, mul_y, xBar.x, xBar.y, AA, PP);

  // return actual_y;
  if (actual_y == expected_y && actual_x == expected_x) {
    return true;
    }

  return false; 
}


function invMod(uint256 val, uint256 p) pure public returns (uint256)
{
    return EllipticCurve.invMod(val,p);
}

function expMod(uint256 val, uint256 e, uint256 p) pure public returns (uint256)
{
    return EllipticCurve.expMod(val,e,p);
}


function getY(uint8 prefix, uint256 x) pure public returns (uint256)
{
    return EllipticCurve.deriveY(prefix,x,AA,BB,PP);
}


function onCurve(uint256 x, uint256 y) pure public returns (bool)
{
    return EllipticCurve.isOnCurve(x,y,AA,BB,PP);
}

function inverse(uint256 x, uint256 y) pure public returns (uint256, 
uint256) {
    return EllipticCurve.ecInv(x,y,PP);
}

function subtract(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure public returns (uint256, uint256) {
    return EllipticCurve.ecSub(x1,y1,x2,y2,AA,PP);
}

function add(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure public returns (uint256, uint256) {
    return EllipticCurve.ecAdd(x1,y1,x2,y2,AA,PP);
}

function derivePubKey(uint256 privKey) pure public returns (uint256, uint256) {
    return EllipticCurve.ecMul(privKey,GX,GY,AA,PP);
}

uint256 constant s1 = 1561561;
uint256 constant s2 = 1561562;
uint256 constant s3 = 1561563;

uint256 constant x1 = 999991;
uint256 constant x2 = 999992;
uint256 constant x3 = 999993;

function test_publicKeyPointGetFromInt() view public returns (bool) {
  publicKeyPointGetFromInt(s1);
  return true;
}

function test_XGen() view public returns (bool) {
  XGen(x1);
  return true;
}

function test_computeR() view public returns (bool) {
  CommonStructs.Point memory pk = publicKeyPointGetFromInt(s1);
  CommonStructs.Point memory X = XGen(x1);
  computeR(X, pk);
  return true;
}


CommonStructs.Point[] pk;
CommonStructs.Point[] X;
bytes32[] r;
bytes message = bytes("hello world");

uint256[] z;

uint256 zBar; 
CommonStructs.Point pkBar; 
CommonStructs.Point xBar;

function test_publicKeyPointGetFromInt1() public {
  pk.push(publicKeyPointGetFromInt(s1));
}

function test_publicKeyPointGetFromInt2() public {
  pk.push(publicKeyPointGetFromInt(s2));
}

function test_publicKeyPointGetFromInt3() public {
  pk.push(publicKeyPointGetFromInt(s3));
}

function test_XGen1() public {
  X.push(XGen(x1));
}

function test_XGen2() public {
  X.push(XGen(x2));
}

function test_XGen3() public {
  X.push(XGen(x3));
}

function test_computeR1() public {
  r.push(computeR(X[0], pk[0]));
}

function test_computeR2() public {
  r.push(computeR(X[1], pk[1]));
}

function test_computeR3() public {
  r.push(computeR(X[2], pk[2]));
}

function test_doRoundThree1() public {
    CommonStructs.Others memory user1Others;
    user1Others.own_s = s1;
    user1Others.own_x = x1;
    
    user1Others.R = new bytes32[](3);
    user1Others.R[0] = r[0];
    user1Others.R[1] = r[1];
    user1Others.R[2] = r[2];
    
    user1Others.message = message;

    CommonStructs.Points memory points;

    points.X = new CommonStructs.Point[](3);
    points.X[0] = X[0];
    points.X[1] = X[1];
    points.X[2] = X[2];
    
    points.PK = new CommonStructs.Point[](3);
    points.PK[0] = pk[0];
    points.PK[1] = pk[1];
    points.PK[2] = pk[2];
    
    z.push(doRoundThree(points, user1Others));
}

function test_doRoundThree2() public {
 CommonStructs.Others memory user2Others;
      user2Others.own_s = s2;
      user2Others.own_x = x2;
      
      user2Others.R = new bytes32[](3);
      user2Others.R[0] = r[0];
      user2Others.R[1] = r[1];
      user2Others.R[2] = r[2];
      
      user2Others.message = message;

      CommonStructs.Points memory points;
  
      points.X = new CommonStructs.Point[](3);
      points.X[0] = X[0];
      points.X[1] = X[1];
      points.X[2] = X[2];
      
      points.PK = new CommonStructs.Point[](3);
      points.PK[0] = pk[0];
      points.PK[1] = pk[1];
      points.PK[2] = pk[2];

      z.push(doRoundThree(points, user2Others));
}

function test_doRoundThree3() public {
    CommonStructs.Others memory user3Others;
      user3Others.own_s = s3;
      user3Others.own_x = x3;
      
      user3Others.R = new bytes32[](3);
      user3Others.R[0] = r[0];
      user3Others.R[1] = r[1];
      user3Others.R[2] = r[2];
      
      user3Others.message = message;

      CommonStructs.Points memory points;
  
      points.X = new CommonStructs.Point[](3);
      points.X[0] = X[0];
      points.X[1] = X[1];
      points.X[2] = X[2];
      
      points.PK = new CommonStructs.Point[](3);
      points.PK[0] = pk[0];
      points.PK[1] = pk[1];
      points.PK[2] = pk[2];

      z.push(doRoundThree(points, user3Others));
}

function test_leader() public {
    (zBar, pkBar, xBar) = leader(z, pk, X);
}

function test_verify() public returns (bool) {
  return verify(zBar, pkBar, xBar, message);
}

// function test1() view public returns (bool) {

//     bytes memory message = bytes("hello world");
    
//     CommonStructs.Point[] memory pk = new CommonStructs.Point[](3);
//     pk[0] = publicKeyPointGetFromInt(s1);
//     pk[1] = publicKeyPointGetFromInt(s2);
//     pk[2] = publicKeyPointGetFromInt(s3);

//     CommonStructs.Point[] memory X = new CommonStructs.Point[](3);
//     X[0] = XGen(x1);
//     X[1] = XGen(x2);
//     X[2] = XGen(x3);

//     bytes32[] memory r = new bytes32[](3);
//     r[0] = computeR(X[0], pk[0]);
//     r[1] = computeR(X[1], pk[1]);
//     r[2] = computeR(X[2], pk[2]);

//     uint256 z1;
//     { 
//       CommonStructs.Others memory user1Others;
//       user1Others.own_s = s1;
//       user1Others.own_x = x1;
      
//       user1Others.R = new bytes32[](3);
//       user1Others.R[0] = r[0];
//       user1Others.R[1] = r[1];
//       user1Others.R[2] = r[2];
      
//       user1Others.message = message;

//       CommonStructs.Points memory points;
  
//       points.X = new CommonStructs.Point[](3);
//       points.X[0] = X[0];
//       points.X[1] = X[1];
//       points.X[2] = X[2];
      
//       points.PK = new CommonStructs.Point[](3);
//       points.PK[0] = pk[0];
//       points.PK[1] = pk[1];
//       points.PK[2] = pk[2];
      
//       z1 = doRoundThree(points, user1Others);
//     }

//     uint256 z2;
//     { 
//       CommonStructs.Others memory user2Others;
//       user2Others.own_s = s2;
//       user2Others.own_x = x2;
      
//       user2Others.R = new bytes32[](3);
//       user2Others.R[0] = r[0];
//       user2Others.R[1] = r[1];
//       user2Others.R[2] = r[2];
      
//       user2Others.message = message;

//       CommonStructs.Points memory points;
  
//       points.X = new CommonStructs.Point[](3);
//       points.X[0] = X[0];
//       points.X[1] = X[1];
//       points.X[2] = X[2];
      
//       points.PK = new CommonStructs.Point[](3);
//       points.PK[0] = pk[0];
//       points.PK[1] = pk[1];
//       points.PK[2] = pk[2];

//       z2 = doRoundThree(points, user2Others);
//     }

//     uint256 z3;
//     { 
//       CommonStructs.Others memory user3Others;
//       user3Others.own_s = s3;
//       user3Others.own_x = x3;
      
//       user3Others.R = new bytes32[](3);
//       user3Others.R[0] = r[0];
//       user3Others.R[1] = r[1];
//       user3Others.R[2] = r[2];
      
//       user3Others.message = message;

//       CommonStructs.Points memory points;
  
//       points.X = new CommonStructs.Point[](3);
//       points.X[0] = X[0];
//       points.X[1] = X[1];
//       points.X[2] = X[2];
      
//       points.PK = new CommonStructs.Point[](3);
//       points.PK[0] = pk[0];
//       points.PK[1] = pk[1];
//       points.PK[2] = pk[2];

//       z3 = doRoundThree(points, user3Others);
//     }

//     uint256[] memory z = new uint256[](3);
//     z[0] = z1;
//     z[1] = z2;
//     z[2] = z3;
    
//     (uint256 zBar, CommonStructs.Point memory pkBar, CommonStructs.Point memory xBar) = leader(z, pk, X);
    
//     bool verified = verify(zBar, pkBar, xBar, message);

//     return verified;
//   } 

}
