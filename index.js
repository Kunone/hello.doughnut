console.log('hello');

const doughnutMaker = require('@plugnet/doughnut-maker')
const {
    cryptoWaitReady,
    schnorrkelKeypairFromSeed,
    schnorrkelKeypairFromU8a,
    naclKeypairFromSeed
} = require("@polkadot/util-crypto");
const { stringToU8a, u8aToBuffer, bufferToU8a, u8aToString, u8aToHex, hexToU8a } = require("@polkadot/util");

const BSON = require('bson')
const bson = new BSON();

const pkArray = [
  48,
  86,
  48,
  16,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  5,
  43,
  129,
  4,
  0,
  10,
  3,
  66,
  0,
  4,
  179,
  49,
  30,
  13,
  242,
  119,
  78,
  114,
  249,
  33,
  168,
  196,
  61,
  118,
  51,
  204,
  89,
  78,
  219,
  234,
  184,
  136,
  115,
  70,
  125,
  40,
  107,
  181,
  246,
  252,
  251,
  139,
  251,
  225,
  64,
  151,
  62,
  85,
  190,
  100,
  64,
  22,
  205,
  105,
  62,
  28,
  140,
  183,
  174,
  18,
  91,
  47,
  23,
  190,
  186,
  180,
  45,
  112,
  170,
  251,
  160,
  218,
  38,
  175 ];

const skArray = [
  120,
  127,
  46,
  210,
  152,
  142,
  199,
  251,
  191,
  234,
  247,
  57,
  144,
  10,
  33,
  127,
  251,
  14,
  222,
  111,
  159,
  93,
  146,
  95,
  128,
  51,
  232,
  83,
  118,
  86,
  29,
  96,
  42,
  243,
  157,
  235,
  198,
  98,
  127,
  125,
  238,
  28,
  43,
  152,
  205,
  155,
  75,
  236,
  220,
  51,
  112,
  89,
  121,
  9,
  254,
  197,
  229,
  0,
  63,
  150,
  40,
  117,
  214,
  194 ];
const issuerPkArray = [
  22,
  126,
  150,
  15,
  176,
  190,
  210,
  156,
  179,
  149,
  142,
  84,
  153,
  4,
  203,
  61,
  62,
  185,
  76,
  45,
  162,
  220,
  254,
  188,
  163,
  187,
  63,
  39,
  186,
  113,
  126,
  12 ];

const awsDataKeyPairPKBase64 = 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEkYj84vcRYGEXnRnR3Ke3HAVgJJ9ozJMGFccTCVl3OUHtnfgOlaWEjglMP0jzO3b7zx5LdX9u8nqVmyjgOnqm8A==';
const awsDataKeyPairSKBase64 = 'MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgpxTr7tKKBe/mT2MRtVmKv9eI9oO5jzjgcl8JTFhk8ZmgBwYFK4EEAAqhRANCAASRiPzi9xFgYRedGdHcp7ccBWAkn2jMkwYVxxMJWXc5Qe2d+A6VpYSOCUw/SPM7dvvPHkt1f27yepWbKOA6eqbw';

// const issuerPublicKeyHex = '92d05983dca10f4ac0a6bb9f080f7ba4c2f6051c44f1d0cf97cb765c2917986d';//'0x167e960fb0bed29cb3958e549904cb3d3eb94c2da2dcfebca3bb3f27ba717e0c';
// const issuerSecretKeyHex = '63656e6e7a6e65746a737465737420202020202020202020202020202020202092d05983dca10f4ac0a6bb9f080f7ba4c2f6051c44f1d0cf97cb765c2917986d';//'0x787f2ed2988ec7fbbfeaf739900a217ffb0ede6f9f5d925f8033e85376561d602af39debc6627f7dee1c2b98cd9b4becdc3370597909fec5e5003f962875d6c2';
// const issuerPublicKey = new Uint8Array(Buffer.from(issuerPublicKeyHex, 'hex'));//hexToU8a(issuerPublicKeyHex);
// const issuerSecretKey = new Uint8Array(Buffer.from(issuerSecretKeyHex, 'hex'));//hexToU8a(issuerSecretKeyHex);

// const issuerPublicKeyHex = 'MHg2YTliZjE3ZjU4MDIxOTJlODM4YmQxNWQ0ODJlOWM0ODE3MDA1NTYyMTM1ZjdjYmRhMDM5MWQxYjI0MDljNGM4';
// const issuerSecretKeyHex = 'MHg2Yjc5NjMyZDYzNmY3MjY1MmQ2NDY1NzYyMDIwMjAyMDIwMjAyMDIwMjAyMDIwMjAyMDIwMjAyMDIwMjAyMDIwNmE5YmYxN2Y1ODAyMTkyZTgzOGJkMTVkNDgyZTljNDgxNzAwNTU2MjEzNWY3Y2JkYTAzOTFkMWIyNDA5YzRjOA==';

// dev
// const issuerPublicKeyBase64 = 'apvxf1gCGS6Di9FdSC6cSBcAVWITX3y9oDkdGyQJxMg=';
// const issuerSecretKeyBase64 = 'a3ljLWNvcmUtZGV2ICAgICAgICAgICAgICAgICAgICBqm/F/WAIZLoOL0V1ILpxIFwBVYhNffL2gOR0bJAnEyA==';

// prod
const issuerPublicKeyBase64 = 'TxbqnY1YNHAgqG7c8foY3AXUpMBn9oUx/nJbqoaMw9E='
const issuerSecretKeyBase64 = 'a3ljLWNvcmUtcHJvZCAgICAgICAgICAgICAgICAgICBPFuqdjVg0cCCobtzx+hjcBdSkwGf2hTH+cluqhozD0Q=='

// test
// const issuerPublicKeyBase64 = 'DZrULb4TViPskUELUc2A6LiRE3iUvC62+gUYwB1JmoA=';
// const issuerSecretKeyBase64 = 'a3ljLWNvcmUtdGVzdCAgICAgICAgICAgICAgICAgICANmtQtvhNWI+yRQQtRzYDouJETeJS8Lrb6BRjAHUmagA==';

// test fake
// const issuerPublicKeyBase64 = '5hdxBMr4nlLs1ajULPkA6/ZUdy5yyZ5xO5hYts9tYac=';
// const issuerSecretKeyBase64 = 'a3ljLWNvcmUtdGVzdC1mYWtlICAgICAgICAgICAgICDmF3EEyvieUuzVqNQs+QDr9lR3LnLJnnE7mFi2z21hpw==';


// const issuerPublicKey = hexToU8a(Buffer.from(issuerPublicKeyHex, 'base64').toString());
// const issuerSecretKey = hexToU8a(Buffer.from(issuerSecretKeyHex, 'base64').toString());
// const issuerPublicKey = bufferToU8a(Buffer.from(issuerPublicKeyBase64, 'base64'));
// const issuerSecretKey = bufferToU8a(Buffer.from(issuerSecretKeyBase64, 'base64'));
const issuerPublicKey = new Uint8Array(Buffer.from(issuerPublicKeyBase64, 'base64'));
const issuerSecretKey = new Uint8Array(Buffer.from(issuerSecretKeyBase64, 'base64'));

const createDoughnut = async () => {
    await cryptoWaitReady();
    // const issuerKeyPair = naclKeypairFromSeed(
    //   stringToU8a("kyc-core-test-fake".padEnd(32, " "))
    // );
    // const issuerKeyPairUat = naclKeypairFromSeed(
    //   stringToU8a("kyc-core-uat".padEnd(32, " "))
    // );
    // const issuerKeyPairProd = naclKeypairFromSeed(
    //   stringToU8a("kyc-core-prod".padEnd(32, " "))
    // );

    // console.log(Buffer.from(u8aToHex(issuerKeyPair.publicKey)).toString('base64'));
    // console.log(Buffer.from(u8aToHex(issuerKeyPair.secretKey)).toString('base64'));
    // console.log('dev key pairs:');
    // console.log(Buffer.from(issuerKeyPair.publicKey).toString('base64'));
    // console.log(Buffer.from(issuerKeyPair.secretKey).toString('base64'));
    // console.log('uat key pairs:');
    // console.log(Buffer.from(issuerKeyPairUat.publicKey).toString('base64'));
    // console.log(Buffer.from(issuerKeyPairUat.secretKey).toString('base64'));
    // console.log('prod key pairs:');
    // console.log(Buffer.from(issuerKeyPairProd.publicKey).toString('base64'));
    // console.log(Buffer.from(issuerKeyPairProd.secretKey).toString('base64'));


    // console.log(issuerKeyPair);
    // console.log(issuerPublicKey);
    // console.log(issuerSecretKey);

    // console.log(issuerPublicKey);
    // test awsDataKeyPairPKBase64
    // const awsDataKeyPairPK = new Uint8Array(Buffer.from(awsDataKeyPairPKBase64, 'base64'));
    // console.log(awsDataKeyPairPK.length);
    // console.log(awsDataKeyPairPK);


    // const pkU8a = new Uint8Array(pkArray);
    // pkU8a.set(pkArray);
    // console.log('pk base64 encoded');
    // const base64Pk = Buffer.from(pkU8a).toString('base64');
    // console.log(base64Pk);

    // console.log('issuer key pair');
    // const seed32 = "cennznetjstest".padEnd(32, " ");
    // console.log(`[${seed32}]`);
    // console.log(stringToU8a(seed32));
    // console.log(u8aToHex(issuerKeyPair.publicKey));
    // console.log(new Uint8Array(Buffer.from('92d05983dca10f4ac0a6bb9f080f7ba4c2f6051c44f1d0cf97cb765c2917986d', 'hex')));
    // console.log(bufferToU8a(u8aToBuffer(issuerKeyPair.publicKey)));
    // const base64Issuer = Buffer.from(issuerKeyPair.publicKey).toString('base64');
    // console.log(base64Issuer);
  
    // const issuer = issuerKeyPair.publicKey
    // const holder = holderKeyPair.publicKey
    // const holder = stringToU8a(''.padEnd(32, ' '));
    // console.log(holder);

    const kycCoreData = {
        "email": "test@centrality.ai",
    }

    const doughnut = await doughnutMaker.generate(
        0,
        1,
        {
            expiry: 1595014877,
            holder: new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
            issuer: issuerPublicKey,
            permissions: {
                "kyc": bson.serialize(kycCoreData)
            }
        },
        {
          publicKey: issuerPublicKey,
          secretKey: issuerSecretKey
        }
    )
    const encodedDoughnut = base64UrlEncode(doughnut);
    console.log(encodedDoughnut);
    return encodedDoughnut
}

// createDoughnut().then((doughnuts)=>{
//     // The binary data of the donut
//     // console.log("doughnut", data)
//     const doughnut = 'BAAapvxf1gCGS6Di9FdSC6cSBcAVWITX3y9oDkdGyQJxMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMqb4XpreWMAAAAAAAAAAAAAAAAARAAiAAAAAmVtYWlsABIAAABrdW5AY2VudHJhbGl0eS5haQAALGkfgEN3aR1T6YnJoGGbeZL4TAWMYdUyUcsYBcubL1XMctwoEIo627WjNq76erIi2GbjPoMjb/spHv6b5s15DQ==';
//     // The binary data encoded in base64 for sending
//     const base64 = Buffer.from(doughnut).toString('base64');
//     // console.log("base64",  base64)

//     // Base64 decoded back to binary
//     const uint8Array = new Uint8Array(Buffer.from(base64, 'base64'))

//     // console.log("doughnut from base64", uint8Array)

//     console.log('started to verify');
//     doughnutMaker.verify(uint8Array).then(result => {
//         console.log("verified doughnut", result)
//         const kycCoreDataDeserialized = bson.deserialize(Buffer.from(result.permissions.kyc_core))
//         console.log("deserialised data from doughnut", kycCoreDataDeserialized, '\n')
//     })
// })

const verifyDoughnut = async (doughnut) => {
  // Base64 decoded back to binary
  // const uint8Array = Buffer.from(doughnut, 'base64');
  const uint8Array = base64UrlDecode(doughnut);
  // console.log("doughnut from base64", uint8Array)
  const result = await doughnutMaker.verify(uint8Array);
  // console.log("verified doughnut", result);
  const pkInDoughnut = Buffer.from(result.issuer).toString('base64');
  console.log(pkInDoughnut);
  const kycCoreDataDeserialized = bson.deserialize(Buffer.from(result.permissions.kyc));
  console.log("deserialised data from doughnut", kycCoreDataDeserialized, '\n');
}

const base64UrlEncode = (unencoded) => {
  const encoded = new Buffer.from(unencoded || '').toString('base64');
  const urlEncoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return urlEncoded;
}

const base64UrlDecode = (encoded) => {
  encoded = encoded.replace(/\-/g, '+').replace(/\_/g, '/');
  while (encoded.length % 4)
    encoded += '=';
  return new Buffer.from(encoded || '', 'base64');
}

// createDoughnut().then(dd => {
//   verifyDoughnut(dd);
// });
verifyDoughnut('ABAATxbqnY1YNHAgqG7c8foY3AXUpMBn9oUx_nJbqoaMw9EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALt_iPpreWMAAAAAAAAAAAAAAAAAxAAjAAAAAmVtYWlsABMAAAB0ZXN0QGNlbnRyYWxpdHkuYWkAAC8XbG_1Ud6XPnMz72V5Cred5lIXJ7j5oNjKOPGrgt2eM5ABDYpbWauiNMxRJIXWC1S529olptiTNLSLMIKvMAw')
.then(dd => {
  console.log(dd);
});