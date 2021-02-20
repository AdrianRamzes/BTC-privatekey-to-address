
function hasQueryKey(key) {
    return getQueryValue(key) !== null;
}
function getQueryValue(key) {
    var _a;
    if (window.location.search.length === 0 || window.location.search[0] !== "?")
        return null;
    var queryValues = window.location.search.substr(1).split("&");
    for (var i = 0; i < queryValues.length; ++i) {
        var match = queryValues[i].match(/([a-zA-Z0-9]+)(=([a-zA-Z0-9]+))?/);
        if (match) {
            if (match[1] === key)
                return _a = match[3], (_a !== null && _a !== void 0 ? _a : "");
        }
    }
    return null;
}

var isTestnet = hasQueryKey("testnet");

// secp256k1 parameters
var ecc_p = new BN("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
var ecc_a = new BN(0);
var ecc_Gx = new BN("079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
var ecc_Gy = new BN("0483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
var ecc_n = new BN("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
var bn_0 = new BN(0);
var bn_1 = new BN(1);
var bn_2 = new BN(2);
var bn_3 = new BN(3);
var bn_58 = new BN(58);
var bn_255 = new BN(255);
function modinv(a, n) {
    var lm = new BN(1);
    var hm = new BN(0);
    var low = a.mod(n);
    var high = n;
    var ratio;
    var nm;
    var nnew;
    while (low.isNeg())
        low = low.add(n);
    while (low.gt(bn_1)) {
        ratio = high.div(low);
        nm = hm.sub(lm.mul(ratio));
        nnew = high.sub(low.mul(ratio));
        hm = lm;
        high = low;
        lm = nm;
        low = nnew;
    }
    return lm.mod(n);
}
function ecAdd(ax, ay, bx, by) {
    var lambda = ((by.sub(ay)).mul(modinv(bx.sub(ax), ecc_p))).mod(ecc_p);
    var x = (lambda.mul(lambda).sub(ax).sub(bx)).mod(ecc_p);
    var y = (lambda.mul(ax.sub(x)).sub(ay)).mod(ecc_p);
    return {
        x: x,
        y: y
    };
}
function ecDouble(ax, ay) {
    var lambda = ((bn_3.mul(ax).mul(ax).add(ecc_a)).mul(modinv(bn_2.mul(ay), ecc_p))).mod(ecc_p);
    var x = (lambda.mul(lambda).sub(bn_2.mul(ax))).mod(ecc_p);
    var y = (lambda.mul(ax.sub(x)).sub(ay)).mod(ecc_p);
    return {
        x: x,
        y: y
    };
}
// convert bigint to bool array (bits)
function bigintToBitArray(bigint) {
    if (bigint.isNeg())
        return [false];
    var values = [];
    while (bigint.gt(bn_0)) {
        values.push(bigint.isOdd());
        bigint = bigint.shrn(1);
    }
    return values.reverse();
}
function EccMultiply(gx, gy, scalar) {
    var qx = gx;
    var qy = gy;
    var bits = bigintToBitArray(scalar);
    for (var i = 1; i < bits.length; ++i) {
        var ret = ecDouble(qx, qy);
        qx = ret.x;
        qy = ret.y;
        if (bits[i]) {
            var ret2 = ecAdd(qx, qy, gx, gy);
            qx = ret2.x;
            qy = ret2.y;
        }
    }
    while (qy.isNeg())
        qy = qy.add(ecc_p);
    return {
        x: qx,
        y: qy,
    };
}
// convert bigint to byte array (uint8)
function bigintToByteArray(bigint) {
    var ret = [];
    while (bigint.gt(bn_0)) {
        ret.push(bigint.and(bn_255).toNumber());
        bigint = bigint.shrn(8);
    }
    return ret;
}
function byteArrayToBigint(bytes) {
    var bigint = new BN(0);
    for (var i = 0; i < bytes.length; ++i) {
        bigint = bigint.shln(8);
        bigint = bigint.or(new BN(bytes[i]));
    }
    return bigint;
}

function bip38decrypt(privkey, password, dummyTest) {
    if (dummyTest === void 0) { dummyTest = false; }
    if (password === "" && !dummyTest)
        return "password must not be empty";
    var newstring = privkey.split("").reverse().join("");
    for (var i = 0; i < privkey.length; ++i) {
        if (privkey[i] === base58Characters[0])
            newstring = newstring.substr(0, newstring.length - 1);
        else
            break;
    }
    var bigint = new BN(0);
    for (var i = newstring.length - 1; i >= 0; --i)
        bigint = bigint.mul(bn_58).add(new BN(base58CharsIndices[newstring[i]]));
    var bytes = bigintToByteArray(bigint);
    if (bytes.length !== 43)
        return "invalid length";
    bytes.reverse();
    var checksum = bytes.slice(bytes.length - 4, bytes.length);
    bytes.splice(bytes.length - 4, 4);
    var sha_result = SHA256(SHA256(bytes));
    for (var i = 0; i < 4; ++i) {
        if (sha_result[i] !== checksum[i])
            return "invalid checksum";
    }
    if (bytes[0] !== 0x01)
        return "invalid byte at position 0";
    bytes.shift();
    // typescript will show an error if I have (bytes[0] === 0x43) here, because it doesn't know that bytes.shift() changes the array
    // see https://github.com/microsoft/TypeScript/issues/35795
    // putting any here so it works
    if (bytes[0] === 0x43) {
        if ((bytes[1] & 0x20) === 0)
            return "only compressed private keys are supported";
        if (dummyTest)
            return 1; // dummy return value, only for checking if the private key is in the correct format
        var ownersalt = bytes.slice(6, 14);
        var scrypt_result = scrypt(password, ownersalt, 14, 8, 8, 32);
        var bigint2 = byteArrayToBigint(scrypt_result);
        var keypair = getECCKeypair(bigint2);
        var bytes_public_x = bigintToByteArray(keypair.x);
        while (bytes_public_x.length < 32)
            bytes_public_x.push(0);
        var passpoint = [];
        passpoint.push.apply(passpoint, bytes_public_x);
        if (keypair.y.isOdd())
            passpoint.push(0x03);
        else
            passpoint.push(0x02);
        passpoint.reverse();
        var encryptedpart2 = bytes.slice(22, 38);
        var addresshash = bytes.slice(2, 14);
        var scrypt_result_2 = scrypt(passpoint, addresshash, 10, 1, 1, 64);
        var derivedhalf1 = scrypt_result_2.slice(0, 32);
        var derivedhalf2 = scrypt_result_2.slice(32, 64);
        var decrypted2 = AES_Decrypt_ECB_NoPadding(encryptedpart2, derivedhalf2);
        var encryptedpart1 = bytes.slice(14, 22);
        encryptedpart1.push.apply(encryptedpart1, byteArrayXOR(decrypted2.slice(0, 8), scrypt_result_2.slice(16, 24)));
        var decrypted1 = AES_Decrypt_ECB_NoPadding(encryptedpart1, derivedhalf2);
        var seedb = byteArrayXOR(decrypted1.slice(0, 16), derivedhalf1.slice(0, 16));
        seedb.push.apply(seedb, byteArrayXOR(decrypted2.slice(8, 16), derivedhalf1.slice(24, 32)));
        var factorb = SHA256(SHA256(seedb));
        var finalprivkeybigint = byteArrayToBigint(scrypt_result).mul(byteArrayToBigint(factorb)).mod(ecc_n);
        var finalkeypair = getECCKeypair(finalprivkeybigint);
        var finaladdress = makeAddress(finalkeypair);
        var finaladdresshash = SHA256(SHA256(finaladdress));
        for (var i = 0; i < 4; ++i) {
            if (addresshash[i] !== finaladdresshash[i])
                return "invalid password";
        }
        var finalprivkey = makePrivateKey(finalprivkeybigint);
        return {
            address: finaladdress,
            privkey: finalprivkey
        };
    }
    else if (bytes[0] === 0x42) {
        if (bytes[1] !== 0xe0)
            return "only compressed private keys are supported";
        if (dummyTest)
            return 1;
        var addresshash = bytes.slice(2, 6);
        var derivedBytes = scrypt(password, addresshash, 14, 8, 8, 64);
        var decrypted = AES_Decrypt_ECB_NoPadding(bytes.slice(6, 38), derivedBytes.slice(32));
        var privkeyBytes = byteArrayXOR(decrypted, derivedBytes);
        var finalprivkeybigint = byteArrayToBigint(privkeyBytes);
        var finalkeypair = getECCKeypair(finalprivkeybigint);
        var finaladdress = makeAddress(finalkeypair);
        var finaladdresshash = SHA256(SHA256(finaladdress));
        for (var i = 0; i < 4; ++i) {
            if (addresshash[i] !== finaladdresshash[i])
                return "invalid password";
        }
        var finalprivkey = makePrivateKey(finalprivkeybigint);
        return {
            address: finaladdress,
            privkey: finalprivkey
        };
    }
    else
        return "invalid byte at EC multiply flag";
}
var base58Characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
var base58CharsIndices = {
    "1": 0, "2": 1, "3": 2, "4": 3,
    "5": 4, "6": 5, "7": 6, "8": 7,
    "9": 8, "A": 9, "B": 10, "C": 11,
    "D": 12, "E": 13, "F": 14, "G": 15,
    "H": 16, "J": 17, "K": 18, "L": 19,
    "M": 20, "N": 21, "P": 22, "Q": 23,
    "R": 24, "S": 25, "T": 26, "U": 27,
    "V": 28, "W": 29, "X": 30, "Y": 31,
    "Z": 32, "a": 33, "b": 34, "c": 35,
    "d": 36, "e": 37, "f": 38, "g": 39,
    "h": 40, "i": 41, "j": 42, "k": 43,
    "m": 44, "n": 45, "o": 46, "p": 47,
    "q": 48, "r": 49, "s": 50, "t": 51,
    "u": 52, "v": 53, "w": 54, "x": 55,
    "y": 56, "z": 57,
};
function base58encode(bytes) {
    var leading_zeroes = 0;
    while (bytes[leading_zeroes] === 0) // count leading zeroes
        ++leading_zeroes;
    var bigint = new BN(0);
    // convert bytes to bigint
    for (var i = 0; i < bytes.length; ++i) {
        bigint = bigint.shln(8);
        bigint = bigint.or(new BN(bytes[i]));
    }
    bytes.reverse();
    var ret = "";
    while (bigint.gt(bn_0)) {
        // get base58 character
        var remainder = bigint.mod(bn_58);
        bigint = bigint.div(bn_58);
        ret += base58Characters[remainder.toNumber()];
    }
    for (var i = 0; i < leading_zeroes; ++i) // add padding if necessary
        ret += base58Characters[0];
    return ret.split("").reverse().join("");
}
function base58checkEncode(bytes) {
    var leading_zeroes = 0;
    while (bytes[leading_zeroes] === 0) // count leading zeroes
        ++leading_zeroes;
    bytes.push.apply(bytes, SHA256(SHA256(bytes)).slice(0, 4));
    var bigint = new BN(0);
    // convert bytes to bigint
    for (var i = 0; i < bytes.length; ++i) {
        bigint = bigint.shln(8);
        bigint = bigint.or(new BN(bytes[i]));
    }
    bytes.reverse();
    var ret = "";
    while (bigint.gt(bn_0)) {
        // get base58 character
        var remainder = bigint.mod(bn_58);
        bigint = bigint.div(bn_58);
        ret += base58Characters[remainder.toNumber()];
    }
    for (var i = 0; i < leading_zeroes; ++i) // add padding if necessary
        ret += base58Characters[0];
    return ret.split("").reverse().join("");
}
function base58checkDecode(text) {
    var newstring = text.split("").reverse().join("");
    for (var i_1 = 0; i_1 < text.length; ++i_1) {
        if (text[i_1] == base58Characters[0])
            newstring = newstring.substr(0, newstring.length - 1);
        else
            break;
    }
    var bigint = bn_0;
    for (var i_2 = newstring.length - 1; i_2 >= 0; --i_2) {
        var charIndex = base58CharsIndices[newstring[i_2]];
        if (charIndex === undefined)
            throw new Error("invalid character: " + newstring[i_2]);
        bigint = (bigint.mul(bn_58)).add(new BN(charIndex));
    }
    var bytes = bigintToByteArray(bigint);
    if (bytes[bytes.length - 1] == 0)
        bytes.pop();
    bytes.reverse();
    var checksum = bytes.slice(bytes.length - 4, bytes.length);
    bytes.splice(bytes.length - 4, 4);
    var sha_result = SHA256(SHA256(bytes));
    for (var i = 0; i < 4; ++i) {
        if (sha_result[i] != checksum[i])
            throw new Error("invalid checksum");
    }
    return bytes;
}
// get ECC public key from bigint
function getECCKeypair(val) {
    if (val.isZero() || val.gte(ecc_n)) {
        console.log("invalid value");
        throw new Error("Invalid EC value");
    }
    return EccMultiply(ecc_Gx, ecc_Gy, val);
}
// make legacy address from public key
function makeAddress(keypair) {
    var key_bytes = [];
    var bytes_public_x = bigintToByteArray(keypair.x);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    key_bytes.push.apply(key_bytes, bytes_public_x);
    if (keypair.y.isOdd())
        key_bytes.push(0x03);
    else
        key_bytes.push(0x02);
    key_bytes.reverse();
    var sha_result_1 = SHA256(key_bytes);
    var ripemd_result_2 = RIPEMD160(sha_result_1);
    var ripemd_extended = [isTestnet ? 0x6F : 0x00];
    ripemd_extended.push.apply(ripemd_extended, ripemd_result_2);
    var sha_result_3 = SHA256(ripemd_extended);
    var sha_result_4 = SHA256(sha_result_3);
    ripemd_extended.push.apply(ripemd_extended, sha_result_4.slice(0, 4));
    return base58encode(ripemd_extended);
}
// make segwit address from public key
function makeSegwitAddress(keypair) {
    var key_bytes = [];
    var bytes_public_x = bigintToByteArray(keypair.x);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    key_bytes.push.apply(key_bytes, bytes_public_x);
    if (keypair.y.isOdd())
        key_bytes.push(0x03);
    else
        key_bytes.push(0x02);
    key_bytes.reverse();
    var sha_result_1 = SHA256(key_bytes);
    var keyhash = RIPEMD160(sha_result_1);
    var redeemscript = [0x00, 0x14];
    redeemscript.push.apply(redeemscript, keyhash);
    var redeemscripthash = [isTestnet ? 0xC4 : 0x05];
    redeemscripthash.push.apply(redeemscripthash, RIPEMD160(SHA256(redeemscript)));
    redeemscripthash.push.apply(redeemscripthash, SHA256(SHA256(redeemscripthash)).slice(0, 4));
    return base58encode(redeemscripthash);
}
var bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32HrpExpand(hrp) {
    var ret = [];
    for (var i = 0; i < hrp.length; ++i)
        ret.push(hrp.charCodeAt(i) >> 5);
    ret.push(0);
    for (var i = 0; i < hrp.length; ++i)
        ret.push(hrp.charCodeAt(i) & 0x1f);
    return ret;
}
function bech32Polymod(values) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var i = 0; i < values.length; ++i) {
        var b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (var j = 0; j < 5; ++j) {
            if ((b >> j) & 1)
                chk ^= GEN[j];
        }
    }
    return chk;
}
function bech32CreateChecksum(hrp, data) {
    var hrpExpanded = bech32HrpExpand(hrp);
    hrpExpanded.push.apply(hrpExpanded, data);
    hrpExpanded.push.apply(hrpExpanded, [0, 0, 0, 0, 0, 0]);
    var polymod = bech32Polymod(hrpExpanded) ^ 1;
    var ret = [];
    for (var i = 0; i < 6; ++i)
        ret.push((polymod >> 5 * (5 - i)) & 31);
    return ret;
}
// create bech32 address from public key
function makeBech32Address(keypair) {
    var key_bytes = [];
    var bytes_public_x = bigintToByteArray(keypair.x);
    while (bytes_public_x.length < 32)
        bytes_public_x.push(0);
    key_bytes.push.apply(key_bytes, bytes_public_x);
    if (keypair.y.isOdd())
        key_bytes.push(0x03);
    else
        key_bytes.push(0x02);
    key_bytes.reverse();
    var sha_result_1 = SHA256(key_bytes);
    var keyhash = RIPEMD160(sha_result_1);
    var redeemscript = [0x00, 0x14];
    redeemscript.push.apply(redeemscript, keyhash);
    var value = 0;
    var bits = 0;
    var result = [0];
    for (var i = 0; i < 20; ++i) {
        value = ((value << 8) | keyhash[i]) & 0xFFFFFF;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result.push((value >> bits) & 0x1F);
        }
    }
    var address = isTestnet ? "tb1" : "bc1";
    for (var i = 0; i < result.length; ++i)
        address += bech32Chars[result[i]];
    var checksum = bech32CreateChecksum(isTestnet ? "tb" : "bc", result);
    for (var i = 0; i < checksum.length; ++i)
        address += bech32Chars[checksum[i]];
    return address;
}
// create base58 encoded private key from bigint
function makePrivateKey(bigint) {
    var privkey = [];
    privkey.push(0x01);
    var temp = bigintToByteArray(bigint);
    while (temp.length < 32)
        temp.push(0);
    privkey.push.apply(privkey, temp);
    privkey.push(isTestnet ? 0xEF : 0x80);
    privkey.reverse();
    privkey.push.apply(privkey, SHA256(SHA256(privkey)).slice(0, 4));
    return base58encode(privkey);
}
var singleAddressType = "bech32";
// set generated address type (single address)
function setAddressType(type) {
    singleAddressType = type;
}
var qrErrorCorrectionLevel = "H";

// returns addresses generated from the private key
function view_address_details_result(privkey) {
    if (privkey.length === 58 && privkey[0] === "6" && privkey[1] === "P") {
        // maybe a bip38 encrypted key
        var bip38_result = bip38decrypt(privkey, "", true);
        if (typeof bip38_result === "number") {
            document.getElementById("bip38_decrypt_div").style.display = "block";
            return 1;
        }
        else if (typeof bip38_result === "string")
            return bip38_result;
        else
            document.getElementById("bip38_decrypt_div").style.display = "none";
    }
    else
        document.getElementById("bip38_decrypt_div").style.display = "none";
    var keypair = privkeyStringToKeyPair(privkey);
    if (typeof keypair === "string")
        return keypair;
    return {
        segwitAddress: makeSegwitAddress(keypair.keypair),
        bech32Address: makeBech32Address(keypair.keypair),
        legacyAddress: makeAddress(keypair.keypair)
    };
}
function privkeyStringToKeyPair(privkey) {
    var newstring = privkey.split("").reverse().join("");
    for (var i = 0; i < privkey.length; ++i) {
        if (privkey[i] === base58Characters[0])
            newstring = newstring.substr(0, newstring.length - 1);
        else
            break;
    }
    var bigint = new BN(0);
    for (var i = newstring.length - 1; i >= 0; --i)
        bigint = bigint.mul(bn_58).add(new BN(base58CharsIndices[newstring[i]]));
    var bytes = bigintToByteArray(bigint);
    if (bytes[bytes.length - 1] === 0)
        bytes.pop();
    bytes.reverse();
    var checksum = bytes.slice(bytes.length - 4, bytes.length);
    bytes.splice(bytes.length - 4, 4);
    var sha_result = SHA256(SHA256(bytes));
    for (var i = 0; i < 4; ++i) {
        if (sha_result[i] !== checksum[i])
            return "invalid checksum";
    }
    if (bytes.pop() !== 1)
        return "only compressed private keys are supported, they start with 'L' or 'K'";
    bytes.reverse();
    bytes.pop();
    if (bytes.length !== 32)
        return "invalid length";
    bigint = new BN(0);
    for (var j = bytes.length - 1; j >= 0; --j) {
        bigint = bigint.shln(8);
        bigint = bigint.or(new BN(bytes[j]));
    }
    var keypair = getECCKeypair(bigint);
    var privkey2 = makePrivateKey(bigint);
    if (privkey !== privkey2)
        return "cannot decode private key";
    return {
        privkey: bigint,
        keypair: keypair
    };
}

function view_address_details() {
    var privkey = document.getElementById("view_address_privkey_textbox").value.trim();
    if (privkey === "")
        return;
    var result = view_address_details_result(privkey);
    if (typeof result === "string" || typeof result === "number") {
        if (typeof result === "string") {
            // error
            document.getElementById("view_address_information").textContent = "Invalid private key (" + result + ")";
        }
        else {
            // bip38 encrypted
            document.getElementById("view_address_information").textContent = "";
        }
        document.getElementById("view_address_segwitaddress").textContent = "";
        document.getElementById("view_address_bech32address").textContent = "";
        document.getElementById("view_address_legacyaddress").textContent = "";
        document.getElementById("view_address_segwitaddress_qr").textContent = "";
        document.getElementById("view_address_bech32address_qr").textContent = "";
        document.getElementById("view_address_legacyaddress_qr").textContent = "";
        document.getElementById("view_address_container").style.display = "none";
        return;
    }
    document.getElementById("view_address_information").innerHTML = "Details for private key: <strong>" + privkey + "</strong>";
    document.getElementById("view_address_segwitaddress").textContent = "Segwit address: " + result.segwitAddress;
    document.getElementById("view_address_bech32address").textContent = "Segwit (bech32) address: " + result.bech32Address;
    document.getElementById("view_address_legacyaddress").textContent = "Legacy address: " + result.legacyAddress;
    var segwitQR = qrcode(0, qrErrorCorrectionLevel);
    segwitQR.addData(result.segwitAddress);
    segwitQR.make();
    document.getElementById("view_address_segwitaddress_qr").innerHTML = segwitQR.createImgTag(4, 8);
    var bech32QR = qrcode(0, qrErrorCorrectionLevel);
    bech32QR.addData(result.bech32Address.toUpperCase(), "Alphanumeric");
    bech32QR.make();
    document.getElementById("view_address_bech32address_qr").innerHTML = bech32QR.createImgTag(4, 8);
    var legacyQR = qrcode(0, qrErrorCorrectionLevel);
    legacyQR.addData(result.legacyAddress);
    legacyQR.make();
    document.getElementById("view_address_legacyaddress_qr").innerHTML = legacyQR.createImgTag(4, 8);
    var containerStyle = document.getElementById("view_address_container").style;
    containerStyle.display = "table";
    containerStyle.border = "2px solid #bbbbbb";
    containerStyle.borderRadius = "3px";
}