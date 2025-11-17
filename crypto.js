/*
    RSA + AES 混合加密核心代码
    使用 WebCrypto API
*/

/* ------------------------------
    RSA 密钥相关
--------------------------------*/

// 生成 RSA 密钥对
async function generateRSAKey() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// 导出 RSA 公钥 → Base64格式
async function exportPublicKey(publicKey) {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(spki)));
}

// 导出 RSA 私钥（一般不用导出）
async function exportPrivateKey(privateKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
    return btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
}

// 导入 RSA 公钥（Base64 → KeyObject）
async function importPublicKey(base64) {
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
        "spki",
        binary,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );
}

// RSA 加密（Uint8Array 输入）
async function rsaEncrypt(data, publicKey) {
    const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
    );
    return new Uint8Array(encrypted);
}

// RSA 解密（Uint8Array 输入）
async function rsaDecrypt(data, privateKey) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        data
    );
    return new Uint8Array(decrypted);
}

/* ------------------------------
    AES 密钥相关
--------------------------------*/

// 生成 AES-GCM 密钥
async function generateAESKey() {
    return await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// 导出 AES Key → Uint8Array
async function exportAESKey(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(raw);
}

// 导入 AES Key（Uint8Array）
async function importAESKey(raw) {
    return await crypto.subtle.importKey(
        "raw",
        raw,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
    );
}

/* ------------------------------
    AES 加密 & 解密
--------------------------------*/

// AES-GCM 加密（返回 Uint8Array 完整包：iv + ciphertext）
async function aesEncrypt(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    // 生成随机 IV（12字节）
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        data
    );

    // 拼接 IV + 密文
    const encryptedBytes = new Uint8Array(encrypted);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);

    combined.set(iv);
    combined.set(encryptedBytes, iv.length);

    return combined;
}

// AES-GCM 解密（输入 Uint8Array 组合包）
async function aesDecrypt(combined, key) {
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}
