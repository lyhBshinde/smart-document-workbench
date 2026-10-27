#!/usr/bin/env node
/**
 * TraeWork 每日签到 - 令牌读取脚本（通用版，纯 Node.js）
 *
 * 从 TraeWork / TraeCode 桌面端的 storage.json 中读取并解密
 * iCubeAuthInfo://icube.cloudide 字段，提取访问令牌和设备 ID。
 *
 * 加密算法：AES-128-CBC + SHA-512 密钥派生 + SHA-512 完整性校验
 *
 * 安全警示（务必阅读）：
 *   - 本脚本输出的 token 等同 TraeWork 账号密码，属于高敏感凭据。
 *   - token 仅通过 stdout 的 DECRYPT_RESULT:<token> 行输出，由调用方经管道立即消费；
 *     切勿 tee/重定向到文件、切勿粘贴分享、切勿提交到任何仓库。
 *   - 日志只记录签到结果（积分/成功失败），绝不记录 token 原文。
 *   - 读取/解密成功时会向 stderr 打印一行安全提示（不进入 stdout，不会污染 token 管道）。
 *
 * 依赖：
 *   - 仅需 Node.js（内置 crypto 模块，无需额外安装 npm 包）
 *
 * 运行方式：
 *   node decrypt-token.js
 *
 * 输出（stdout，按行前缀过滤）：
 *   DECRYPT_RESULT:<accessToken>
 *   DEVICE_ID:<deviceId>
 *   USER_ID:<userId>
 *   EDITION:<edition>
 *
 * 失败时 DECRYPT_RESULT:ERR <原因>
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

// ============================================================
// 加密常量（与 Trae 客户端同源）
// ============================================================

const SALT_A = Uint8Array.from([
  82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
  124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
  84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
  8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
]);

const SALT_B = Uint8Array.from([
  31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
  96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
  160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
  23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
]);

const HEADER_AES = Buffer.from([116, 99, 5, 16, 0, 0]);
const HEADER_AES_PRIVATE = Buffer.from([18, 57, 32, 32, 2, 3]);

const AUTH_STORAGE_KEY = "iCubeAuthInfo://icube.cloudide";
const DC_KEY_PREFIX = "iCubeAuthInfo://icube-dc:";

// ============================================================
// 工具函数
// ============================================================

function xor(a, b) {
  return Buffer.from(a.map((v, i) => v ^ (b[i] ?? 0)));
}

function encryptionType(header) {
  if (header.equals(HEADER_AES)) return "aes";
  if (header.equals(HEADER_AES_PRIVATE)) return "aes-private";
  return null;
}

/**
 * 解密 Trae 存储字段
 * @param {string} encoded - base64 编码的密文
 * @returns {string} 解密后的明文字符串
 */
function decryptTraeStorageValue(encoded) {
  const buffer = Buffer.from(encoded, "base64");
  if (buffer.length <= 102) {
    throw new Error("密文太短（<= 102 字节）");
  }

  const type = encryptionType(buffer.subarray(0, 6));
  if (!type) {
    throw new Error("不支持的加密头部格式");
  }

  const random = buffer.subarray(6, 38); // 32 字节随机数
  const encrypted = buffer.subarray(38); // 剩余为密文

  // 密钥派生：SHA-512(SHA-512(random) + salt)
  // 注：aes-private 类型使用 SALT_C/SALT_D，普通 aes 使用 SALT_A/SALT_B
  // 但 TraeWork 登录态通常为 aes 类型，此处只处理 aes 类型
  const salt = xor(SALT_A, SALT_B);
  const first = crypto.createHash("sha512").update(random).digest();
  const derived = crypto
    .createHash("sha512")
    .update(Buffer.concat([first, salt]))
    .digest();

  const key = derived.subarray(0, 16); // AES-128 密钥
  const iv = derived.subarray(16, 32); // CBC IV

  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  if (decrypted.length < 64) {
    throw new Error("明文太短（< 64 字节），完整性校验失败");
  }

  // 完整性校验：前 64 字节是明文的 SHA-512 哈希
  const expectedHash = decrypted.subarray(0, 64);
  const plaintext = decrypted.subarray(64);
  const actualHash = crypto.createHash("sha512").update(plaintext).digest();

  if (!expectedHash.equals(actualHash)) {
    throw new Error("完整性校验失败（SHA-512 不匹配）");
  }

  return plaintext.toString("utf8");
}

// ============================================================
// storage.json 候选路径（按平台和应用名优先级）
// ============================================================

function storageCandidates() {
  const home = os.homedir();
  const ap = process.env.APPDATA || "";
  const xdg = process.env.XDG_CONFIG_HOME || path.join(home, ".config");

  // 应用名按优先级排列：SOLO（Work版）优先于 IDE 版，CN 版优先于国际版
  const appNames = ["TRAE SOLO CN", "Trae CN", "TRAE SOLO", "Trae"];
  const editions = ["solo", "cn", "solo-sg", "sg"];

  let roots;
  if (process.platform === "darwin") {
    roots = appNames.map((a) =>
      path.join(home, "Library", "Application Support", a)
    );
  } else if (process.platform === "win32") {
    roots = appNames.map((a) => path.join(ap, a));
  } else {
    roots = appNames.map((a) => path.join(xdg, a));
  }

  return roots.map((root, i) => ({
    root,
    appName: appNames[i],
    edition: editions[i],
    storagePath: path.join(root, "User", "globalStorage", "storage.json"),
    machineIdPath: path.join(root, "machineid"),
  }));
}

// ============================================================
// 设备 ID 提取
// ============================================================

function extractDeviceId(storage, machineIdFile, edition) {
  // 优先级 1：设备中心 ID（icube-dc）
  const dcKey = Object.keys(storage).find((k) => k.startsWith(DC_KEY_PREFIX));
  if (dcKey) {
    return dcKey.slice(DC_KEY_PREFIX.length);
  }

  // 优先级 2：telemetry.devDeviceId
  if (storage["telemetry.devDeviceId"]) {
    return storage["telemetry.devDeviceId"];
  }

  // 优先级 3：SHA-256(telemetry.machineId) 前 32 字节
  const mid =
    storage["telemetry.machineId"] ||
    (fs.existsSync(machineIdFile)
      ? fs.readFileSync(machineIdFile, "utf8").trim()
      : "");

  if (mid) {
    return crypto.createHash("sha256").update(mid).digest("hex").slice(0, 32);
  }

  return "";
}

// ============================================================
// 主流程
// ============================================================

function emitAndExit(code, lines) {
  process.stdout.write(lines.join("\n") + "\n");
  // 延迟退出确保 stdout flush
  setTimeout(() => process.exit(code), 100);
}

function main() {
  // 手动指定 storage 路径
  const manualStorage = process.env.TRAE_CHECKIN_STORAGE;
  const manualApp = process.env.TRAE_CHECKIN_APP;

  let candidates;
  if (manualStorage) {
    candidates = [
      {
        root: path.dirname(path.dirname(path.dirname(manualStorage))),
        appName: manualApp || "custom",
        edition: "custom",
        storagePath: manualStorage,
        machineIdPath: path.join(
          path.dirname(path.dirname(path.dirname(manualStorage))),
          "machineid"
        ),
      },
    ];
  } else {
    candidates = storageCandidates();
    if (manualApp) {
      candidates = candidates.filter((c) => c.appName === manualApp);
    }
  }

  let lastError = "";

  for (const cand of candidates) {
    if (!fs.existsSync(cand.storagePath)) continue;

    try {
      const storageRaw = fs.readFileSync(cand.storagePath, "utf8");
      const storage = JSON.parse(storageRaw);

      const encrypted = storage[AUTH_STORAGE_KEY];
      if (!encrypted || typeof encrypted !== "string") {
        lastError = `storage.json 中缺少 ${AUTH_STORAGE_KEY} 字段`;
        continue;
      }

      // 如果已经是明文 JSON（开发模式或旧版本），直接使用
      let plaintext;
      if (encrypted.startsWith("{")) {
        plaintext = encrypted;
      } else {
        plaintext = decryptTraeStorageValue(encrypted);
      }

      const auth = JSON.parse(plaintext);
      const token = auth.token || auth.accessToken;

      if (!token) {
        lastError = "解密后未找到 token 字段";
        continue;
      }

      const deviceId = extractDeviceId(storage, cand.machineIdPath, cand.edition);
      const userId = auth.userId || auth.uid || "";

      process.stderr.write(
        "[安全提示] 已从本地登录态解密访问令牌（AES-128-CBC），仅用于 TraeWork 官方签到接口；" +
          "请勿将其写入日志、分享或提交。\n"
      );

      emitAndExit(0, [
        "DECRYPT_RESULT:" + token,
        "DEVICE_ID:" + deviceId,
        "USER_ID:" + userId,
        "EDITION:" + cand.edition,
      ]);
      return;
    } catch (e) {
      lastError = e.message;
      // 继续尝试下一个候选
    }
  }

  emitAndExit(1, [
    "DECRYPT_RESULT:ERR 未找到有效的 TraeWork 本地登录态（" +
      lastError +
      "）。请确认已安装并登录 TraeWork / TraeCode 桌面端。",
  ]);
}

main();
