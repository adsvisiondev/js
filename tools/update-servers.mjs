import { createCipheriv } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const SOURCE_URL =
  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt";

const OUTPUT_FILE = resolve(process.cwd(), "servers.enc");

/*
 * در برنامه شما مقادیر اولیه 17 کاراکتر هستند:
 *
 * MyMaterialVPNKey!
 * MyMaterialVPNIV!!
 *
 * اما ابزار فقط 16 بایت اول را استفاده می‌کند.
 * بنابراین مقدار مؤثر دقیقاً این‌ها هستند:
 */
const AES_KEY = "MyMaterialVPNKey"; // دقیقاً 16 بایت
const AES_IV = "MyMaterialVPNIV!";  // دقیقاً 16 بایت

const USERNAME = "vpn";
const PASSWORD = "vpn";

const COUNTRY_FLAGS = {
  Australia: "🇦🇺",
  Austria: "🇦🇹",
  Belgium: "🇧🇪",
  Brazil: "🇧🇷",
  Canada: "🇨🇦",
  China: "🇨🇳",
  France: "🇫🇷",
  Germany: "🇩🇪",
  India: "🇮🇳",
  Indonesia: "🇮🇩",
  Iran: "🇮🇷",
  Italy: "🇮🇹",
  Japan: "🇯🇵",
  Mexico: "🇲🇽",
  Netherlands: "🇳🇱",
  "The Netherlands": "🇳🇱",
  Norway: "🇳🇴",
  Poland: "🇵🇱",
  Russia: "🇷🇺",
  "Saudi Arabia": "🇸🇦",
  Singapore: "🇸🇬",
  Spain: "🇪🇸",
  Syria: "🇸🇾",
  Taiwan: "🇹🇼",
  Thailand: "🇹🇭",
  Turkey: "🇹🇷",
  Ukraine: "🇺🇦",
  "United Kingdom": "🇬🇧",
  "United States": "🇺🇸",
  Vietnam: "🇻🇳",
  "South Korea": "🇰🇷",
  "North Korea": "🇰🇵",
};

async function main() {
  console.log("Downloading SSTP server list...");
  console.log(`Source: ${SOURCE_URL}`);

  const response = await fetch(SOURCE_URL, {
    method: "GET",
    redirect: "follow",
    headers: {
      Accept: "text/plain,*/*",
      "User-Agent": "adsvisiondev-sstp-updater/1.0",
    },
  });

  if (!response.ok) {
    throw new Error(
      `Source request failed: HTTP ${response.status} ${response.statusText}`
    );
  }

  const sourceText = await response.text();

  if (!sourceText.trim()) {
    throw new Error("Source returned an empty server list");
  }

  const parsedServers = parseServerList(sourceText);

  if (parsedServers.length === 0) {
    throw new Error(
      "No valid SSTP servers were extracted from the source"
    );
  }

  const servers = parsedServers.map((server, index) => ({
    id: String(index + 1),
    countryName: server.country,
    flagEmoji: getCountryFlag(server.country),
    pingMs: 0,
    hostName: server.host,
    userName: USERNAME,
    password: PASSWORD,
    sslPort: server.port,
  }));

  /*
   * JSON دقیقاً با همان مدل فایل نمونه ساخته می‌شود.
   */
  const normalJson = JSON.stringify(servers, null, 2);

  /*
   * ایموجی پرچم‌ها را به فرمت:
   *
   * \uD83C\uDDEF\uD83C\uDDF5
   *
   * تبدیل می‌کند تا ساختار خروجی با JSON نمونه یکسان باشد.
   */
  const compatibleJson = escapeNonAscii(normalJson);

  const encryptedOutput = encryptAes128Cbc(compatibleJson);

  await writeFile(OUTPUT_FILE, encryptedOutput, {
    encoding: "utf8",
  });

  console.log("----------------------------------------");
  console.log(`Valid servers: ${servers.length}`);
  console.log(`JSON length: ${compatibleJson.length}`);
  console.log(`Encrypted length: ${encryptedOutput.length}`);
  console.log(`Output file: ${OUTPUT_FILE}`);
  console.log("----------------------------------------");
  console.log("servers.enc generated successfully.");
}

/**
 * خطوطی با ساختار زیر را شناسایی می‌کند:
 *
 * France | vpn.example.com:443
 * South Korea | vpn.example.com:995
 *
 * این الگو حتی اگر تمام ورودی اشتباهاً در یک خط قرار گرفته باشد
 * نیز می‌تواند سرورها را استخراج کند.
 */
function parseServerList(sourceText) {
  const normalized = sourceText
    .replace(/\uFEFF/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");

  const pattern =
    /([A-Za-z][A-Za-z .'-]*?)\s*\|\s*([A-Za-z0-9.-]+):(\d{1,5})/g;

  const uniqueServers = [];
  const duplicateCheck = new Set();

  for (const match of normalized.matchAll(pattern)) {
    const country = normalizeCountryName(match[1]);
    const host = match[2].trim().toLowerCase();
    const port = Number.parseInt(match[3], 10);

    if (!country) {
      continue;
    }

    if (!isValidHostname(host)) {
      console.warn(`Invalid hostname ignored: ${host}`);
      continue;
    }

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.warn(`Invalid port ignored: ${host}:${port}`);
      continue;
    }

    const uniqueKey = `${host}:${port}`;

    if (duplicateCheck.has(uniqueKey)) {
      continue;
    }

    duplicateCheck.add(uniqueKey);

    uniqueServers.push({
      country,
      host,
      port,
    });
  }

  return uniqueServers;
}

function normalizeCountryName(value) {
  return value
    .replace(/\s+/g, " ")
    .replace(/^[\s|,-]+/, "")
    .replace(/[\s|,-]+$/, "")
    .trim();
}

function isValidHostname(host) {
  if (!host || host.length > 253) {
    return false;
  }

  if (
    host.startsWith(".") ||
    host.endsWith(".") ||
    host.includes("..")
  ) {
    return false;
  }

  return /^[a-z0-9.-]+$/i.test(host);
}

function getCountryFlag(countryName) {
  return COUNTRY_FLAGS[countryName] ?? "🌐";
}

/**
 * AES-128-CBC
 * Key: 16 bytes
 * IV: 16 bytes
 * Padding: PKCS#7
 * Output: Base64
 */
function encryptAes128Cbc(plainText) {
  const keyBuffer = Buffer.from(AES_KEY, "utf8");
  const ivBuffer = Buffer.from(AES_IV, "utf8");

  if (keyBuffer.length !== 16) {
    throw new Error(
      `AES key must be exactly 16 bytes; received ${keyBuffer.length}`
    );
  }

  if (ivBuffer.length !== 16) {
    throw new Error(
      `AES IV must be exactly 16 bytes; received ${ivBuffer.length}`
    );
  }

  const cipher = createCipheriv(
    "aes-128-cbc",
    keyBuffer,
    ivBuffer
  );

  /*
   * در Node.js، Auto Padding به‌صورت پیش‌فرض فعال است
   * و از PKCS#7 استفاده می‌کند.
   */
  cipher.setAutoPadding(true);

  const encrypted = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final(),
  ]);

  return encrypted.toString("base64");
}

/**
 * JSON.stringify ایموجی را مستقیم ذخیره می‌کند.
 * این تابع کاراکترهای غیر ASCII را به Unicode Escape تبدیل می‌کند.
 */
function escapeNonAscii(value) {
  return value.replace(
    /[\u007F-\uFFFF]/g,
    (character) =>
      `\\u${character
        .charCodeAt(0)
        .toString(16)
        .toUpperCase()
        .padStart(4, "0")}`
  );
}

main().catch((error) => {
  console.error("Update failed:");
  console.error(error);
  process.exitCode = 1;
});
