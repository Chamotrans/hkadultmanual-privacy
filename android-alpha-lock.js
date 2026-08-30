(() => {
  "use strict";

  const saltHex = "3ac7389e3d5e3606408d6d7f453074d4";
  const expectedHex = "777f38fa7c25931f5fc0bb58f41b8725e4e8499f91cfff5693706011d6350e93";
  const iterations = 210000;
  const sessionKey = "hkadultmanual-alpha-access";

  const gate = document.querySelector("#access-gate");
  const content = document.querySelector("#protected-content");
  const form = document.querySelector("#access-form");
  const input = document.querySelector("#access-password");
  const error = document.querySelector("#access-error");

  const hexToBytes = (hex) =>
    new Uint8Array(hex.match(/.{2}/g).map((byte) => Number.parseInt(byte, 16)));

  const bytesToHex = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

  const matches = (left, right) => {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
      difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return difference === 0;
  };

  const showContent = () => {
    gate.hidden = true;
    content.hidden = false;
    document.title = "香港大人說明書 — Android Alpha";
  };

  if (sessionStorage.getItem(sessionKey) === expectedHex) {
    showContent();
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "驗證中…";

    try {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(input.value),
        "PBKDF2",
        false,
        ["deriveBits"]
      );
      const bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: hexToBytes(saltHex),
          iterations,
          hash: "SHA-256"
        },
        keyMaterial,
        256
      );
      const actualHex = bytesToHex(new Uint8Array(bits));

      if (!matches(actualHex, expectedHex)) {
        input.select();
        error.textContent = "密碼不正確，請向邀請人確認。";
        return;
      }

      sessionStorage.setItem(sessionKey, expectedHex);
      input.value = "";
      error.textContent = "";
      showContent();
    } catch {
      error.textContent = "瀏覽器無法完成密碼驗證，請更新後再試。";
    }
  });
})();
