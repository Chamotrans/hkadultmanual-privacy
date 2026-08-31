(() => {
  "use strict";

  const saltHex = "3ac7389e3d5e3606408d6d7f453074d4";
  const expectedHex = "dcb0b2bed28ba3808bcf6caf9665012276223037046e0f4a5b8ce53164cc9e8c";
  const iterations = 210000;
  const sessionKey = "hkadultmanual-alpha-access";
  const memberAccess = "verified-member";
  const articleTaskKey = "hkadultmanual-alpha-article-opened";
  let firebaseConfigPromise;

  const gate = document.querySelector("#access-gate");
  const content = document.querySelector("#protected-content");
  const form = document.querySelector("#access-form");
  const input = document.querySelector("#access-password");
  const error = document.querySelector("#access-error");
  const memberForm = document.querySelector("#member-access-form");
  const memberEmail = document.querySelector("#member-email");
  const memberPassword = document.querySelector("#member-password");
  const memberError = document.querySelector("#member-access-error");
  const taskItems = Object.fromEntries(
    Array.from(document.querySelectorAll("[data-task]"), (item) => [item.dataset.task, item])
  );
  taskItems.article?.querySelector("a")?.addEventListener("click", () => {
    try {
      localStorage.setItem(articleTaskKey, "1");
    } catch {
      // The task can still be checked after sign-in. Some Android browsers
      // disable storage in private/restricted mode, so this must not break the
      // rest of the gate.
    }
  });

  const hexToBytes = (hex) =>
    new Uint8Array(hex.match(/.{2}/g).map((byte) => Number.parseInt(byte, 16)));

  const bytesToHex = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

  const normalizeInviteCode = (value) =>
    value.normalize("NFKC").toUpperCase().replace(/[^A-Z0-9]/gu, "");

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

  if ([expectedHex, memberAccess].includes(sessionStorage.getItem(sessionKey))) {
    showContent();
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "驗證中…";

    try {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(normalizeInviteCode(input.value)),
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

  const firebaseRequest = async (url, options = {}) => {
    const response = await fetch(url, options);
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const requestError = new Error(
        payload?.error?.message || `firebase-http-${response.status}`
      );
      requestError.code = payload?.error?.message || "firebase-request-failed";
      requestError.status = response.status;
      throw requestError;
    }
    return payload;
  };

  const authenticationMessage = (requestError) => {
    const code = String(requestError?.code || requestError?.message || "");
    if (/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND/u.test(code)) {
      return "電郵或密碼不正確。";
    }
    if (/USER_DISABLED/u.test(code)) return "帳戶已停用，未能進入測試頁。";
    if (/TOO_MANY_ATTEMPTS_TRY_LATER|TOO_MANY_REQUESTS/u.test(code)) {
      return "登入嘗試太多，請稍後再試或先到網站重設密碼。";
    }
    return "暫時未能連接帳戶服務，請檢查網絡後再試。";
  };

  const optionalFirebaseDocument = async (url, options) => {
    try {
      return await firebaseRequest(url, options);
    } catch (requestError) {
      if (requestError?.status === 404) return null;
      throw requestError;
    }
  };

  const articleTaskComplete = () => {
    try {
      return localStorage.getItem(articleTaskKey) === "1";
    } catch {
      return false;
    }
  };

  const loadFirebaseConfig = () => {
    if (firebaseConfigPromise) return firebaseConfigPromise;

    firebaseConfigPromise = new Promise((resolve, reject) => {
      const previousFirebase = window.firebase;
      const script = document.createElement("script");
      const cleanup = () => {
        if (previousFirebase === undefined) delete window.firebase;
        else window.firebase = previousFirebase;
        script.remove();
      };

      window.firebase = {
        initializeApp(config) {
          cleanup();
          resolve(config);
        }
      };
      script.src = "https://hkadultmanual.web.app/__/firebase/init.js";
      script.async = true;
      script.onerror = () => {
        cleanup();
        reject(new Error("firebase-config-failed"));
      };
      document.head.append(script);
    });

    return firebaseConfigPromise;
  };

  const markTask = (name, complete) => {
    taskItems[name]?.classList.toggle("complete", complete);
  };

  const firestoreQuery = async (idToken, projectId, structuredQuery) => {
    const rows = await firebaseRequest(
      `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${idToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ structuredQuery })
      }
    );
    return rows.flatMap((row) => row.document ? [row.document] : []);
  };

  const hasOwnDocument = async (idToken, projectId, uid, collectionId) => {
    const documents = await firestoreQuery(idToken, projectId, {
      from: [{ collectionId }],
      where: {
        fieldFilter: {
          field: { fieldPath: "authorID" },
          op: "EQUAL",
          value: { stringValue: uid }
        }
      },
      limit: 1
    });
    return documents.length > 0;
  };

  const hasQuestionComment = async (idToken, projectId, uid) => {
    const comments = await firestoreQuery(idToken, projectId, {
      from: [{ collectionId: "comments", allDescendants: true }],
      where: {
        fieldFilter: {
          field: { fieldPath: "authorID" },
          op: "EQUAL",
          value: { stringValue: uid }
        }
      },
      limit: 20
    });
    const postIDs = [...new Set(comments.flatMap((comment) => {
      const match = comment.name?.match(/\/documents\/posts\/([^/]+)\/comments\//u);
      return match ? [match[1]] : [];
    }))];
    const posts = await Promise.allSettled(postIDs.map((postID) => optionalFirebaseDocument(
      `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/posts/${encodeURIComponent(postID)}`,
      { headers: { Authorization: `Bearer ${idToken}` } }
    )));
    if (posts.some((result) =>
      result.status === "fulfilled"
      && result.value?.fields?.type?.stringValue === "question"
    )) return true;

    // Deleted posts can leave orphaned comment subcollections. A missing parent
    // means the task is incomplete, not that the user's password was wrong.
    const failed = posts.find((result) => result.status === "rejected");
    if (failed?.status === "rejected") throw failed.reason;
    return false;
  };

  memberForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    memberError.textContent = "正在核對網站帳戶及任務…";

    let firebaseConfig;
    let signIn;
    try {
      firebaseConfig = await loadFirebaseConfig();
      signIn = await firebaseRequest(
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: memberEmail.value.trim(),
            password: memberPassword.value,
            returnSecureToken: true
          })
        }
      );
    } catch (requestError) {
      memberPassword.select();
      memberError.textContent = authenticationMessage(requestError);
      return;
    }

    let account;
    try {
      account = await firebaseRequest(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken: signIn.idToken })
        }
      );
    } catch {
      memberError.textContent = "帳戶已登入，但暫時未能讀取電郵驗證狀態。請稍後再試。";
      return;
    }

    const verified = account.users?.[0]?.emailVerified === true;
    markTask("account", verified);

    const checks = await Promise.allSettled([
      optionalFirebaseDocument(
        `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/users/${encodeURIComponent(signIn.localId)}`,
        { headers: { Authorization: `Bearer ${signIn.idToken}` } }
      ),
      hasQuestionComment(signIn.idToken, firebaseConfig.projectId, signIn.localId),
      hasOwnDocument(signIn.idToken, firebaseConfig.projectId, signIn.localId, "chatMessages")
    ]);
    const checkLabels = ["帳戶狀態", "知識＋留言", "聊天室發言"];
    const failedChecks = checks.flatMap((result, index) =>
      result.status === "rejected" ? [checkLabels[index]] : []
    );
    if (failedChecks.length) {
      memberError.textContent = `帳戶已登入，但暫時未能核對${failedChecks.join("、")}。請稍後再試。`;
      return;
    }

    const profile = checks[0].status === "fulfilled" ? checks[0].value : null;
    const comment = checks[1].status === "fulfilled" && checks[1].value;
    const chat = checks[2].status === "fulfilled" && checks[2].value;
    const article = articleTaskComplete();
    const banned = profile?.fields?.isBanned?.booleanValue === true;
    markTask("article", article);
    markTask("comment", comment);
    markTask("chat", chat);

    const missing = [
      [verified, "完成電郵驗證"],
      [article, "閱讀一篇文章"],
      [comment, "喺我要發問留言一次"],
      [chat, "喺聊天室發言一次"]
    ].filter(([complete]) => !complete).map(([, label]) => label);
    if (banned) {
      memberError.textContent = "帳戶已停用，未能進入測試頁。";
      return;
    }
    if (missing.length) {
      memberError.textContent = `尚欠：${missing.join("、")}。完成後再按一次核對。`;
      return;
    }

    try {
      sessionStorage.setItem(sessionKey, memberAccess);
    } catch {
      // Restricted storage must not block an otherwise valid one-time visit.
    }
    memberPassword.value = "";
    memberError.textContent = "";
    showContent();
  });
})();
