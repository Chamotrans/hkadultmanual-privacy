(() => {
  "use strict";

  const saltHex = "3ac7389e3d5e3606408d6d7f453074d4";
  const expectedHex = "777f38fa7c25931f5fc0bb58f41b8725e4e8499f91cfff5693706011d6350e93";
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
    localStorage.setItem(articleTaskKey, "1");
  });

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

  const firebaseRequest = async (url, options) => {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error("firebase-request-failed");
    return response.json();
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
    const posts = await Promise.all(postIDs.map((postID) => firebaseRequest(
      `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/posts/${encodeURIComponent(postID)}`,
      { headers: { Authorization: `Bearer ${idToken}` } }
    )));
    return posts.some((post) => post.fields?.type?.stringValue === "question");
  };

  memberForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    memberError.textContent = "正在核對網站帳戶及任務…";

    try {
      const firebaseConfig = await loadFirebaseConfig();
      const signIn = await firebaseRequest(
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
      const account = await firebaseRequest(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken: signIn.idToken })
        }
      );
      const verified = account.users?.[0]?.emailVerified === true;
      markTask("account", verified);

      const profile = await firebaseRequest(
        `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/users/${encodeURIComponent(signIn.localId)}`,
        { headers: { Authorization: `Bearer ${signIn.idToken}` } }
      );
      const article = localStorage.getItem(articleTaskKey) === "1";
      const [comment, chat] = await Promise.all([
        hasQuestionComment(signIn.idToken, firebaseConfig.projectId, signIn.localId),
        hasOwnDocument(signIn.idToken, firebaseConfig.projectId, signIn.localId, "chatMessages")
      ]);
      const banned = profile.fields?.isBanned?.booleanValue === true;
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

      sessionStorage.setItem(sessionKey, memberAccess);
      memberPassword.value = "";
      memberError.textContent = "";
      showContent();
    } catch {
      memberPassword.select();
      memberError.textContent = "未能核對帳戶。請確認電郵、密碼及網絡後再試。";
    }
  });
})();
