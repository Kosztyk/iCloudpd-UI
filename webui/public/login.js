(async function(){
  // Theme switch
  const sw = document.getElementById("themeSwitch");
  sw.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    window.__theme.setTheme(cur === "dark" ? "light" : "dark");
  });

  // Determine if setup needed
  try {
    const me = await api("/api/me", { method: "GET" });
    // already authenticated
    window.location.href = "/app.html";
    return;
  } catch (e) {
    // ignore
  }

  const status = await api("/api/setup/status", { method: "GET" });
  const setupNeeded = !!status.setupRequired;
  const title = document.getElementById("title");
  const subtitle = document.getElementById("subtitle");
  const btn = document.getElementById("submitBtn");
  const hint = document.getElementById("setupHint");

  if (setupNeeded) {
    title.textContent = "Initial setup";
    subtitle.textContent = "Create the first admin user.";
    btn.textContent = "Create admin";
    hint.style.display = "block";
  }

  // Break-glass admin password reset (requires reset token)
  const resetWrap = document.getElementById("resetWrap");
  const forgotBtn = document.getElementById("forgotBtn");
  if (!setupNeeded && resetWrap && forgotBtn) {
    resetWrap.style.display = "block";
    forgotBtn.addEventListener("click", () => {
      const backdrop = document.createElement("div");
      backdrop.className = "simple-modal-backdrop";
      backdrop.innerHTML = `
        <div class="simple-modal" style="max-width: 560px;">
          <div class="simple-modal-head" style="align-items:flex-start; gap:10px">
            <div style="flex:1">
              <div class="simple-modal-title">Reset admin password</div>
              <div class="small" style="margin-top:2px">Requires the admin reset token.</div>
            </div>
            <div style="display:flex; gap:8px">
              <button class="btn secondary" id="rpCancel">Cancel</button>
              <button class="btn" id="rpSave">Reset</button>
            </div>
          </div>
          <div class="simple-modal-body">
            <label>Admin username</label>
            <input class="input" id="rpUser" placeholder="admin" />
            <label>Reset token</label>
            <input class="input" id="rpToken" placeholder="ADMIN_RESET_TOKEN" />
            <label>New password</label>
            <input class="input" id="rpPass" type="password" placeholder="Minimum 10 characters" />
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);
      const close = () => backdrop.remove();
      backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
      backdrop.querySelector("#rpCancel").addEventListener("click", close);
      backdrop.querySelector("#rpSave").addEventListener("click", async () => {
        const btn = backdrop.querySelector("#rpSave");
        btn.disabled = true;
        try {
          const username = backdrop.querySelector("#rpUser").value.trim();
          const token = backdrop.querySelector("#rpToken").value.trim();
          const new_password = backdrop.querySelector("#rpPass").value;
          await api("/api/admin/reset-password", {
            method: "POST",
            body: JSON.stringify({ username, token, new_password }),
          });
          toast("Password reset. You can sign in now.");
          close();
        } catch (err) {
          toast(String(err.message || err));
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  document.getElementById("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    try {
      if (setupNeeded) {
        await api("/api/setup/create-admin", { method: "POST", body: JSON.stringify({ username, password }) });
      } else {
        await api("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
      }
      window.location.href = "/app.html";
    } catch (err) {
      toast(String(err.message || err));
    }
  });
})();
