function openSimpleModal(title, bodyHtml){
  const m = document.createElement("div");
  m.className = "simple-modal-backdrop";
  m.innerHTML = `
    <div class="simple-modal">
      <div class="simple-modal-head">
        <div class="simple-modal-title">${escapeHtml(title)}</div>
        <button class="btn" id="modalCloseBtn">Close</button>
      </div>
      <div class="simple-modal-body">${bodyHtml}</div>
    </div>
  `;
  document.body.appendChild(m);
  const close = () => m.remove();
  m.addEventListener("click", (e) => { if (e.target === m) close(); });
  m.querySelector("#modalCloseBtn").addEventListener("click", close);
}

async function refreshSessionInfo(){
  const box = document.getElementById("sessionBox");
  if (!box) return;

  const id = state.activeAccountId;
  if (!id) { box.textContent = ""; return; }

  try{
    const r = await api(`/api/accounts/${id}/session-info`);
    const s = r.summary || {};

    const rows = [
      ["Container health", (r.health || "unknown")],
      ["Web cookie expires", (s.web_cookie_expires || "-")],
      ["MFA cookie expires", (s.mfa_cookie_expires || "-")],
      ["Days remaining", (typeof s.days_remaining === "number" ? String(s.days_remaining) : "-")],
      ["Next download", (s.next_download_at || "-")],
    ];

    const hasWarnings = !!(r.warnings && r.warnings.length);

    state.lastWarnings = (r.warnings && r.warnings.length) ? r.warnings.slice() : [];

    box.innerHTML = rows.map(([k,v]) =>
      `<div class="session-row"><span class="session-k">${escapeHtml(k)}:</span> <span class="session-v">${escapeHtml(v)}</span></div>`
    ).join("");

    if (hasWarnings){
      box.innerHTML += `<div class="session-sep"></div>`;
      box.innerHTML += r.warnings.map(w =>
        `<div class="session-warn">${escapeHtml(w)}</div>`
      ).join("");
    }

    box.classList.toggle("warn", hasWarnings);

    // Header alert badge (prominent + clickable)
    const badge = document.getElementById("headerAlert");
    const dot = document.getElementById("warnDot");
    const badgeWrap = document.getElementById("warnBadge");

    if (badge){
      if (!badge.dataset.bound){
        badge.dataset.bound = "1";
        badge.addEventListener("click", async () => {
          if (!state.lastWarnings || !state.lastWarnings.length){
            try{ await refreshSessionInfo(); }catch(_){}
          }
          const warnings = state.lastWarnings || [];
          const html = warnings.length
            ? `<ul class="warn-list">${warnings.map(w => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`
            : `<div class="muted">No active warnings.</div>`;
          openSimpleModal("Warnings", html);
        });
      }

      const count = (state.lastWarnings && state.lastWarnings.length) ? state.lastWarnings.length : 0;
      badge.textContent = `Warnings: ${count}`;

      // Visual severity
      badge.classList.remove("warn-ok","warn-bad");
      if (count > 0) badge.classList.add("warn-bad"); else badge.classList.add("warn-ok");

      if (dot){
        dot.classList.remove("warn-bad");
        if (count > 0) dot.classList.add("warn-bad");
      }
      if (badgeWrap){
        // keep spacing consistent
      }
    }

    // Toast only when warning status flips from OK->WARN or changes message from OK->WARN or changes message
    const warnKey = hasWarnings ? (r.warnings.join("|")) : "";
    if (state._lastWarnKey !== warnKey){
      if (hasWarnings){
        toast(r.warnings[0]);
      }
      state._lastWarnKey = warnKey;
    }
  }catch(e){
    box.textContent = "Unable to fetch session details.";
  }
}


async function fixSkipDatesActiveAccount(){
  const id = state.activeAccountId;
  if (!id) return;
  try{
    document.getElementById("termOut").innerHTML = "";
    document.getElementById("modalTitle").textContent = "Fix skip dates";
    document.getElementById("modalSub").textContent = `Account ID ${id}`;
    openModal(true);

    const termIn = document.getElementById("termIn");
    const termSend = document.getElementById("termSend");
    termIn.value = "";
    termIn.disabled = true;
    termSend.disabled = true;

    appendTerm("[running patch inside container...]");
    const r = await api(`/api/accounts/${id}/fix-skip-dates`, { method:"POST" });
    if (r?.output) {
      appendTerm("\n" + r.output);
    } else {
      appendTerm("\n[done]");
    }
  }catch(e){
    console.error(e);
    toast("Fix failed.");
  }
}

let state = { me:null, accounts:[], users:[], activeTab:"dashboard", activeAccountId:null };
let ws = null;

function escapeHtml(s){
  return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
}

function openFormModal({ title, subtitle, bodyHtml, onSave, saveText = "Save" }) {
  const m = document.createElement("div");
  m.className = "simple-modal-backdrop";
  m.innerHTML = `
    <div class="simple-modal" style="max-width: 760px;">
      <div class="simple-modal-head" style="align-items:flex-start; gap:10px">
        <div style="flex:1">
          <div class="simple-modal-title">${escapeHtml(title)}</div>
          ${subtitle ? `<div class="small" style="margin-top:2px">${escapeHtml(subtitle)}</div>` : ""}
        </div>
        <div style="display:flex; gap:8px">
          <button class="btn secondary" id="fmCancel">Cancel</button>
          <button class="btn" id="fmSave">${escapeHtml(saveText)}</button>
        </div>
      </div>
      <div class="simple-modal-body">${bodyHtml}</div>
    </div>
  `;
  document.body.appendChild(m);
  const close = () => m.remove();
  m.addEventListener("click", (e) => { if (e.target === m) close(); });
  m.querySelector("#fmCancel").addEventListener("click", close);
  m.querySelector("#fmSave").addEventListener("click", async () => {
    try {
      const btn = m.querySelector("#fmSave");
      btn.disabled = true;
      await onSave({ close, root: m });
    } catch (e) {
      toast(String(e.message || e));
    } finally {
      const btn = m.querySelector("#fmSave");
      if (btn) btn.disabled = false;
    }
  });
  return { close, root: m };
}

function setActiveTab(tab){
  state.activeTab = tab;
  qsa(".nav button").forEach(b => b.classList.toggle("active", b.dataset.tab===tab));
  render();
}

async function requireAuth(){
  try{
    state.me = await api("/api/me", { method:"GET" });
    document.getElementById("userBadge").textContent = `${state.me.username} (${state.me.role})`;

    // Hide Users tab for non-admins
    const usersTab = document.getElementById("usersTabBtn");
    if (usersTab) {
      const isAdmin = state.me.role === "admin";
      usersTab.style.display = isAdmin ? "" : "none";
      if (!isAdmin && state.activeTab === "users") state.activeTab = "dashboard";
    }
  }catch(e){
    window.location.href = "/login.html";
    return false;
  }
  return true;
}

async function loadData(){
  state.accounts = await api("/api/accounts", { method:"GET" });
  if (state.me?.role === "admin") {
    state.users = await api("/api/users", { method:"GET" });
  } else {
    state.users = [];
  }
  if (!state.activeAccountId && state.accounts.length) state.activeAccountId = state.accounts[0].id;
}

function renderDashboard(){
  const active = state.accounts.find(a=>a.id===state.activeAccountId);
  return `
    <h2>Dashboard</h2>
    <p>Manage multiple iCloud accounts. Each account runs its own <span class="mono">icloudpd_${'${id}'}</span> container.</p>
    <label>Active account</label>
    <select class="input" id="activeAccount">
      ${state.accounts.map(a=>`<option value="${a.id}" ${a.id===state.activeAccountId?"selected":""}>${escapeHtml(a.label)} (${escapeHtml(a.apple_id)})</option>`).join("")}
    </select>

    <div class="actions">
      <button class="btn" id="ensureBtn">Ensure container</button>
      <button class="btn secondary" id="fixSkipBtn">Fix skip dates</button>
      <button class="btn secondary" id="restartBtn">Restart</button>
      <button class="btn secondary" id="mountedBtn">Create .mounted</button>
      <button class="btn" id="initBtn">Initialise (2FA)</button>
      <button class="btn secondary" id="termBtn">Open terminal</button>
      <button class="btn secondary" id="logBtn">View log</button>
    </div>

    <div class="grid3" style="margin-top:12px">
  <div class="card">
    <h2>Status</h2>
    <div class="mono" id="statusBox">Click "Ensure container" to create/start.</div>
  </div>
  <div class="card">
    <h2>Notes</h2>
    <p class="small">MFA requires an interactive session. "Initialise (2FA)" opens a terminal and runs <span class="mono">sync-icloud.sh --Initialise</span>.</p>
    <p class="small">The image requires <span class="mono">/home/&lt;user&gt;/iCloud/.mounted</span> to exist. The UI can create it.</p>
  </div>
  <div class="card">
    <h2>Session &amp; Auth</h2>
    <div class="mono" id="sessionBox">Loading…</div>
  </div>
</div>
  `;
}

function renderAccounts(){
  return `
    <h2>Accounts</h2>
    <p>Create and manage multiple iCloud accounts. Each account is isolated in its own container.</p>

    <div class="row">
      <div class="card" style="flex:1; min-width:300px">
        <h2>Create account</h2>
        <label>Label</label><input class="input" id="a_label" placeholder="e.g. Personal"/>
        <label>Apple ID (email)</label><input class="input" id="a_apple" placeholder="name@icloud.com"/>
        <label>Apple ID password</label><input class="input" id="a_pass" type="password" placeholder="Stored encrypted in DB"/>
        <label>Authentication</label>
        <select class="input" id="a_auth">
          <option value="2FA">2FA</option>
          <option value="Web">Web</option>
        </select>
        <label>Container user (inside icloudpd)</label><input class="input" id="a_user" value="user"/>
        <div class="row">
          <div style="flex:1; min-width:120px">
            <label>UID</label><input class="input" id="a_uid" value="1000"/>
          </div>
          <div style="flex:1; min-width:120px">
            <label>GID</label><input class="input" id="a_gid" value="1000"/>
          </div>
        </div>
        <label>Host download path</label><input class="input" id="a_dl" placeholder="/mnt/pool/icloudpd/account1"/>
        <label>Synchronisation interval (seconds)</label><input class="input" id="a_sync" value="86400"/>
        <label>Download only from date</label><input class="input" id="a_skip_before" type="date"/>
        <label>Download only until date</label><input class="input" id="a_skip_after" type="date"/>
        <div class="actions">
          <button class="btn" id="createAccountBtn">Create</button>
        </div>
      </div>

      <div class="card" style="flex:2; min-width:360px">
        <h2>Existing accounts</h2>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>ID</th><th>Label</th><th>Apple ID</th><th>Auth</th><th>Download path</th><th>Filter</th><th></th></tr></thead>
          <tbody>
            ${state.accounts.map(a=>`
              <tr>
                <td class="mono">${a.id}</td>
                <td>${escapeHtml(a.label)}</td>
                <td>${escapeHtml(a.apple_id)}</td>
                <td>${escapeHtml(a.authentication_type)}</td>
                <td class="mono">${escapeHtml(a.download_path || "")}</td>
                <td class="mono">${escapeHtml((a.skip_created_before||'') + (a.skip_created_before||a.skip_created_after ? ' ' : '') + (a.skip_created_after||''))}</td>
                <td>
                  <button class="btn secondary" data-act="select" data-id="${a.id}">Select</button>
                  <button class="btn secondary" data-act="edit" data-id="${a.id}">Edit</button>
                  <button class="btn danger" data-act="delete" data-id="${a.id}">Delete</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table></div>
      </div>
    </div>
  `;
}

function renderUsers(){
  return `
    <h2>Users</h2>
    <p>Manage Web UI users (not iCloud accounts). Only admins can create users.</p>

    <div class="card" style="margin-bottom:12px">
      <h2>iCloudPD worker image</h2>
      <div class="small">Configured image: <span class="mono" id="icloudpdImgName">(loading)</span></div>
      <div class="small">Current digest: <span class="mono" id="icloudpdImgDigest">(loading)</span></div>
      <div class="small">Last pulled: <span class="mono" id="icloudpdImgPulledAt">(loading)</span></div>
      <div class="actions" style="gap:8px; flex-wrap:wrap">
        <button class="btn secondary" id="refreshIcloudpdImgBtn">Refresh</button>
        <button class="btn secondary" id="pullIcloudpdImgBtn">Pull only (don't rebuild)</button>
        <button class="btn" id="updateSelectedIcloudpdBtn" ${state.accounts && state.accounts.length ? "" : "disabled"}>Update only selected account</button>
        <button class="btn" id="rebuildAllIcloudpdBtn">Pull and rebuild all icloudpd containers</button>
      </div>
      <div class="small" style="margin-top:8px; opacity:.9">
        This uses the configured developer image (default <span class="mono">boredazfcuk/icloudpd:latest</span>). "Update selected" is blocked only when that selected account is downloading. "Rebuild all" is blocked while any downloads are running.
      </div>
    </div>
    <div class="row">
      <div class="card" style="flex:1; min-width:300px">
        <h2>Create user</h2>
        <label>Username</label><input class="input" id="u_name" />
        <label>Password</label><input class="input" id="u_pass" type="password" />
        <label>Role</label>
        <select class="input" id="u_role">
          <option value="admin">admin</option>
          <option value="user">user</option>
        </select>
        <div class="actions"><button class="btn" id="createUserBtn">Create</button></div>
      </div>
      <div class="card" style="flex:2; min-width:360px">
        <h2>Existing users</h2>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>ID</th><th>Username</th><th>Role</th><th></th></tr></thead>
            <tbody>
              ${state.users.map(u=>`
                <tr>
                  <td class="mono">${u.id}</td>
                  <td>${escapeHtml(u.username)}</td>
                  <td>${escapeHtml(u.role)}</td>
                  <td>
                    <button class="btn secondary" data-uact="edit" data-id="${u.id}">Edit</button>
                    <button class="btn danger" data-uact="delete" data-id="${u.id}">Delete</button>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderHelp(){
  return `
    <h2>Help</h2>
    <p class="small">This UI controls Docker containers via <span class="mono">/var/run/docker.sock</span>. Keep it private.</p>
    <p class="small">Manual MFA: <span class="mono">docker exec -it icloudpd_&lt;id&gt; sync-icloud.sh --Initialise</span></p>
    <p class="small">Failsafe marker: <span class="mono">/home/&lt;user&gt;/iCloud/.mounted</span></p>
  `;
}


function render(){
  const view = document.getElementById("view");
  if (state.activeTab==="dashboard") view.innerHTML = renderDashboard();
  if (state.activeTab==="accounts") view.innerHTML = renderAccounts();
  if (state.activeTab==="users") view.innerHTML = renderUsers();
  if (state.activeTab==="help") view.innerHTML = renderHelp();

  applyResponsiveTables(view);

  // attach handlers per tab
  if (state.activeTab==="dashboard"){
    const sel = document.getElementById("activeAccount");
    sel.addEventListener("change", () => { state.activeAccountId = parseInt(sel.value,10); refreshSessionInfo(); });

    document.getElementById("ensureBtn").addEventListener("click", async ()=>{
      try{
        const r = await api(`/api/accounts/${state.activeAccountId}/ensure`, { method:"POST" });
        document.getElementById("statusBox").textContent = JSON.stringify(r, null, 2);
        refreshSessionInfo();
        toast("Container ensured.");
      }catch(e){ toast(String(e.message||e)); }
    });

    

document.getElementById("fixSkipBtn").addEventListener("click", async ()=>{
  try{
    const r = await api(`/api/accounts/${state.activeAccountId}/fix-skip-dates`, { method:"POST" });
    // show output in modal (read-only) for visibility
    document.getElementById("modalTitle").textContent = "Fix skip dates";
    document.getElementById("modalSub").textContent = `Account ID ${state.activeAccountId}`;
    openModal(true);
    const termIn = document.getElementById("termIn");
    const termSend = document.getElementById("termSend");
    termIn.value = "";
    termIn.disabled = true;
    termSend.disabled = true;
    document.getElementById("termOut").innerHTML = "";
    appendTerm(r?.output ? r.output : "[done]");
    toast("Patch executed.");
  }catch(e){ toast(String(e.message||e)); }
});

document.getElementById("restartBtn").addEventListener("click", async ()=>{
      try{
        const r = await api(`/api/accounts/${state.activeAccountId}/restart`, { method:"POST" });
        document.getElementById("statusBox").textContent = JSON.stringify(r, null, 2);
        refreshSessionInfo();
        toast("Restart requested.");
      }catch(e){ toast(String(e.message||e)); }
    });

    document.getElementById("mountedBtn").addEventListener("click", async ()=>{
      try{
        const r = await api(`/api/accounts/${state.activeAccountId}/mounted`, { method:"POST" });
        document.getElementById("statusBox").textContent = JSON.stringify(r, null, 2);
        refreshSessionInfo();
        toast(".mounted created.");
      }catch(e){ toast(String(e.message||e)); }
    });

    document.getElementById("termBtn").addEventListener("click", ()=>openTerminal(state.activeAccountId, false));
    document.getElementById("logBtn").addEventListener("click", ()=>openLogs(state.activeAccountId));
    document.getElementById("initBtn").addEventListener("click", ()=>openTerminal(state.activeAccountId, true));
    // initial load for the selected account
    refreshSessionInfo();
  }

  if (state.activeTab==="accounts"){
    document.getElementById("createAccountBtn").addEventListener("click", async ()=>{
      try{
        const body = {
          label: qs("#a_label").value.trim(),
          apple_id: qs("#a_apple").value.trim(),
          apple_password: qs("#a_pass").value,
          authentication_type: qs("#a_auth").value,
          container_user: qs("#a_user").value.trim() || "user",
          user_id: parseInt(qs("#a_uid").value,10)||1000,
          group_id: parseInt(qs("#a_gid").value,10)||1000,
          download_path: qs("#a_dl").value.trim(),
          synchronisation_interval: parseInt(qs("#a_sync").value,10)||86400,
          skip_created_before: (qs("#a_skip_before").value || "").trim() || null,
          skip_created_after: (qs("#a_skip_after").value || "").trim() || null
        };
        await api("/api/accounts", { method:"POST", body: JSON.stringify(body) });
        await loadData();
        toast("Account created.");
        render();
      }catch(e){ toast(String(e.message||e)); }
    });

    qsa("button[data-act]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = parseInt(btn.dataset.id,10);
        const act = btn.dataset.act;
        try{
          if (act==="select"){ state.activeAccountId = id; setActiveTab("dashboard"); return; }
          if (act==="edit"){
            const acc = await api(`/api/accounts/${id}`, { method:"GET" });
            const bodyHtml = `
              <div class="row" style="gap:12px; align-items:flex-start">
                <div style="flex:1; min-width:260px">
                  <label>Label</label>
                  <input class="input" id="e_label" value="${escapeHtml(acc.label || "")}" />
                  <label>Apple ID</label>
                  <input class="input" id="e_apple" value="${escapeHtml(acc.apple_id || "")}" />
                  <label>Apple ID password</label>
                  <input class="input" id="e_pass" type="password" placeholder="Leave blank to keep existing" />
                  <div class="small" style="margin-top:6px; opacity:.85">Current password is ${acc.has_password ? "set" : "not set"}. For security it is never displayed.</div>
                  <label style="margin-top:12px">Host download path</label>
                  <input class="input" id="e_dl" value="${escapeHtml(acc.download_path || "")}" />
                  <label>Synchronisation interval (seconds)</label>
                  <input class="input" id="e_sync" value="${escapeHtml(acc.synchronisation_interval ?? "")}" />
                  <label>Download only from date</label>
                  <input class="input" id="e_skip_before" type="date" value="${escapeHtml(acc.skip_created_before || "")}" />
                  <label>Download only until date</label>
                  <input class="input" id="e_skip_after" type="date" value="${escapeHtml(acc.skip_created_after || "")}" />
                </div>

                <div style="flex:1; min-width:260px">
                  <label>Authentication</label>
                  <select class="input" id="e_auth">
                    <option value="2FA" ${String(acc.authentication_type).toUpperCase()==="2FA" ? "selected" : ""}>2FA</option>
                    <option value="Web" ${String(acc.authentication_type).toUpperCase()==="WEB" ? "selected" : ""}>Web</option>
                  </select>
                  <label>Container user</label>
                  <input class="input" id="e_user" value="${escapeHtml(acc.container_user || "user")}" />
                  <div class="row" style="gap:12px">
                    <div style="flex:1; min-width:120px">
                      <label>UID</label>
                      <input class="input" id="e_uid" value="${escapeHtml(acc.user_id ?? "")}" />
                    </div>
                    <div style="flex:1; min-width:120px">
                      <label>GID</label>
                      <input class="input" id="e_gid" value="${escapeHtml(acc.group_id ?? "")}" />
                    </div>
                  </div>

                  <details style="margin-top:10px">
                    <summary class="small" style="cursor:pointer">Advanced options</summary>
                    <div style="margin-top:10px">
                      <label>Folder structure</label>
                      <input class="input" id="e_folder_structure" value="${escapeHtml(acc.folder_structure || "")}" />
                      <label>Directory permissions</label>
                      <input class="input" id="e_dir_perm" value="${escapeHtml(acc.directory_permissions || "")}" />
                      <label>File permissions</label>
                      <input class="input" id="e_file_perm" value="${escapeHtml(acc.file_permissions || "")}" />
                      <label>Convert HEIC to JPEG</label>
                      <input class="input" id="e_heic" value="${escapeHtml(acc.convert_heic_to_jpeg || "")}" />
                      <label>Delete HEIC JPEGs</label>
                      <input class="input" id="e_del_heic" value="${escapeHtml(acc.delete_heic_jpegs || "")}" />
                      <label>Command line options</label>
                      <input class="input" id="e_cli" value="${escapeHtml(acc.command_line_options || "")}" />
                      <label>Notification days</label>
                      <input class="input" id="e_notif_days" value="${escapeHtml(acc.notification_days ?? "")}" />
                      <label>Notification type</label>
                      <input class="input" id="e_notif_type" value="${escapeHtml(acc.notification_type || "")}" />
                      <label>Prowl API key</label>
                      <input class="input" id="e_prowl" value="${escapeHtml(acc.prowl_api_key || "")}" />
                      <label>Pushbullet API key</label>
                      <input class="input" id="e_push" value="${escapeHtml(acc.pushbullet_api_key || "")}" />
                      <label>Telegram token</label>
                      <input class="input" id="e_tg_token" value="${escapeHtml(acc.telegram_token || "")}" />
                      <label>Telegram chat ID</label>
                      <input class="input" id="e_tg_chat" value="${escapeHtml(acc.telegram_chat_id || "")}" />
                    </div>
                  </details>
                </div>
              </div>
            `;

            openFormModal({
              title: "Edit iCloud account",
              subtitle: `Account ID ${id}`,
              bodyHtml,
              saveText: "Save changes",
              onSave: async ({ close, root }) => {
                const get = (sel) => root.querySelector(sel);
                const payload = {
                  label: get("#e_label").value.trim(),
                  apple_id: get("#e_apple").value.trim(),
                  authentication_type: get("#e_auth").value,
                  container_user: get("#e_user").value.trim(),
                  user_id: parseInt(get("#e_uid").value, 10) || 1000,
                  group_id: parseInt(get("#e_gid").value, 10) || 1000,
                  download_path: get("#e_dl").value.trim(),
                  synchronisation_interval: parseInt(get("#e_sync").value, 10) || 86400,
                  skip_created_before: (get("#e_skip_before").value || "").trim() || null,
                  skip_created_after: (get("#e_skip_after").value || "").trim() || null,
                  folder_structure: get("#e_folder_structure")?.value?.trim() || null,
                  directory_permissions: get("#e_dir_perm")?.value?.trim() || null,
                  file_permissions: get("#e_file_perm")?.value?.trim() || null,
                  convert_heic_to_jpeg: get("#e_heic")?.value?.trim() || null,
                  delete_heic_jpegs: get("#e_del_heic")?.value?.trim() || null,
                  command_line_options: get("#e_cli")?.value?.trim() || null,
                  notification_days: get("#e_notif_days")?.value?.trim() || null,
                  notification_type: get("#e_notif_type")?.value?.trim() || null,
                  prowl_api_key: get("#e_prowl")?.value?.trim() || null,
                  pushbullet_api_key: get("#e_push")?.value?.trim() || null,
                  telegram_token: get("#e_tg_token")?.value?.trim() || null,
                  telegram_chat_id: get("#e_tg_chat")?.value?.trim() || null,
                };
                const pass = get("#e_pass").value;
                if (pass && pass.length) payload.apple_password = pass;
                await api(`/api/accounts/${id}`, { method:"PUT", body: JSON.stringify(payload) });
                await loadData();
                toast("Account updated.");
                close();
                render();
              }
            });
            return;
          }
          if (act==="delete"){
            // Optimistic UI: remove immediately, then perform delete in background
            const rowBtn = btn;
            rowBtn.disabled = true;
            rowBtn.textContent = "Deleting...";
            state.accounts = state.accounts.filter(a => a.id !== id);
            if (state.activeAccountId === id) state.activeAccountId = (state.accounts[0]?.id || null);
            render();
            api(`/api/accounts/${id}`, { method:"DELETE" })
              .then(async ()=>{ await loadData(); toast("Account deleted."); render(); })
              .catch(async (err)=>{ console.error(err); await loadData(); toast("Delete failed."); render(); });
          }
        }catch(e){ toast(String(e.message||e)); }
      });
    });
  }

  if (state.activeTab==="users"){

    const refreshIcloudpdImg = async ()=>{
      try{
        const info = await api("/api/admin/icloudpd/image", { method: "GET" });
        qs("#icloudpdImgName").textContent = info.image || "(unknown)";
        qs("#icloudpdImgDigest").textContent = info.digest || "(none)";
        qs("#icloudpdImgPulledAt").textContent = info.last_pulled_at || "(unknown)";
      }catch(e){
        qs("#icloudpdImgName").textContent = "(error)";
        qs("#icloudpdImgDigest").textContent = String(e.message||e);
        qs("#icloudpdImgPulledAt").textContent = "";
      }
    };
    // Wire iCloudPD update controls
    const openIcloudpdModal = (title, subtitle) => {
      document.getElementById("modalTitle").textContent = title;
      document.getElementById("modalSub").textContent = subtitle;
      openModal(true);

      const termIn = document.getElementById("termIn");
      const termSend = document.getElementById("termSend");
      termIn.value = "";
      termIn.disabled = true;
      termSend.disabled = true;
      document.getElementById("termOut").innerHTML = "";
      appendTerm("[starting]");
    };

    const renderDownloadLock = (details) => {
      const active = (details && details.active) ? details.active : [];
      appendTerm("[blocked] Downloads are currently running. Try again when downloads finish.");
      if (active.length){
        appendTerm("Active containers:");
        for (const a of active){
          const id = (a.id != null) ? a.id : "?";
          const name = a.name || a.container || "(unknown)";
          appendTerm(`- Account ${id} (${name})`);
          if (a.lastLine) appendTerm(`    ${a.lastLine}`);
          if (a.nextDownloadAt) appendTerm(`    Next download: ${a.nextDownloadAt}`);
        }
      }
    };

    qs("#refreshIcloudpdImgBtn").addEventListener("click", refreshIcloudpdImg);

    qs("#pullIcloudpdImgBtn").addEventListener("click", async ()=>{
      openIcloudpdModal("Pull iCloudPD image", "Pull developer image only (no rebuild)");
      try{
        const r = await api("/api/admin/icloudpd/pull-image", { method: "POST" });
        if (r?.pulled?.digest) appendTerm(`Pulled digest: ${r.pulled.digest}`);
        if (r?.pulled?.image) appendTerm(`Image: ${r.pulled.image}`);
        appendTerm("[done]");
        await refreshIcloudpdImg();
        toast("Image pulled.");
      }catch(e){
        appendTerm(`[error] ${String(e.message||e)}`);
        toast(String(e.message||e));
      }
    });

    const rebuildAll = async ()=>{
      openIcloudpdModal("Update iCloudPD workers", "Pull image and rebuild all icloudpd containers");
      try{
        const r = await api("/api/admin/icloudpd/rebuild-all", { method: "POST" });
        if (r?.pulled?.digest) appendTerm(`Pulled digest: ${r.pulled.digest}`);
        if (r?.pulled?.image) appendTerm(`Image: ${r.pulled.image}`);
        if (Array.isArray(r?.accounts)){
          appendTerm(`Recreated accounts: ${r.accounts.length}`);
          for (const a of r.accounts){
            appendTerm(`Account ${a.id}: ${a.ok ? "OK" : "FAILED"}${a.message ? " - " + a.message : ""}`);
          }
        }
        appendTerm("[done]");
        await loadData();
        await refreshIcloudpdImg();
        toast("Rebuild complete.");
      }catch(e){
        if (e.message === "downloads_running"){
          renderDownloadLock(e.details);
          toast("Updates blocked: downloads running.");
          return;
        }
        appendTerm(`[error] ${String(e.message||e)}`);
        toast(String(e.message||e));
      }
    };

    const rebuildSelected = async ()=>{
      if (!state.accounts || !state.accounts.length){
        toast("No iCloud accounts available.");
        return;
      }

      const defaultId = state.activeAccountId || state.accounts[0].id;

      const options = state.accounts.map(a => {
        const label = a.label ? `${a.label} - ` : "";
        const txt = `${label}${a.apple_id} (ID ${a.id})`;
        return `<option value="${a.id}" ${a.id === defaultId ? "selected" : ""}>${escapeHtml(txt)}</option>`;
      }).join("");

      openFormModal({
        title: "Update iCloudPD container",
        subtitle: "Select which iCloud account container to rebuild",
        bodyHtml: `
          <label>Account</label>
          <select class="input" id="upd_acc">${options}</select>
          <div class="small" style="margin-top:8px; opacity:.9">
            This action will pull the configured developer image and rebuild only the selected account container.
            It is blocked only if that selected account is currently downloading.
          </div>
        `,
        saveText: "Update",
        onSave: async ({ close, root }) => {
          const id = parseInt(root.querySelector("#upd_acc").value, 10);
          close();
          openIcloudpdModal("Update selected worker", `Pull image and rebuild account ID ${id}`);
          try{
            const r = await api(`/api/admin/icloudpd/rebuild-account/${id}`, { method: "POST" });
            if (r?.pulled?.digest) appendTerm(`Pulled digest: ${r.pulled.digest}`);
            if (r?.pulled?.image) appendTerm(`Image: ${r.pulled.image}`);
            appendTerm(`Account ${id}: OK`);
            appendTerm("[done]");
            await loadData();
            await refreshIcloudpdImg();
            toast("Selected account updated.");
          }catch(e){
            if (e.message === "downloads_running"){
              renderDownloadLock(e.details);
              toast("Updates blocked: downloads running.");
              return;
            }
            appendTerm(`[error] ${String(e.message||e)}`);
            toast(String(e.message||e));
          }
        }
      });
    };

    qs("#rebuildAllIcloudpdBtn").addEventListener("click", rebuildAll);
    qs("#updateSelectedIcloudpdBtn").addEventListener("click", rebuildSelected);

    // Initial info load
    refreshIcloudpdImg();

    document.getElementById("createUserBtn").addEventListener("click", async ()=>{
      try{
        const body = {
          username: qs("#u_name").value.trim(),
          password: qs("#u_pass").value,
          role: qs("#u_role").value
        };
        await api("/api/users", { method:"POST", body: JSON.stringify(body) });
        await loadData();
        toast("User created.");
        render();
      }catch(e){ toast(String(e.message||e)); }
    });

    qsa("button[data-uact='edit']").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = parseInt(btn.dataset.id,10);
        const u = state.users.find(x => x.id === id);
        if (!u) return;
        const bodyHtml = `
          <label>Username</label>
          <input class="input" value="${escapeHtml(u.username)}" disabled />
          <label>Role</label>
          <select class="input" id="ue_role">
            <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
            <option value="user" ${u.role === "user" ? "selected" : ""}>user</option>
          </select>
          <label>New password</label>
          <input class="input" id="ue_pass" type="password" placeholder="Leave blank to keep existing" />
          <div class="small" style="margin-top:6px; opacity:.85">For safety, the UI prevents deleting or demoting the last admin.</div>
        `;
        openFormModal({
          title: "Edit user",
          subtitle: `User ID ${id}`,
          bodyHtml,
          saveText: "Save",
          onSave: async ({ close, root }) => {
            const role = root.querySelector("#ue_role").value;
            const password = root.querySelector("#ue_pass").value;
            const payload = { role };
            if (password && password.length) payload.password = password;
            await api(`/api/users/${id}`, { method:"PUT", body: JSON.stringify(payload) });
            await loadData();
            toast("User updated.");
            close();
            render();
          }
        });
      });
    });

    qsa("button[data-uact='delete']").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = parseInt(btn.dataset.id,10);
        try{
          await api(`/api/users/${id}`, { method:"DELETE" });
          await loadData();
          toast("User deleted.");
          render();
        }catch(e){ toast(String(e.message||e)); }
      });
    });
  }
}

function openModal(show){
  const m = document.getElementById("modal");
  m.classList.toggle("show", !!show);
}

function appendTerm(line){
  const out = document.getElementById("termOut");
  const div = document.createElement("div");
  div.className = "line";
  div.textContent = line;
  out.appendChild(div);
  out.scrollTop = out.scrollHeight;
}


function openLogs(accountId){
  document.getElementById("termOut").innerHTML = "";
  document.getElementById("modalTitle").textContent = "Logs";
  document.getElementById("modalSub").textContent = `Account ID ${accountId}`;
  openModal(true);

  // Disable input for log view
  const termIn = document.getElementById("termIn");
  const termSend = document.getElementById("termSend");
  termIn.value = "";
  termIn.disabled = true;
  termSend.disabled = true;

  if (ws) { try{ ws.close(); }catch(e){} ws=null; }
  const proto = (location.protocol==="https:") ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/terminal?accountId=${accountId}&logs=1`);
  ws.onmessage = (ev)=> appendTerm(ev.data);
  ws.onopen = ()=> appendTerm("[connected]");
  ws.onclose = ()=> appendTerm("[disconnected]");
  ws.onerror = ()=> appendTerm("[error]");
}

function openTerminal(accountId, runInit){
  document.getElementById("termOut").innerHTML = "";
  document.getElementById("modalTitle").textContent = runInit ? "Initialise (2FA)" : "Terminal";
  document.getElementById("modalSub").textContent = `Account ID ${accountId}`;
  openModal(true);

  // Enable input for interactive terminal
  const termIn = document.getElementById("termIn");
  const termSend = document.getElementById("termSend");
  termIn.disabled = false;
  termSend.disabled = false;

  if (ws) { try{ ws.close(); }catch(e){} ws=null; }
  const proto = (location.protocol==="https:") ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/terminal?accountId=${accountId}${runInit ? "&init=1" : ""}`);

  ws.onmessage = (ev)=> appendTerm(ev.data);
  ws.onopen = ()=>{
    appendTerm("[connected]");
    if (runInit) {
      ws.send("sync-icloud.sh --Initialise\n");
    }
  };
  ws.onclose = ()=> appendTerm("[disconnected]");
  ws.onerror = ()=> appendTerm("[error]");
}

(async function(){
  // responsive layout
  state.compact = window.matchMedia("(max-width: 700px)").matches;
  let _rzT = null;
  const _applyCompact = () => {
    const c = window.matchMedia("(max-width: 700px)").matches;
    if (c !== state.compact) { state.compact = c; render(); }
  };
  window.addEventListener("resize", () => { clearTimeout(_rzT); _rzT = setTimeout(_applyCompact, 120); });
  window.addEventListener("orientationchange", _applyCompact);

  // theme switch
  const sw = document.getElementById("themeSwitch");
  sw.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    window.__theme.setTheme(cur === "dark" ? "light" : "dark");
  });

  document.getElementById("logoutBtn").addEventListener("click", async ()=>{
    try{ await api("/api/logout", { method:"POST" }); }catch(e){}
    window.location.href = "/login.html";
  });

  qsa(".nav button").forEach(b => b.addEventListener("click", ()=>setActiveTab(b.dataset.tab)));

  document.getElementById("modalClose").addEventListener("click", ()=>{ openModal(false); if(ws){ws.close();ws=null;} });
  document.getElementById("termSend").addEventListener("click", ()=>{
    const v = document.getElementById("termIn").value;
    document.getElementById("termIn").value = "";
    if (ws && ws.readyState===1) ws.send(v + "\n");
  });
  document.getElementById("termIn").addEventListener("keydown", (e)=>{
    if (e.key==="Enter") document.getElementById("termSend").click();
  });

  if (!(await requireAuth())) return;
  await loadData();
  render();
})();

function applyResponsiveTables(root){
  if (!root) return;
  const compact = window.matchMedia("(max-width: 700px)").matches;
  root.classList.toggle("is-compact", compact);
  const tables = root.querySelectorAll("table.table");
  tables.forEach(tbl => {
    if (!compact) {
      tbl.classList.remove("table-cards");
      return;
    }
    const headers = Array.from(tbl.querySelectorAll("thead th")).map(th => (th.textContent || "").trim());
    const rows = tbl.querySelectorAll("tbody tr");
    rows.forEach(tr => {
      Array.from(tr.children).forEach((td, idx) => {
        td.setAttribute("data-label", headers[idx] || "");
      });
    });
    tbl.classList.add("table-cards");
  });
}
