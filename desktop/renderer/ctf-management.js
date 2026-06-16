(function () {
  installCompactStylesheet();
  installStableSidebarStyle();
  window.setTimeout(() => {
    installCtf2SettingsCard();
    installCtf2CategoryDropdownSkin();
  }, 0);

  function installCompactStylesheet() {
    if (document.querySelector('link[href="./compact-ui.css"]')) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "./compact-ui.css";
    document.head.append(link);
  }

  function installStableSidebarStyle() {
    if (document.getElementById("stable-sidebar-inline-style")) return;
    const style = document.createElement("style");
    style.id = "stable-sidebar-inline-style";
    style.textContent = `
      .sidebar-state-dot,.nav-count{display:none!important}
      body.sidebar-collapsed.sidebar-hover-expanded{--sidebar-width:88px!important}
      body.sidebar-collapsed.sidebar-hover-expanded .shell{grid-template-columns:88px minmax(0,1fr)!important}
      body.sidebar-collapsed.sidebar-hover-expanded .sidebar{width:88px!important}
      .shell,.sidebar,.sidebar-top,.nav,.nav-group,.nav-item,.nav-icon,.brand,.brand-mark,.brand-copy,.sidebar-toggle,.sidebar-footer,.sidebar-row,.theme-toggle{transition:none!important}
      .sidebar{display:flex!important;flex-direction:column!important;height:100vh!important;padding:16px 14px!important;overflow:hidden!important}
      .sidebar-top,body.sidebar-collapsed .sidebar-top,body.sidebar-collapsed.sidebar-hover-expanded .sidebar-top{height:auto!important;min-height:0!important;display:grid!important;grid-template-rows:auto auto auto!important;align-content:start!important;gap:16px!important}
      .sidebar-toggle,body:not(.sidebar-collapsed) .sidebar-toggle,body.sidebar-collapsed .sidebar-toggle,body.sidebar-collapsed.sidebar-hover-expanded .sidebar-toggle{width:42px!important;height:42px!important;min-width:42px!important;min-height:42px!important;padding:0!important;display:grid!important;place-items:center!important;justify-self:start!important;margin-left:9px!important;box-shadow:none!important}
      .sidebar-toggle svg{width:24px!important;height:24px!important;margin:auto!important;display:block!important}
      .brand,body:not(.sidebar-collapsed) .brand,body.sidebar-collapsed .brand,body.sidebar-collapsed.sidebar-hover-expanded .brand{position:relative!important;min-height:48px!important;display:block!important;padding:0!important;border:0!important;background:transparent!important}
      .brand-mark,body.sidebar-collapsed .brand-mark,body.sidebar-collapsed.sidebar-hover-expanded .brand-mark{position:absolute!important;left:30px!important;top:50%!important;width:48px!important;height:48px!important;margin:0!important;transform:translate(-50%,-50%)!important;display:grid!important;place-items:center!important}
      .brand-copy,body:not(.sidebar-collapsed) .brand-copy,body.sidebar-hover-expanded .brand-copy{display:block!important;margin-left:72px!important;padding-top:2px!important;width:auto!important;opacity:1!important;transform:none!important;pointer-events:auto!important}
      body.sidebar-collapsed .brand-copy,body.sidebar-collapsed.sidebar-hover-expanded .brand-copy{opacity:0!important;pointer-events:none!important;width:auto!important}
      .nav,body.sidebar-collapsed .nav,body.sidebar-collapsed.sidebar-hover-expanded .nav{min-height:0!important;height:auto!important;display:grid!important;gap:6px!important;padding:6px 0 0!important;justify-content:stretch!important}
      .nav-group,body.sidebar-collapsed .nav-group,body.sidebar-collapsed.sidebar-hover-expanded .nav-group{display:grid!important;gap:6px!important}
      .nav-item,body:not(.sidebar-collapsed) .nav-item,body.sidebar-collapsed .nav-item,body.sidebar-collapsed.sidebar-hover-expanded .nav-item{position:relative!important;width:100%!important;min-height:44px!important;height:44px!important;margin:0!important;padding:0!important;display:block!important;border-radius:13px!important;box-shadow:none!important}
      .nav-icon,body.sidebar-collapsed .nav-icon,body.sidebar-collapsed.sidebar-hover-expanded .nav-icon{position:absolute!important;left:30px!important;top:50%!important;width:26px!important;height:26px!important;margin:0!important;display:grid!important;place-items:center!important;transform:translate(-50%,-50%)!important;flex:none!important;align-self:auto!important}
      .nav-icon svg{width:100%!important;height:100%!important;margin:auto!important;display:block!important}
      .nav-item>span:not(.nav-icon):not(.nav-count),body:not(.sidebar-collapsed) .nav-item>span:not(.nav-icon):not(.nav-count),body.sidebar-hover-expanded .nav-item>span:not(.nav-icon):not(.nav-count){display:block!important;margin-left:72px!important;padding-right:12px!important;line-height:44px!important;width:auto!important;opacity:1!important;white-space:nowrap!important;pointer-events:auto!important;transform:none!important}
      body.sidebar-collapsed .nav-item>span:not(.nav-icon):not(.nav-count),body.sidebar-collapsed.sidebar-hover-expanded .nav-item>span:not(.nav-icon):not(.nav-count){opacity:0!important;pointer-events:none!important;width:auto!important}
      body.sidebar-collapsed .nav-item.active,body.sidebar-collapsed.sidebar-hover-expanded .nav-item.active{background:var(--accent-soft)!important;border-color:color-mix(in srgb,var(--accent) 28%,transparent)!important;color:var(--accent)!important;box-shadow:none!important}
      .sidebar-footer,body.sidebar-collapsed .sidebar-footer,body.sidebar-collapsed.sidebar-hover-expanded .sidebar-footer{display:flex!important;flex:0 0 auto!important;margin-top:auto!important;width:auto!important;opacity:1!important;pointer-events:auto!important;transform:none!important;border-top:0!important}
      .sidebar-footer .meta-row,.sidebar-footer .sidebar-row:first-child>div{display:none!important}
      .sidebar-footer .sidebar-row:first-child,body.sidebar-collapsed .sidebar-footer .sidebar-row:first-child,body.sidebar-collapsed.sidebar-hover-expanded .sidebar-footer .sidebar-row:first-child{width:auto!important;min-height:0!important;padding:0!important;border:0!important;background:transparent!important;box-shadow:none!important}
      body:not(.sidebar-collapsed) .sidebar-footer,body.sidebar-collapsed .sidebar-footer,body.sidebar-collapsed.sidebar-hover-expanded .sidebar-footer{justify-content:flex-start!important;padding:12px 0 20px 7px!important}
      .theme-toggle,body.sidebar-collapsed .theme-toggle,body.sidebar-collapsed.sidebar-hover-expanded .theme-toggle{width:46px!important;height:46px!important;min-width:46px!important;min-height:46px!important;display:grid!important;place-items:center!important;padding:0!important;border:1px solid var(--line)!important;border-radius:15px!important;background:var(--surface-subtle)!important;color:var(--accent)!important;opacity:1!important;pointer-events:auto!important;transform:none!important}
      .theme-toggle .theme-track{display:none!important}
      .theme-toggle::before{content:"☾";display:block;font-size:20px;line-height:1;font-weight:800}
      body[data-theme="dark"] .theme-toggle::before{content:"☀"}
    `;
    document.head.append(style);
  }

  function installCtf2CategoryDropdownSkin() {
    const select = document.getElementById("ctf2-category-select");
    if (!select || document.getElementById("ctf2-category-skin")) return;

    const field = select.closest(".field");
    if (field) {
      field.classList.add("ctf2-native-category-field");
    }

    const root = document.createElement("div");
    root.id = "ctf2-category-skin";
    root.className = "ctf2-category-skin";
    root.innerHTML = `
      <button id="ctf2-category-button" class="ctf2-category-button" type="button" aria-expanded="false">
        <span class="ctf2-category-label">题型</span>
        <strong id="ctf2-category-current">全部</strong>
        <span class="ctf2-category-caret">▾</span>
      </button>
      <div id="ctf2-category-menu" class="ctf2-category-menu" hidden></div>
    `;
    (field || select).after(root);

    const button = root.querySelector("#ctf2-category-button");
    const current = root.querySelector("#ctf2-category-current");
    const menu = root.querySelector("#ctf2-category-menu");

    function labelOf(option) {
      return option?.textContent?.trim() || option?.value || "全部";
    }

    function sync() {
      const options = Array.from(select.options || []);
      const active = options.find((option) => option.value === select.value) || options[0];
      current.textContent = labelOf(active);
      menu.innerHTML = "";
      options.forEach((option) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = `ctf2-category-option${option.value === select.value ? " is-active" : ""}`;
        item.textContent = labelOf(option);
        item.addEventListener("click", () => {
          select.value = option.value;
          select.dispatchEvent(new Event("change", { bubbles: true }));
          closeMenu();
          sync();
        });
        menu.append(item);
      });
    }

    function openMenu() {
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
      root.classList.add("is-open");
    }

    function closeMenu() {
      menu.hidden = true;
      button.setAttribute("aria-expanded", "false");
      root.classList.remove("is-open");
    }

    button.addEventListener("click", (event) => {
      event.stopPropagation();
      if (menu.hidden) openMenu();
      else closeMenu();
    });
    document.addEventListener("click", (event) => {
      if (!root.contains(event.target)) closeMenu();
    });
    select.addEventListener("change", sync);
    new MutationObserver(sync).observe(select, { childList: true, subtree: true, attributes: true });
    sync();
  }

  function installCtf2SettingsCard() {
    const list = document.querySelector("#settings-view .settings-list");
    if (!list || document.getElementById("ctf2-settings-row")) return;

    const row = document.createElement("div");
    row.id = "ctf2-settings-row";
    row.className = "settings-row settings-row-stack ctf2-settings-row";
    row.innerHTML = `
      <div class="settings-row-header">
        <div>
          <strong>CTF2 管理</strong>
          <p id="ctf2-settings-status">检查登录状态、导入记录和本地下载缓存。</p>
        </div>
        <div class="settings-actions">
          <button id="ctf2-settings-refresh" class="secondary-button" type="button">刷新</button>
          <button id="ctf2-settings-open" class="secondary-button" type="button">打开下载目录</button>
          <button id="ctf2-settings-clear" class="secondary-button danger-button" type="button">清除 CTF2 数据</button>
        </div>
      </div>
      <div id="ctf2-history-list" class="stack-list compact-stack ctf2-history-list"></div>
    `;
    list.append(row);

    const status = row.querySelector("#ctf2-settings-status");
    const historyList = row.querySelector("#ctf2-history-list");
    const refreshButton = row.querySelector("#ctf2-settings-refresh");
    const openButton = row.querySelector("#ctf2-settings-open");
    const clearButton = row.querySelector("#ctf2-settings-clear");

    async function refresh() {
      refreshButton.disabled = true;
      try {
        const [ctf2Status, history] = await Promise.all([
          window.ctfCompass.getCtf2Status?.(),
          window.ctfCompass.getCtf2History?.(),
        ]);
        status.textContent = ctf2Status?.connected
          ? `已登录${ctf2Status.profile?.username ? `：${ctf2Status.profile.username}` : ""}。导入记录 ${history?.length || 0} 条。`
          : `未登录。导入记录 ${history?.length || 0} 条。`;
        renderHistory(history || []);
      } catch (error) {
        status.textContent = `刷新失败：${error.message}`;
      } finally {
        refreshButton.disabled = false;
      }
    }

    function renderHistory(history) {
      historyList.innerHTML = "";
      if (!history.length) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent = "暂无 CTF2 导入记录。";
        historyList.append(empty);
        return;
      }
      history.slice(0, 5).forEach((item) => {
        const node = document.createElement("div");
        node.className = "stack-item ctf2-history-item";
        const time = item.importedAt ? new Date(item.importedAt).toLocaleString("zh-CN") : "";
        node.innerHTML = `<strong>${escapeHtml(item.name || "Unnamed challenge")}</strong><p>${escapeHtml([item.category, item.groundName, `${item.attachmentCount || 0} 附件`, time].filter(Boolean).join(" · "))}</p>`;
        historyList.append(node);
      });
    }

    refreshButton.addEventListener("click", refresh);
    openButton.addEventListener("click", async () => {
      try {
        await window.ctfCompass.revealCtf2Downloads?.();
      } catch (error) {
        status.textContent = `打开失败：${error.message}`;
      }
    });
    clearButton.addEventListener("click", async () => {
      if (!confirm("清除 CTF2 下载缓存和导入记录？登录 token 会保留。")) return;
      clearButton.disabled = true;
      try {
        await window.ctfCompass.clearCtf2Data?.();
        await refresh();
        status.textContent = "CTF2 下载缓存和导入记录已清除。";
      } catch (error) {
        status.textContent = `清除失败：${error.message}`;
      } finally {
        clearButton.disabled = false;
      }
    });

    refresh().catch(() => {});
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
})();
