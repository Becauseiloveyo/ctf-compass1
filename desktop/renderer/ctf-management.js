(function () {
  window.setTimeout(installCtf2SettingsCard, 0);

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
