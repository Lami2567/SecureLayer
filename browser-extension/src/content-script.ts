// Content script operates within an isolated world in Chrome Manifest V3.
// Private keys and cryptographic signing material never enter this context.
void chrome.runtime.sendMessage({
  type: "DETECT_PROTECTED_APPLICATION",
  url: location.href,
});

chrome.runtime.onMessage.addListener((message: { type?: string; decision?: { allowed: boolean; reason: string; url?: string } }) => {
  if (message.type !== "SECURELAYER_DECISION" || !message.decision) {
    return;
  }

  showBanner(message.decision.allowed, message.decision.reason, message.decision.url);
});

function showBanner(allowed: boolean, reason: string, url?: string): void {
  const existing = document.getElementById("securelayer-access-banner");
  existing?.remove();

  const banner = document.createElement("div");
  banner.id = "securelayer-access-banner";

  const statusText = allowed ? "ACCESS ALLOWED" : "ACCESS DENIED";
  const bgColor = allowed ? "#064e3b" : "#7f1d1d";
  const borderColor = allowed ? "#10b981" : "#ef4444";
  const icon = allowed ? "✓" : "⚠";

  banner.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;max-width:1200px;margin:0 auto;gap:12px;">
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;background:rgba(255,255,255,0.2);font-weight:bold;">${icon}</span>
        <div>
          <strong style="letter-spacing:0.5px;">[SECURELAYER] ${statusText}</strong>
          <span style="margin-left:8px;opacity:0.9;">${escapeHtml(reason)}</span>
          <span style="margin-left:8px;font-size:11px;opacity:0.75;font-style:italic;">Application-level access control (Not a VPN)</span>
        </div>
      </div>
      <button id="securelayer-banner-close" style="background:transparent;border:0;color:white;font-size:18px;cursor:pointer;padding:0 6px;line-height:1;">&times;</button>
    </div>
  `;

  banner.style.cssText = [
    "position:fixed",
    "z-index:2147483647",
    "top:0",
    "left:0",
    "right:0",
    "padding:10px 16px",
    "font:13px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
    `background:${bgColor}`,
    "color:#ffffff",
    `border-bottom:2px solid ${borderColor}`,
    "box-shadow:0 4px 12px rgba(0,0,0,0.3)",
    "transition:opacity 0.3s ease",
  ].join(";");

  document.documentElement.appendChild(banner);

  const closeBtn = banner.querySelector("#securelayer-banner-close");
  closeBtn?.addEventListener("click", () => banner.remove());

  window.setTimeout(() => {
    banner.style.opacity = "0";
    window.setTimeout(() => banner.remove(), 400);
  }, 9000);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
