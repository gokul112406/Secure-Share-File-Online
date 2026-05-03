// ============================================================
// public/js/app.js — Shared utilities used across all pages
// ============================================================

// ── Format bytes to human-readable string ──
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + units[i];
}

// ── Copy text content of element to clipboard ──
async function copyKey(elementId, btnId) {
  const text = document.getElementById(elementId)?.textContent?.trim();
  const btn  = document.getElementById(btnId);
  if (!text || !btn) return;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = '✅ Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 2000);
  } catch (_) {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;opacity:0;';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = '✅ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  }
}

// ── Highlight active nav link ──
(function () {
  const path  = window.location.pathname.replace(/\/$/, '') || '/';
  const links = document.querySelectorAll('.nav-links a');
  links.forEach(link => {
    const href = link.getAttribute('href').replace(/\/$/, '') || '/';
    link.classList.toggle('active', href === path);
  });
})();

// ── Animate elements on scroll (Intersection Observer) ──
(function () {
  const observer = new IntersectionObserver(
    entries => entries.forEach(e => {
      if (e.isIntersecting) { e.target.style.opacity = '1'; e.target.style.transform = 'translateY(0)'; }
    }),
    { threshold: 0.1 }
  );
  document.querySelectorAll('.animate-in').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(24px)';
    el.style.transition = 'opacity 0.55s ease, transform 0.55s ease';
    observer.observe(el);
  });
})();
