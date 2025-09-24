(function () {
  function ensureToaster() {
    let el = document.getElementById('ap-toaster');
    if (!el) {
      el = document.createElement('div');
      el.id = 'ap-toaster';
      el.setAttribute('aria-live', 'polite');
      el.setAttribute('aria-atomic', 'false');
      document.body.appendChild(el);
    }
    return el;
  }
  function removeToast(node, delay) {
    setTimeout(() => {
      node.classList.remove('ap-shown');
      setTimeout(() => node.remove(), 300);
    }, delay);
  }
  window.toast = function (message, type = 'info', opts = {}) {
    const root = ensureToaster();
    const t = document.createElement('div');
    t.className = `ap-toast ap-toast--${type}`;
    t.role = 'status';
    t.textContent = message || '';
    root.appendChild(t);
    // force reflow then show
    void t.offsetWidth;
    t.classList.add('ap-shown');
    const dur = Math.max(1500, opts.duration || 3500);
    removeToast(t, dur);
  };
})();
