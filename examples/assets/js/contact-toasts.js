// assets/js/contact-toasts.js — single source of user-facing messages
(function () {
  if (!window.htmx) return;

  function isContactForm(e) {
    return e && e.target && e.target.matches && e.target.matches('form.email-form');
  }

  // Centralized copy
  var MSG = {
    sending: 'Message is being sent …',
    success: 'Thank you! I will get back to you as soon as possible.',
    network: 'Network error – please try again later.',
    error: 'An error has occurred.',
  };

  function notify(form, type, message, opts) {
    // Toasts (if available)
    if (window.toast) {
      var variant = (type === 'success') ? 'success' : (type === 'error' ? 'error' : 'info');
      window.toast(message, variant, { duration: (opts && opts.duration) || (type === 'error' ? 5000 : 2000) });
    }
    // SR text / inline boxes via custom event (handled by contact.js)
    if (form && form.dispatchEvent) {
      form.dispatchEvent(new CustomEvent('ap:notify', { bubbles: true, detail: { type: type, message: message } }));
    }
  }

  document.addEventListener('htmx:configRequest', function (e) {
    if (!isContactForm(e)) return;
    notify(e.target, 'info', MSG.sending, { duration: 1800 });
  });

  document.addEventListener('htmx:afterRequest', function (e) {
    if (!isContactForm(e)) return;
    var xhr = e.detail && e.detail.xhr;
    var status = (xhr && xhr.status) || 0;
    var data = null;
    try { data = JSON.parse((xhr && xhr.responseText) || ''); } catch (_) { }

    if (status >= 200 && status < 300 && data && data.ok) {
      notify(e.target, 'success', MSG.success);
      return;
    }

    var msg = (data && data.error) ? data.error :
      (status ? ('Error (' + status + ')') : MSG.network);
    notify(e.target, 'error', msg, { duration: 5000 });
  });

  document.addEventListener('htmx:sendError', function (e) {
    if (!isContactForm(e)) return;
    notify(e.target, 'error', MSG.network);
  });
})();
