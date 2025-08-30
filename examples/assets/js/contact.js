// Alpine store + guards for spam reduction (client-side)
document.addEventListener('alpine:init', () => {
  Alpine.store('fg', { status: '' });

  Alpine.data('formGuard', () => ({
      minFillMs: 5000,
      cooldownMs: 60000,
      dupKey: 'contact:lastHash',
      cooldownKey: 'contact:lastTs',
      challenge: randomHex(16),
      start: Date.now(),

      init() {},

      configRequest(e) {
        if (e.target !== this.$el) return;
        e.detail.parameters._js_challenge = this.challenge;
        e.detail.parameters._elapsed_ms   = String(Date.now() - this.start);
      },

      beforeRequest(e) {
        if (e.target !== this.$el) return;
        const fd = new FormData(this.$el);
        const hp = (fd.get('website') || '').trim();
        if (hp) {
          e.preventDefault();
          Alpine.store('fg').status = 'Thanks! Your message has been sent.';
          this.$el.reset(); this.resetGuards(); return;
        }
        if (Date.now() - this.start < this.minFillMs) {
          e.preventDefault(); Alpine.store('fg').status = 'Please take a moment to complete the form.'; return;
        }
        const name = (fd.get('name') || '').trim();
        const email= (fd.get('email')|| '').trim();
        const msg  = (fd.get('message')|| '').trim();
        if (!name || !msg || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          e.preventDefault(); Alpine.store('fg').status = 'Please check the required fields.'; return;
        }
        const lastTs = parseInt(localStorage.getItem(this.cooldownKey) || '0', 10);
        if (lastTs && Date.now() - lastTs < this.cooldownMs) {
          e.preventDefault(); Alpine.store('fg').status = 'Please wait a moment before sending again.'; return;
        }
        const fp = hashStr(`${name}|${email}|${msg}`);
        const lastHash = sessionStorage.getItem(this.dupKey);
        if (lastHash && lastHash === fp) {
          e.preventDefault(); Alpine.store('fg').status = 'Looks like you already sent this.'; return;
        }
        sessionStorage.setItem(this.dupKey, fp);
        Alpine.store('fg').status = 'Sending…';
      },

      afterRequest(e) {
        if (e.target !== this.$el) return;
        if (e.detail.successful) {
          localStorage.setItem(this.cooldownKey, String(Date.now()));
          Alpine.store('fg').status = 'Thanks! Your message has been sent.';
          this.$el.reset(); this.resetGuards();
        } else {
          Alpine.store('fg').status = 'Sending failed. Please try again later.';
        }
      },

      resetGuards() { this.start = Date.now(); this.challenge = randomHex(16); }
  }));
});

function randomHex(len){
  const a = new Uint8Array(len);
  (crypto||window.crypto).getRandomValues(a);
  return Array.from(a, b => b.toString(16).padStart(2,'0')).join('');
}
function hashStr(s){
  let h = 5381;
  for (let i=0; i<s.length; i++) h = ((h<<5)+h) ^ s.charCodeAt(i);
  return (h>>>0).toString(36);
}
