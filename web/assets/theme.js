// Applies the saved theme before first paint. VOTPORT PROPRIETARY LICENSE.
// Classic script, loaded in <head>: a module would run after the first
// frame and flash the system theme. No choice saved means follow the system.
(function () {
  try {
    const saved = window.localStorage.getItem('votport-theme');
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.dataset.theme = saved;
    }
  } catch (error) {
    // Storage blocked: the system preference applies.
  }
})();
