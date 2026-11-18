// Löschen fragt einmal nach.
document.querySelectorAll("form[data-frage]").forEach((f) =>
  f.addEventListener("submit", (e) => { if (!confirm(f.dataset.frage)) e.preventDefault(); }));
