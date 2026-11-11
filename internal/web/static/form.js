// Boutons « − » du formulaire d'hôte : retire la ligne (nom ou chemin) et relance les vérifications.
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-remove]");
  if (!b) return;
  var form = b.closest("form");
  b.closest(".rep").remove();
  if (form) form.dispatchEvent(new Event("input", { bubbles: true }));
});

// Copie les extraits de configuration sans dépendance ni permission particulière.
document.addEventListener("click", function (e) {
  var button = e.target.closest("[data-copy]");
  if (!button) return;
  var source = document.querySelector(button.getAttribute("data-copy"));
  if (!source || !navigator.clipboard) return;
  navigator.clipboard.writeText(source.textContent.trim()).then(function () {
    var label = button.textContent;
    button.textContent = "Copié";
    window.setTimeout(function () { button.textContent = label; }, 1400);
  });
});

// « À surveiller » : les hôtes dont la vérification a échoué ou dont le certificat pose problème.
(function () {
  var btn = document.getElementById("watch-filter");
  if (!btn) return;
  function rows() { return document.querySelectorAll("#hosts-list a.hrow"); }
  function refresh() {
    var n = 0;
    rows().forEach(function (r) {
      var bad = r.hasAttribute("data-problem") || r.querySelector(".state .dot.err, .state .dot.warn[data-state]");
      r.toggleAttribute("data-watch", !!bad);
      if (bad) n++;
    });
    var count = document.getElementById("watch-count");
    count.textContent = n;
    count.classList.toggle("some", n > 0);
    if (btn.getAttribute("aria-pressed") === "true") rows().forEach(function (r) { r.hidden = !r.hasAttribute("data-watch"); });
  }
  btn.addEventListener("click", function () {
    var on = btn.getAttribute("aria-pressed") !== "true";
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    rows().forEach(function (r) { r.hidden = on && !r.hasAttribute("data-watch"); });
  });
  document.body.addEventListener("htmx:afterSwap", refresh);
  document.body.addEventListener("htmx:oobAfterSwap", refresh);
  refresh();
})();

// Trafic : filtre des dernières requêtes (toutes, ou seulement les erreurs).
document.querySelectorAll("[data-rfilter]").forEach(function (c) {
  c.addEventListener("click", function () {
    document.querySelectorAll("[data-rfilter]").forEach(function (x) { x.classList.toggle("on", x === c); });
    document.querySelectorAll("tr[data-class]").forEach(function (r) {
      r.hidden = c.dataset.rfilter === "err" && r.dataset.class !== "err" && r.dataset.class !== "warn";
    });
  });
});

// Recherche dans une liste déjà affichée (adresses bloquées).
document.querySelectorAll("[data-filter-rows]").forEach(function (input) {
  input.addEventListener("input", function () {
    var q = input.value.toLowerCase().trim();
    document.querySelectorAll(input.dataset.filterRows).forEach(function (r) {
      r.hidden = !r.textContent.toLowerCase().includes(q);
    });
  });
});

// Réglages : le thème est un choix de ce navigateur, enregistré ici seulement.
(function () {
  var select = document.getElementById("theme-select");
  if (!select) return;
  try { select.value = localStorage.getItem("gw-theme") || ""; } catch (e) {}
  select.addEventListener("change", function () {
    try { if (select.value) localStorage.setItem("gw-theme", select.value); else localStorage.removeItem("gw-theme"); } catch (e) {}
    if (select.value) document.documentElement.dataset.theme = select.value; else delete document.documentElement.dataset.theme;
  });
})();

// Un formulaire marqué data-confirm demande confirmation avant d'être envoyé.
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
