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

// Menus de la barre supérieure : un seul ouvert, fermeture hors menu et avec Échap.
document.addEventListener("toggle", function (e) {
  var menu = e.target;
  if (!menu.matches || !menu.matches(".navdrop") || !menu.open) return;
  document.querySelectorAll(".navdrop[open]").forEach(function (other) {
    if (other !== menu) other.open = false;
  });
}, true);

document.addEventListener("click", function (e) {
  var link = e.target.closest(".navdrop .drop a");
  if (link) {
    link.closest(".navdrop").open = false;
    return;
  }
  if (e.target.closest(".navdrop")) return;
  document.querySelectorAll(".navdrop[open]").forEach(function (menu) {
    menu.open = false;
  });
});

document.addEventListener("keydown", function (e) {
  if (e.key !== "Escape") return;
  document.querySelectorAll(".navdrop[open]").forEach(function (menu) {
    menu.open = false;
  });
});
