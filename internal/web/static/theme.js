// Thème choisi dans Réglages (clair ou sombre) ; sans choix, le thème suit le système. Chargé avant la page pour éviter un éclair.
try { var t = localStorage.getItem("gw-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) {}
