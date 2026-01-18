(function(){
  const root = document.documentElement;
  const saved = localStorage.getItem("theme") || "dark";
  root.setAttribute("data-theme", saved);
  function setTheme(t){
    root.setAttribute("data-theme", t);
    localStorage.setItem("theme", t);
  }
  window.__theme = { setTheme };
})();
