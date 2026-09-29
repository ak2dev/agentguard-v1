// Progressive enhancement for the rule catalog: filter rows as you type.
// The page is fully usable without JavaScript.
(function () {
  var host = document.getElementById("rule-filter-host");
  var input = document.getElementById("rule-filter");
  if (!host || !input) return;
  host.hidden = false;
  input.addEventListener("input", function () {
    var q = input.value.trim().toLowerCase();
    var rows = document.querySelectorAll("table.rules-table tbody tr");
    for (var i = 0; i < rows.length; i++) {
      var hay = rows[i].getAttribute("data-search") || "";
      rows[i].classList.toggle("hidden", q !== "" && hay.indexOf(q) === -1);
    }
  });
})();
