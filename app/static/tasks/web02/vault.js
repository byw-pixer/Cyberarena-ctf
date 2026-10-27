// Файл сгенерирован tasks/build_tasks.py. Вручную не редактировать.
(function () {
  var parts = ["Q1RGe3ZpZXc=", "X3NvdXJjZV8=", "aXNfbm90X2E=", "X2NyaW1lfQ=="];

  function expected() {
    var s = "";
    for (var i = 0; i < parts.length; i++) { s += atob(parts[i]); }
    return s;
  }

  var form = document.getElementById("vault-form");
  var input = document.getElementById("code");
  var result = document.getElementById("result");

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (input.value.trim() === expected()) {
      result.textContent = "Доступ разрешён. Этот код и есть флаг: сдайте его на платформе.";
    } else {
      result.textContent = "Неверный код доступа.";
    }
  });
})();
