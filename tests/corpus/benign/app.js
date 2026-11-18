document.addEventListener('DOMContentLoaded', function () {
  var items = document.querySelectorAll('nav a');
  items.forEach(function (a) {
    if (a.href === window.location.href) {
      a.classList.add('active');
    }
  });
});
