// Elevation AI Docs — Shared Navigation & Scroll Spy

(function () {
  // Close sidebar on mobile when link clicked
  document.querySelectorAll('.sidebar a').forEach(function (link) {
    link.addEventListener('click', function () {
      if (window.innerWidth <= 900) {
        document.getElementById('sidebar').classList.remove('open');
      }
    });
  });

  // Active section tracking (scroll spy)
  var sectionLinks = document.querySelectorAll('.sidebar a[data-section]');
  var sections = [];
  sectionLinks.forEach(function (link) {
    var id = link.getAttribute('data-section');
    var el = document.getElementById(id);
    if (el) sections.push({ el: el, link: link });
  });

  function updateActive() {
    var scrollY = window.scrollY + 120;
    var current = sections[0];
    for (var i = 0; i < sections.length; i++) {
      if (sections[i].el.offsetTop <= scrollY) current = sections[i];
    }
    sectionLinks.forEach(function (l) { l.classList.remove('active'); });
    if (current) current.link.classList.add('active');
  }

  if (sections.length > 0) {
    window.addEventListener('scroll', updateActive, { passive: true });
    updateActive();
  }
})();
