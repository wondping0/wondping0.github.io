(() => {
  const root = document.documentElement;
  root.classList.add("js");

  // Inline disclosure keeps navigation available on small screens and without JS.
  const menu = document.querySelector(".nav-toggle");
  const nav = document.querySelector("#primary-nav");
  if (menu && nav) {
    const setMenu = (open) => {
      menu.setAttribute("aria-expanded", String(open));
      nav.classList.toggle("is-open", open);
    };
    menu.addEventListener("click", () => setMenu(menu.getAttribute("aria-expanded") !== "true"));
    nav.addEventListener("click", (event) => {
      if (event.target.closest("a")) setMenu(false);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menu.getAttribute("aria-expanded") === "true") {
        setMenu(false);
        menu.focus();
      }
    });
    window.matchMedia("(max-width: 1040px)").addEventListener("change", () => setMenu(false));
  }

  const year = document.getElementById("year");
  if (year) year.textContent = String(new Date().getFullYear());

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Reveal sections as they scroll into view.
  const items = document.querySelectorAll(".reveal");
  if (reduced || !("IntersectionObserver" in window)) {
    items.forEach((el) => el.classList.add("is-visible"));
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px" },
    );
    document.querySelectorAll(".projects, .list, .ctf-grid").forEach((group) => {
      group.querySelectorAll(".reveal").forEach((el, i) => el.style.setProperty("--delay", `${i * 70}ms`));
    });
    items.forEach((el) => io.observe(el));
  }

  // Type through the roles in the hero.
  const typed = document.querySelector(".typed-text");
  if (!typed || reduced) return;
  let roles;
  try {
    roles = JSON.parse(typed.dataset.roles);
  } catch {
    return;
  }
  let role = 0;
  let chars = roles[0].length;
  let deleting = true;
  const tick = () => {
    if (deleting) {
      chars -= 1;
      if (chars <= 0) {
        deleting = false;
        role = (role + 1) % roles.length;
      }
    } else {
      chars += 1;
    }
    typed.textContent = roles[role].slice(0, Math.max(chars, 0));
    let delay = deleting ? 28 : 60;
    if (!deleting && chars >= roles[role].length) {
      deleting = true;
      delay = 2200;
    }
    setTimeout(tick, delay);
  };
  setTimeout(tick, 2400);
})();
