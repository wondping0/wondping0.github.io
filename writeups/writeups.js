(() => {
  // Copy buttons on code blocks.
  document.querySelectorAll(".code .copy").forEach((button) => {
    button.addEventListener("click", async () => {
      const code = button.closest(".code").querySelector("code").innerText;
      try {
        await navigator.clipboard.writeText(code);
        button.textContent = "copied";
      } catch {
        button.textContent = "failed";
      }
      setTimeout(() => (button.textContent = "copy"), 1600);
    });
  });

  // Highlight the table-of-contents entry for the section in view.
  const links = new Map();
  document.querySelectorAll(".toc a").forEach((a) => links.set(a.getAttribute("href").slice(1), a));
  if (!links.size || !("IntersectionObserver" in window)) return;
  let current;
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        current?.classList.remove("is-active");
        current = links.get(entry.target.id);
        current?.classList.add("is-active");
      });
    },
    { rootMargin: "-90px 0px -70% 0px" },
  );
  links.forEach((_, id) => {
    const heading = document.getElementById(id);
    if (heading) io.observe(heading);
  });
})();
