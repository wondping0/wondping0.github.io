(() => {
  "use strict";

  // This is a narrative preview. It never calls the marketplace or executes a bundle.
  const stages = {
    build: {
      comment: "# Illustrative build, not a live run",
      command: "> build shared-primes / version 01",
      output:
        "[inspect] validate manifest and archive limits\n[mount]   read-only input bundle\n[isolate] no network, bounded CPU and memory\n[run]     generator writes the player handout\n[collect] capture the build artifact",
      result: "Build alone does not unlock publication",
    },
    verify: {
      comment: "# Illustrative verification, not a live run",
      command: "> verify shared-primes / version 01",
      output:
        "[isolate] network disabled · non-root\n[build]   generate with an ephemeral flag\n[solve]   run the author's solver\n[compare] recovered flag matches\n[bind]    receipt → exact version hash",
      result: "PASS in this example · publish gate unlocked",
    },
    deliver: {
      comment: "# Illustrative fulfillment, not a live order",
      command: "> fulfill paid order / generate mode",
      output:
        "[payment] accept a signature-verified webhook\n[derive]  prepare an order-specific flag\n[queue]   rerun generator in the sandbox\n[package] handout, solver, and writeup\n[deliver] issue a signed download",
      result: "The buyer runs the artifact on their own infrastructure",
    },
  };

  const controls = document.querySelector(".demo-controls");
  if (!controls) return;
  const buttons = controls.querySelectorAll("button[data-stage]");
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const stage = stages[button.dataset.stage];
      if (!stage) return;
      buttons.forEach((item) =>
        item.setAttribute("aria-pressed", String(item === button)),
      );
      for (const field of ["comment", "command", "output", "result"]) {
        document.getElementById(`demo-${field}`).textContent = stage[field];
      }
    });
  });
  controls.hidden = false;
})();
