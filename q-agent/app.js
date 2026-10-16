"use strict";

const flowImage = document.getElementById("flow-image");
const flowButton = document.getElementById("play-flow");
const flowStatus = document.getElementById("flow-status");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const dashboardImage = document.getElementById("dashboard-image");
const dashboardButton = document.getElementById("play-dashboard");
const dashboardStatus = document.getElementById("dashboard-status");
let dashboardTimer;
let dashboardPlaying = false;

function stopDashboard() {
  window.clearTimeout(dashboardTimer);
  dashboardPlaying = false;
  dashboardImage.src = "assets/dashboard-preview.png";
  dashboardButton.textContent = "Play dashboard study";
  dashboardButton.disabled = reducedMotion.matches;
  dashboardStatus.textContent = reducedMotion.matches
    ? "Static concept · reduced motion enabled"
    : "Concept only · web dashboard is not shipped";
}

dashboardButton.hidden = false;
stopDashboard();
reducedMotion.addEventListener("change", stopDashboard);
dashboardButton.addEventListener("click", () => {
  if (dashboardPlaying || reducedMotion.matches) {
    stopDashboard();
    return;
  }
  dashboardPlaying = true;
  dashboardImage.src = "assets/dashboard-preview.gif?play=" + Date.now();
  dashboardButton.textContent = "Stop animation";
  dashboardStatus.textContent =
    "Playing concept · fictional hosts and telemetry";
  dashboardTimer = window.setTimeout(stopDashboard, 4560);
});
const walkthroughs = {
  architecture: {
    asset: "command-flow",
    label: "command flow",
    alt: "qctl requests a command; qserver signs it; qagent verifies, authorizes, executes, and records the outcome.",
  },
  shell: {
    asset: "shell-preview",
    label: "shell session",
    alt: "Illustrative shell on main after beta.2: qctl verifies an independently obtained host key pin before opening an admin session; echo hello returns hello, then exit closes the session and records an audit event.",
  },
  features: {
    asset: "features-preview",
    label: "feature overview",
    alt: "Implemented capabilities: host telemetry, signed exec with restricted allowlists, encrypted shell, and independent audit verification.",
  },
};
let selectedWalkthrough = "architecture";
let flowTimer;
let flowPlaying = false;

function stopFlow() {
  window.clearTimeout(flowTimer);
  flowPlaying = false;
  const selected = walkthroughs[selectedWalkthrough];
  flowImage.src = "assets/" + selected.asset + ".png";
  flowImage.alt = selected.alt;
  document.getElementById("walkthrough-fullsize").href =
    "assets/" + selected.asset + ".png";
  flowButton.textContent = "Play " + selected.label;
  flowButton.disabled = reducedMotion.matches;
  flowStatus.textContent = reducedMotion.matches
    ? "Static illustration · reduced motion enabled"
    : "Illustration · no live host connection";
}

flowButton.hidden = false;
stopFlow();
reducedMotion.addEventListener("change", stopFlow);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopFlow();
    stopDashboard();
  }
});
flowButton.addEventListener("click", () => {
  if (flowPlaying || reducedMotion.matches) {
    stopFlow();
    return;
  }
  flowPlaying = true;
  // A new URL replays a GIF that has already finished its single iteration.
  const selected = walkthroughs[selectedWalkthrough];
  flowImage.src = "assets/" + selected.asset + ".gif?play=" + Date.now();
  flowButton.textContent = "Stop animation";
  flowStatus.textContent = "Playing illustrative " + selected.label;
  flowTimer = window.setTimeout(stopFlow, 4560);
});

const walkthroughTabs = [...document.querySelectorAll("[data-walkthrough]")];
document.getElementById("walkthrough-tabs").hidden = false;
function selectWalkthrough(tab) {
  selectedWalkthrough = tab.dataset.walkthrough;
  for (const item of walkthroughTabs) {
    item.setAttribute("aria-selected", String(item === tab));
    item.tabIndex = item === tab ? 0 : -1;
  }
  document.getElementById("flow-panel").setAttribute("aria-labelledby", tab.id);
  stopFlow();
}
for (const tab of walkthroughTabs) {
  tab.addEventListener("click", () => selectWalkthrough(tab));
  tab.addEventListener("keydown", (event) => {
    const index = walkthroughTabs.indexOf(tab);
    let next;
    if (event.key === "ArrowRight")
      next = walkthroughTabs[(index + 1) % walkthroughTabs.length];
    if (event.key === "ArrowLeft")
      next =
        walkthroughTabs[
          (index + walkthroughTabs.length - 1) % walkthroughTabs.length
        ];
    if (event.key === "Home") next = walkthroughTabs[0];
    if (event.key === "End") next = walkthroughTabs.at(-1);
    if (!next) return;
    event.preventDefault();
    selectWalkthrough(next);
    next.focus();
  });
}

const examples = {
  exec: {
    comment: "# A command for an operator-ceiling host",
    command: "qctl exec agent-ID --role operator\n  -- /usr/bin/id",
    output: "uid=1000(agent) gid=1000(agent)",
    checks: ["Authority signature", "Local role ceiling", "Durable audit"],
  },
  shell: {
    comment: "# Main after beta.2; $PIN comes from the trusted admin host",
    command: 'qctl shell agent-ID --agent-key-pin "$PIN"',
    output: "$ echo hello\nhello\n$ exit",
    checks: ["Trusted host key pin", "HPKE session keys", "Session-end audit"],
  },
  audit: {
    comment: "# Verify a snapshot against a retained checkpoint",
    command: "qctl audit-verify journal.jsonl\n  --checkpoint checkpoint.json",
    output:
      "verified agent=agent-ID records=5\nhash=<matching checkpoint hash>",
    checks: [
      "Canonical record hashes",
      "Ordered hash chain",
      "Exact checkpoint match",
    ],
  },
};

const tabs = [...document.querySelectorAll("[data-demo]")];
const output = document.getElementById("console-output");

function activateTab(tab) {
  const example = examples[tab.dataset.demo];
  for (const item of tabs) {
    const active = item === tab;
    item.setAttribute("aria-selected", String(active));
    item.tabIndex = active ? 0 : -1;
  }
  output.setAttribute("aria-labelledby", tab.id);
  output.querySelector(".console-comment").textContent = example.comment;
  const command = output.querySelector(".console-command");
  command.replaceChildren();
  const prompt = document.createElement("span");
  prompt.textContent = "$";
  command.append(prompt, document.createTextNode(" " + example.command));
  output.querySelector(".console-result").textContent = example.output;
  output.querySelector(".console-checks").replaceChildren(
    ...example.checks.map((label) => {
      const item = document.createElement("span");
      item.textContent = "✓ " + label;
      return item;
    }),
  );
}

for (const tab of tabs) {
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    let next;
    const index = tabs.indexOf(tab);
    if (event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
    if (event.key === "ArrowLeft")
      next = tabs[(index + tabs.length - 1) % tabs.length];
    if (event.key === "Home") next = tabs[0];
    if (event.key === "End") next = tabs[tabs.length - 1];
    if (!next) return;
    event.preventDefault();
    activateTab(next);
    next.focus();
  });
}

const explanations = {
  observe:
    "Observe hosts send telemetry. Exec and shell requests are rejected locally.",
  restricted:
    "Restricted hosts accept only complete argv entries from the host-owned allowlist. Missing or invalid local policy denies exec. Interactive shell is denied.",
  operator:
    "Operator hosts accept signed exec requests. Admin shell requests are rejected locally.",
  admin:
    "Admin hosts can accept signed exec and shell requests. Signature, target, expiry, and replay checks still apply.",
};

for (const button of document.querySelectorAll("[data-role]")) {
  button.addEventListener("click", () => {
    const role = button.dataset.role;
    for (const item of document.querySelectorAll("[data-role]"))
      item.setAttribute("aria-pressed", String(item === button));
    for (const [id, allowed] of [
      ["exec-decision", role !== "observe"],
      ["shell-decision", role === "admin"],
    ]) {
      const decision = document.getElementById(id);
      decision.textContent =
        id === "exec-decision" && role === "restricted"
          ? "ALLOWLIST ONLY"
          : allowed
            ? "ALLOWED"
            : "DENIED";
      decision.className = "decision " + (allowed ? "allowed" : "denied");
    }
    document.getElementById("role-explanation").textContent =
      explanations[role];
  });
}

document.getElementById("copy-command").addEventListener("click", async () => {
  const command =
    "docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build -d --wait";
  const feedback = document.getElementById("copy-feedback");
  try {
    if (!navigator.clipboard?.writeText)
      throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(command);
    feedback.textContent =
      "Command copied. Configure deploy/.env with the guide before running it.";
  } catch {
    document.getElementById("startup-command").textContent = command;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(document.getElementById("startup-command"));
    selection.removeAllRanges();
    selection.addRange(range);
    feedback.textContent = "Command selected. Press Ctrl+C (or ⌘C) to copy.";
  }
});
