const form = document.querySelector("#auth-form");
const message = document.querySelector("#message");
const account = document.querySelector("#account");
const logout = document.querySelector("#logout");

function showMessage(text, isError = false) {
  message.textContent = text;
  message.className = isError ? "error" : "success";
}

async function request(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { "Content-Type": "application/json", ...options.headers } });
  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(data?.error || "Request failed.");
  return data;
}

async function refresh() {
  try {
    const data = await request("/api/me");
    account.textContent = `Signed in as ${data.user.email}`;
    form.classList.add("hidden");
    logout.classList.remove("hidden");
  } catch {
    account.textContent = "";
    form.classList.remove("hidden");
    logout.classList.add("hidden");
  }
}

form.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await request(`/api/${button.dataset.action}`, { method: "POST", body: JSON.stringify(payload) });
    showMessage(button.dataset.action === "signup" ? "Account created." : "Signed in.");
    account.textContent = `Signed in as ${data.user.email}`;
    form.classList.add("hidden");
    logout.classList.remove("hidden");
  } catch (error) {
    showMessage(error.message, true);
  }
});

logout.addEventListener("click", async () => {
  await request("/api/logout", { method: "POST" });
  showMessage("You have been logged out.");
  await refresh();
});

refresh();
