async function api(path, opts={}){
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(opts.headers||{}) },
    ...opts,
  });
  if (res.status === 429) {
    const msg = "Too many requests. Please refresh and try again.";
    throw new Error(msg);
  }
  if (res.status === 401) {
    throw new Error("unauthorized");
  }
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const err = (data && data.error) ? data.error : "request_failed";
    throw new Error(err);
  }
  return data;
}

function toast(msg){
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(()=>t.classList.remove("show"), 3200);
}

function qs(sel){ return document.querySelector(sel); }
function qsa(sel){ return [...document.querySelectorAll(sel)]; }
