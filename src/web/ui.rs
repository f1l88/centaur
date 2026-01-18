use axum::{
    routing::get,
    Router,
    response::Html,
};

pub fn ui_router() -> Router {
    Router::new().route("/", get(index))
}

async fn index() -> Html<&'static str> {
    Html(r#"
<!doctype html>
<html>
<head>
  <title>Centaur WAF Admin</title>
  <style>
    body { font-family: sans-serif; padding: 20px; }
    button { margin: 5px; padding: 10px 15px; }
    select { margin: 5px; padding: 5px; }
    pre { background: #f0f0f0; padding: 10px; white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>Centaur WAF Admin</h1>

  <div>
    <button onclick="postCall('/reload')">Reload Rules</button>
    <button onclick="postCall('/reloadserver')">Reload Servers</button>
    <button onclick="postCall('/upgrade')">Upgrade</button>
    <button onclick="getCall('/health')">Health</button>
    <button onclick="getCall('/stats')">Stats</button>
    <button onclick="getCall('/info')">Info</button>
  </div>

  <h3>Servers</h3>
  <select id="servers" onchange="loadServerInfo()">
    <option value="">-- Select a server --</option>
  </select>
  <button onclick="loadServerInfo()">Show Info</button>

  <pre id="out"></pre>

<script>
async function postCall(path) {
  try {
    const res = await fetch(path, { method: 'POST' });
    const text = await res.text();
    document.getElementById('out').innerText = `[POST ${path}] ${text}`;
    if(path === '/server') loadServers(); // обновим список после reload
  } catch(e) {
    document.getElementById('out').innerText = `Error: ${e}`;
  }
}

async function getCall(path) {
  try {
    const res = await fetch(path);
    const text = await res.text();
    document.getElementById('out').innerText = `[GET ${path}] ${text}`;
  } catch(e) {
    document.getElementById('out').innerText = `Error: ${e}`;
  }
}

async function loadServers() {
  try {
    const res = await fetch('/server');
    const text = await res.text();
    const servers = text.split('\n').filter(s => s);
    const select = document.getElementById('servers');
    select.innerHTML = '<option value="">-- Select a server --</option>';
    servers.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.text = s;
      select.appendChild(opt);
    });
  } catch(e) {
    console.error('Failed to load servers:', e);
  }
}

async function loadServerInfo() {
  const select = document.getElementById('servers');
  const server = select.value;
  if(!server) return;
  try {
    const res = await fetch(`/server/${server}`);
    const text = await res.text();
    document.getElementById('out').innerText = `[GET /server/${server}]\n${text}`;
  } catch(e) {
    document.getElementById('out').innerText = `Error: ${e}`;
  }
}

// Подгружаем список серверов при открытии страницы
window.onload = loadServers;
</script>
</body>
</html>
"#)
}
