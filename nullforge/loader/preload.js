const { contextBridge, ipcRenderer } = require('electron');
const fs = require('fs');
const path = require('path');

function discover_gateway_port() {
  // Try multiple possible registry paths
  const possible_paths = [
    path.join(__dirname, '..', 'server', 'runtime', 'services.json'),
    path.join(__dirname, '..', '..', 'server', 'runtime', 'services.json'),
  ];
  
  for (const p of possible_paths) {
    try {
      if (fs.existsSync(p)) {
        const data = JSON.parse(fs.readFileSync(p, 'utf8'));
        const gateway = data.gateway;
        if (gateway && gateway.host && gateway.port) {
          return `http://${gateway.host}:${gateway.port}`;
        }
      }
    } catch (err) {
      // Continue to next path
    }
  }
  
  // Fallback to default
  return 'http://localhost:8080';
}

contextBridge.exposeInMainWorld('nullforge', {
  apiBase: discover_gateway_port(),
  getApiBase: () => discover_gateway_port(),
});
