const { app, BrowserWindow, session } = require('electron');
const path = require('path');

const CLIENT_BUILD = '1.0.4';

function createWindow() {
  const win = new BrowserWindow({
    width: 1080,
    height: 720,
    minWidth: 720,
    minHeight: 520,
    frame: true,
    backgroundColor: '#000000',
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true
    }
  });
  win.setTitle('NULLFORGE Loader');
  win.loadFile('nullforge-loader.html');
}

app.whenReady().then(createWindow);
