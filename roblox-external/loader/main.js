const { app, BrowserWindow, session } = require('electron');
const path = require('path');

const CLIENT_BUILD = '1.0.4';

const isDev = !app.isPackaged;

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
      sandbox: true,
      devTools: isDev,
    },
  });
  win.setTitle('NULLFORGE Loader');
  win.loadFile('nullforge-loader.html');

  // Prevent the renderer from navigating to attacker-controlled URLs.
  win.webContents.on('will-navigate', (event) => {
    if (event.preventDefault) {
      event.preventDefault();
    } else {
      event.returnValue = false;
    }
  });
  // Prevent new-window/navigation attempts (e.g. target="_blank").
  win.webContents.setWindowOpenHandler(() => ({ event: 'deny', createBrowserView: false, outbound: false }));
}

// Block the right-click context menu in production to prevent devtools/inspection.
app.on('web-contents-created', (_event, contents) => {
  contents.on('context-menu', (event) => {
    event.preventDefault();
  });
});

app.whenReady().then(createWindow);
