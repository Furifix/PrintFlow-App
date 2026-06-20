import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Set environment variables for server.js BEFORE importing it
const userDataPath = app.getPath('userData');
process.env.DATA_DIR = path.join(userDataPath, 'data');
process.env.UPLOADS_DIR = path.join(userDataPath, 'uploads', 'backgrounds');
process.env.PORT = '0'; // Let the OS assign a free port

let mainWindow;

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  try {
    const { server } = await import('./server.js');

    // Wait until the server is actually listening
    server.on('listening', () => {
      const port = server.address().port;
      mainWindow.loadURL(`http://127.0.0.1:${port}`);
    });

    // If server is already listening
    if (server.listening) {
      const port = server.address().port;
      mainWindow.loadURL(`http://127.0.0.1:${port}`);
    }

  } catch (err) {
    console.error('Failed to start server:', err);
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
